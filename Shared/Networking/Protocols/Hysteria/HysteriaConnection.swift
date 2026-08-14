//
//  HysteriaConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaConnection")

actor HysteriaConnection {

    private let session: HysteriaSession
    private let destination: String

    private enum Phase: PhaseTransitionable {
        case idle
        case opening
        case open(sid: Int64, ready: Bool)
        case closed(sid: Int64?)

        var isClosed: Bool {
            if case .closed = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .open),
                 (.open(_, false), .open(_, true)):
                return true
            case (_, .closed):
                return !old.isClosed
            default:
                return false
            }
        }
    }
    private nonisolated let phase = Mutex<Phase>(.idle)

    private let rawInbox = AsyncInbox<Data>()
    private var pendingData = Data()

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
    }

    nonisolated var isConnected: Bool {
        phase.withLock { if case .open(_, true) = $0 { true } else { false } }
    }

    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }

    private nonisolated var currentSID: Int64? {
        phase.withLock { state in
            switch state {
            case .open(let sid, _): sid
            case .closed(let sid): sid
            case .idle, .opening: nil
            }
        }
    }

    private nonisolated func closeLifecycle() -> Int64? {
        phase.withLock { state in
            let sid: Int64?
            switch state {
            case .closed: return nil
            case .open(let s, _): sid = s
            case .idle, .opening: sid = nil
            }
            Phase.transition(&state, to: .closed(sid: sid))
            return sid
        }
    }

    // MARK: - Open

    func open() async throws {
        let begin = phase.withLock { Phase.transition(&$0, to: .opening) }
        guard begin else { throw AnywhereError.proxy(.hysteria, .streamClosed) }

        let sid: Int64
        do {
            sid = try await session.openTCPStream(for: self)
        } catch {
            _ = closeLifecycle()
            throw error
        }
        let adopted = phase.withLock { Phase.transition(&$0, to: .open(sid: sid, ready: false)) }
        guard adopted else {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid)
            throw AnywhereError.proxy(.hysteria, .streamClosed)
        }

        let frame = HysteriaProtocol.encodeTCPRequest(address: destination)
        try await session.writeStream(sid, data: frame)

        var buffer = Data()
        while true {
            guard let chunk = try await nextChunk() else {
                throw AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Stream closed before response"))
            }
            buffer.append(chunk)
            guard let parsed = HysteriaProtocol.parseTCPResponse(from: buffer) else { continue }
            if parsed.consumed > 0 { session.extendStreamOffset(sid, count: parsed.consumed) }
            guard parsed.status == HysteriaProtocol.tcpResponseStatusOK else {
                throw AnywhereError.proxy(.hysteria, .tunnelRejected(detail: parsed.message))
            }
            buffer.removeFirst(parsed.consumed)
            pendingData = buffer
            let becameReady = phase.withLock { state -> Bool in
                guard case .open(let s, false) = state else { return false }
                return Phase.transition(&state, to: .open(sid: s, ready: true))
            }
            guard becameReady else { throw AnywhereError.proxy(.hysteria, .streamClosed) }
            return
        }
    }

    // MARK: - Demux feed

    nonisolated func feedStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty { rawInbox.yield(Data(data)) }
        if fin { rawInbox.finish() }
    }

    nonisolated func handleStreamTermination(error: Error?, cause: QUICConnection.StreamTerminationCause) {
        if let error { rawInbox.finish(throwing: error) } else { rawInbox.finish() }
        guard cause == .closed || error != nil else { return }
        if let sid = closeLifecycle() {
            session.shutdownStream(sid)
        }
    }

    nonisolated func handleSessionError(_ error: Error) {
        if case AnywhereError.quic(.closed(graceful: true)) = error {
            rawInbox.finish()
        } else {
            rawInbox.finish(throwing: error)
        }
        _ = closeLifecycle()
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        let sid: Int64? = phase.withLock { if case .open(let s, true) = $0 { s } else { nil } }
        guard let sid else {
            throw AnywhereError.proxy(.hysteria, .streamClosed)
        }
        try await session.writeStream(sid, data: data)
    }

    func receiveRaw() async throws -> Data? {
        if !pendingData.isEmpty {
            let out = pendingData
            pendingData = Data()
            if let sid = currentSID { session.extendStreamOffset(sid, count: out.count) }
            return out
        }
        guard let chunk = try await nextChunk() else { return nil }
        if !chunk.isEmpty, let sid = currentSID {
            session.extendStreamOffset(sid, count: chunk.count)
        }
        return chunk
    }

    private func nextChunk() async throws -> Data? {
        guard let batch = try await rawInbox.nextBatch() else { return nil }
        guard batch.count > 1 else { return batch.first }
        var merged = batch[0]
        merged.reserveCapacity(batch.reduce(0) { $0 + $1.count })
        for chunk in batch.dropFirst() { merged.append(chunk) }
        return merged
    }

    nonisolated func cancel() {
        rawInbox.finish()
        if let sid = closeLifecycle() {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid)
        }
    }
}

extension HysteriaConnection: ProxyConnection {}
