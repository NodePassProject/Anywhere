//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

actor NowhereConnection {
    private let session: NowhereSession
    private let destination: NowhereProtocol.Target
    private let initialData: Data?

    private enum Phase: PhaseTransitionable {
        case idle
        case opening
        case open(sid: Int64, ready: Bool, credited: Int)
        case closed

        var isClosed: Bool {
            if case .closed = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .open):
                return true
            case (.open(_, let wasReady, _), .open(_, let isReady, _)):
                return isReady || !wasReady
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

    private var uncreditedBytes = 0
    private static let creditFlushThreshold = 256 << 10

    private var backlogChunks: [Data] = []
    private static let maxChunkBytes = 512 << 10
    private static let inboxCompactionDepth = 32

    init(
        session: NowhereSession,
        destination: NowhereProtocol.Target,
        initialData: Data?
    ) {
        self.session = session
        self.destination = destination
        self.initialData = initialData
    }

    nonisolated var isConnected: Bool {
        phase.withLock { if case .open(_, true, _) = $0 { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }

    private nonisolated func closeLifecycle() -> (sid: Int64, credited: Int)? {
        phase.withLock { state in
            let released: (sid: Int64, credited: Int)?
            switch state {
            case .closed: return nil
            case .open(let sid, _, let credited): released = (sid, credited)
            case .idle, .opening: released = nil
            }
            Phase.transition(&state, to: .closed)
            return released
        }
    }

    private nonisolated func becomeReady() -> Bool {
        phase.withLock { state -> Bool in
            guard case .open(let sid, false, let credited) = state else { return false }
            return Phase.transition(&state, to: .open(sid: sid, ready: true, credited: credited))
        }
    }

    // MARK: - Open

    func open() async throws {
        let begin = phase.withLock { Phase.transition(&$0, to: .opening) }
        guard begin else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        do {
            try await performOpen()
        } catch {
            if let released = closeLifecycle() {
                session.shutdownStream(released.sid)
                session.releaseTCPStream(released.sid, credited: released.credited)
            }
            throw error
        }
    }

    private func performOpen() async throws {
        let frame = NowhereProtocol.encodeFlowRequest(kind: .tcp, target: destination)
        let sid = try await session.openTCPStream(for: self, request: frame)
        let adopted = phase.withLock { Phase.transition(&$0, to: .open(sid: sid, ready: false, credited: 0)) }
        guard adopted else {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid, credited: 0)
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }

        var buffer = Data()
        while true {
            guard let chunk = try await nextChunk() else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Stream closed before complete READY"))
            }
            buffer.append(chunk)
            guard buffer.count >= NowhereProtocol.flowResultSize else { continue }
            guard let result = NowhereProtocol.decodeFlowResult(buffer) else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid flow result"))
            }
            recordCredit(count: NowhereProtocol.flowResultSize)
            switch result {
            case .ready:
                pendingData = Data(buffer.dropFirst(NowhereProtocol.flowResultSize))
                guard becomeReady() else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
                if let initialData, !initialData.isEmpty {
                    try await session.writeStream(sid, data: initialData)
                }
                return
            case .reject(let code):
                throw AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
            }
        }
    }

    // MARK: - Demux feed

    nonisolated func feedStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            rawInbox.yield(data, compactingAbove: Self.inboxCompactionDepth) { Data($0) }
        }
        if fin { rawInbox.finish() }
    }

    nonisolated func handleStreamTermination(error: Error?) {
        if let error { rawInbox.finish(throwing: error) } else { rawInbox.finish() }
        if let released = closeLifecycle() {
            session.shutdownStream(released.sid)
            session.releaseTCPStream(released.sid, credited: released.credited)
        }
    }

    nonisolated func handleSessionClose() {
        rawInbox.finish()
        _ = closeLifecycle()
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
        let sid: Int64? = phase.withLock { if case .open(let s, true, _) = $0 { s } else { nil } }
        guard let sid else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        try await session.writeStream(sid, data: data)
    }

    func receiveRaw() async throws -> Data? {
        if !pendingData.isEmpty {
            let out = pendingData
            pendingData = Data()
            credit(out.count)
            return out
        }
        guard let chunk = try await nextChunk() else {
            flushCredit()
            return nil
        }
        if !chunk.isEmpty {
            credit(chunk.count)
        }
        return chunk
    }

    private func nextChunk() async throws -> Data? {
        if !backlogChunks.isEmpty { return takeBacklog() }
        guard let batch = try await rawInbox.nextBatch() else { return nil }
        if batch.count == 1 { return batch[0] }
        backlogChunks = batch
        return takeBacklog()
    }

    private func takeBacklog() -> Data {
        var joined = Data(capacity: min(backlogChunks.reduce(0) { $0 + $1.count }, Self.maxChunkBytes))
        var index = 0
        while index < backlogChunks.count, joined.count < Self.maxChunkBytes {
            joined.append(backlogChunks[index])
            index += 1
        }
        backlogChunks.removeFirst(index)
        return joined
    }

    private func credit(_ count: Int) {
        uncreditedBytes += count
        guard uncreditedBytes >= Self.creditFlushThreshold else { return }
        flushCredit()
    }

    private func flushCredit() {
        guard uncreditedBytes > 0 else { return }
        let count = uncreditedBytes
        uncreditedBytes = 0
        recordCredit(count: count)
    }

    private nonisolated func recordCredit(count: Int) {
        guard count > 0 else { return }
        let sid: Int64? = phase.withLock { state -> Int64? in
            guard case .open(let s, let ready, let credited) = state else { return nil }
            Phase.transition(&state, to: .open(sid: s, ready: ready, credited: credited + count))
            return s
        }
        guard let sid else { return }
        session.extendStreamOffset(sid, count: count)
    }

    nonisolated func cancel() {
        rawInbox.finish()
        if let released = closeLifecycle() {
            session.shutdownStream(released.sid)
            session.releaseTCPStream(released.sid, credited: released.credited)
        }
    }
}

nonisolated final class NowhereTCPUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let udpState = Mutex(UDPFramingState())

    init(inner: ProxyConnection) {
        self.inner = inner
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    func sendRaw(_ data: Data) async throws {
        let frame: Data
        do {
            frame = try NowhereProtocol.encodeUDPStreamPacket(data)
        } catch AnywhereError.proxy(.nowhere, .packetTooLarge) {
            return
        }
        try await inner.sendRaw(frame)
    }

    private enum PacketStep {
        case deliver(Data)
        case needMore
    }

    private func nextPacketStep(_ state: inout UDPFramingState) -> PacketStep {
        let available = state.buffer.count - state.bufferOffset
        guard available >= 2 else { return .needMore }
        guard let (payload, consumed) = NowhereProtocol.decodeUDPStreamPacket(
            state.buffer,
            offset: state.bufferOffset
        ) else {
            return .needMore
        }
        state.bufferOffset += consumed
        if state.bufferOffset > 8192 {
            state.buffer.removeSubrange(0..<state.bufferOffset)
            state.bufferOffset = 0
        }
        return .deliver(payload)
    }

    func receiveRaw() async throws -> Data? {
        while true {
            let step = udpState.withLock { nextPacketStep(&$0) }
            switch step {
            case .deliver(let packet):
                return packet
            case .needMore:
                let data = try await inner.receive()
                guard let data else {
                    inner.cancel()
                    let truncated = udpState.withLock {
                        $0.buffer.count - $0.bufferOffset != 0
                    }
                    if truncated {
                        throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Truncated UoT packet"))
                    }
                    return nil
                }
                if data.isEmpty { continue }
                udpState.withLock { $0.buffer.append(data) }
            }
        }
    }

    func cancel() {
        finish(abortive: false)
    }

    func abort() {
        finish(abortive: true)
    }

    private func finish(abortive: Bool) {
        udpState.withLock {
            $0.buffer = Data()
            $0.bufferOffset = 0
        }
        if abortive {
            inner.abort()
        } else {
            inner.cancel()
        }
    }
}

extension NowhereConnection: ProxyConnection {}
