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
        case open(sid: Int64, ready: Bool)
        case closed

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

    private var receiveInProgress = false

    private var backlogChunks: [Data] = []
    private var backlogIndex = 0
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
        phase.withLock { if case .open(_, true) = $0 { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }

    private nonisolated func closeLifecycle() -> Int64? {
        phase.withLock { state in
            let released: Int64?
            switch state {
            case .closed: return nil
            case .open(let sid, _): released = sid
            case .idle, .opening: released = nil
            }
            Phase.transition(&state, to: .closed)
            return released
        }
    }

    private nonisolated func becomeReady() -> Bool {
        phase.withLock { state -> Bool in
            guard case .open(let sid, false) = state else { return false }
            return Phase.transition(&state, to: .open(sid: sid, ready: true))
        }
    }

    // MARK: - Open

    func open() async throws {
        let begin = phase.withLock { Phase.transition(&$0, to: .opening) }
        guard begin else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        do {
            try await withTaskCancellationHandler {
                try Task.checkCancellation()
                try await performOpen()
                try Task.checkCancellation()
            } onCancel: {
                self.cancel()
            }
        } catch {
            cancel()
            throw error
        }
    }

    private func performOpen() async throws {
        let frame = NowhereProtocol.encodeFlowRequest(kind: .tcp, target: destination)
        let sid = try await session.openTCPStream(for: self, request: frame)
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
            session.consumeTCPBytes(sid, count: NowhereProtocol.flowResultSize)
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
        cancel()
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
        let sid: Int64? = phase.withLock { if case .open(let s, true) = $0 { s } else { nil } }
        guard let sid else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await session.writeStream(sid, data: data)
        } onCancel: {
            self.cancel()
        }
    }

    func receiveRaw() async throws -> Data? {
        try Task.checkCancellation()
        guard !receiveInProgress else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Overlapping receive on Nowhere stream"))
        }
        receiveInProgress = true
        defer { receiveInProgress = false }
        if !pendingData.isEmpty {
            let out = pendingData
            pendingData = Data()
            credit(out.count)
            return out
        }
        guard let chunk = try await nextChunk() else { return nil }
        credit(chunk.count)
        return chunk
    }

    private func nextChunk() async throws -> Data? {
        if backlogIndex < backlogChunks.count { return takeBacklog() }
        guard let batch = try await rawInbox.nextBatch() else { return nil }
        if batch.count == 1 { return batch[0] }
        backlogChunks = batch
        backlogIndex = 0
        return takeBacklog()
    }

    private func takeBacklog() -> Data {
        defer {
            if backlogIndex == backlogChunks.count {
                backlogChunks.removeAll(keepingCapacity: false)
                backlogIndex = 0
            }
        }
        var joined = backlogChunks[backlogIndex]
        backlogChunks[backlogIndex] = Data()
        backlogIndex += 1
        while backlogIndex < backlogChunks.count,
              backlogChunks[backlogIndex].count <= Self.maxChunkBytes - joined.count {
            joined.append(backlogChunks[backlogIndex])
            backlogChunks[backlogIndex] = Data()
            backlogIndex += 1
        }
        return joined
    }

    private func credit(_ count: Int) {
        let sid = phase.withLock { state -> Int64? in
            if case .open(let sid, _) = state { return sid }
            return nil
        }
        if let sid { session.consumeTCPBytes(sid, count: count) }
    }

    nonisolated func adoptStream(_ sid: Int64) -> Bool {
        phase.withLock { Phase.transition(&$0, to: .open(sid: sid, ready: false)) }
    }

    nonisolated func cancel() {
        rawInbox.finish()
        if let sid = closeLifecycle() {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid)
        }
    }
}

nonisolated final class NowhereTCPUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private struct State {
        var framing = UDPFramingState()
        var receiveInProgress = false
        var closed = false
    }
    private let state = Mutex(State())

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
        case end
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
            let end = state.buffer.index(state.buffer.startIndex, offsetBy: state.bufferOffset)
            state.buffer.removeSubrange(state.buffer.startIndex..<end)
            state.bufferOffset = 0
        }
        return .deliver(payload)
    }

    func receiveRaw() async throws -> Data? {
        let begin = try state.withLock { state in
            guard !state.receiveInProgress else {
                throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Overlapping receive on Nowhere UDP framing"))
            }
            guard !state.closed else { return false }
            state.receiveInProgress = true
            return true
        }
        guard begin else { return nil }
        defer { state.withLock { $0.receiveInProgress = false } }
        return try await withTaskCancellationHandler {
            try await receivePacket()
        } onCancel: {
            self.cancel()
        }
    }

    private func receivePacket() async throws -> Data? {
        while true {
            try Task.checkCancellation()
            let step = state.withLock { state in
                state.closed ? .end : nextPacketStep(&state.framing)
            }
            switch step {
            case .deliver(let packet):
                return packet
            case .end:
                return nil
            case .needMore:
                let data = try await inner.receive()
                guard let data else {
                    let truncated = state.withLock {
                        $0.framing.buffer.count - $0.framing.bufferOffset != 0
                    }
                    cancel()
                    if truncated {
                        throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Truncated UoT packet"))
                    }
                    return nil
                }
                if data.isEmpty { continue }
                state.withLock {
                    if !$0.closed { $0.framing.buffer.append(data) }
                }
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
        state.withLock {
            $0.closed = true
            $0.framing = UDPFramingState()
        }
        if abortive {
            inner.abort()
        } else {
            inner.cancel()
        }
    }
}

extension NowhereConnection: ProxyConnection {}
