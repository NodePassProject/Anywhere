//
//  SudokuMux.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import Darwin
import Synchronization

nonisolated private let sudokuLogger = AnywhereLogger(category: "SudokuProxyConnection")
nonisolated private let sudokuMuxMaxQueueBytes = 4 * 1024 * 1024

nonisolated enum SudokuAddress {
    static func encode(host: String, port: UInt16) throws -> Data {
        var out = Data()
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            out.append(0x01)
            withUnsafeBytes(of: ipv4.s_addr) { out.append(contentsOf: $0) }
        } else if host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            out.append(0x04)
            withUnsafeBytes(of: ipv6) { out.append(contentsOf: $0) }
        } else {
            let bytes = Array(host.utf8)
            guard bytes.count <= 255 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "domain too long")) }
            out.append(0x03)
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(UInt8(port >> 8))
        out.append(UInt8(port & 0xff))
        return out
    }
}

nonisolated final class SudokuMuxClient: Multiplexer, Sendable {
    private static let keepaliveInterval: TimeInterval = 15
    private let record: SudokuRecordStream
    private let factory: SudokuConnectionFactory?
    private let usesHTTPMaskControlFrames: Bool
    
    private let onClose: (@Sendable (SudokuMuxClient) -> Void)?

    private struct State: PhaseHolding {
        var streams: [UInt32: SudokuMuxStream] = [:]
        var nextStreamID: UInt32 = 0
        var lastWrite: ContinuousClock.Instant = ContinuousClock.now
        var lastPong: ContinuousClock.Instant = ContinuousClock.now
        var phase: SudokuLifecycle = .open
        var runTask: Task<Void, Never>?
        var keepalive: DeadlineToken?
    }
    private let state = Mutex(State())

    var isClosed: Bool {
        state.withLock { $0.phase == .closed }
    }
    
    var activeStreamCount: Int {
        state.withLock { $0.streams.count }
    }

    init(
        record: SudokuRecordStream,
        factory: SudokuConnectionFactory? = nil,
        usesHTTPMaskControlFrames: Bool = false,
        onClose: (@Sendable (SudokuMuxClient) -> Void)? = nil
    ) {
        self.record = record
        self.factory = factory
        self.usesHTTPMaskControlFrames = usesHTTPMaskControlFrames
        self.onClose = onClose
        let task = Task { await self.readerLoop() }
        state.withLock { $0.runTask = task }
        armKeepalive()
    }

    private func armKeepalive() {
        state.withLock { state in
            guard state.phase == .open else { return }
            state.keepalive?.cancel()
            state.keepalive = TickScheduler.shared.schedule(
                in: .seconds(Self.keepaliveInterval),
                precision: .relaxed
            ) { [weak self] in
                guard let self else { return }
                self.sendKeepaliveIfIdle()
                self.armKeepalive()
            }
        }
    }

    func dialTCP(host: String, port: UInt16) async throws -> SudokuMuxStream {
        let stream = SudokuMuxStream(client: self, id: allocateStreamID())
        let closed = state.withLock { state -> Bool in
            if state.phase == .closed { return true }
            state.streams[stream.id] = stream
            return false
        }
        if closed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        do {
            try await sendFrame(type: 0x01, streamID: stream.id, payload: SudokuAddress.encode(host: host, port: port))
        } catch {
            state.withLock { _ = $0.streams.removeValue(forKey: stream.id) }
            stream.markClosed(discardQueuedData: true, error: error)
            throw error
        }
        return stream
    }

    func sendFrame(type: UInt8, streamID: UInt32, payload: Data) async throws {
        guard payload.count <= 256 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "mux frame too large")) }
        let isClosed = state.withLock { $0.phase == .closed }
        guard !isClosed else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        var header = Data([type])
        var sid = streamID.bigEndian
        var length = UInt32(payload.count).bigEndian
        header.append(Data(bytes: &sid, count: 4))
        header.append(Data(bytes: &length, count: 4))
        do {
            try await record.sendBuffers([header, payload])
            state.withLock { $0.lastWrite = ContinuousClock.now }
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            close(error: error)
            throw error
        }
    }

    func removeStream(id: UInt32) {
        state.withLock { _ = $0.streams.removeValue(forKey: id) }
    }
    
    func close(error: Error? = nil) {
        typealias Drained = (streams: [SudokuMuxStream], run: Task<Void, Never>?, keepalive: DeadlineToken?)
        let drained: Drained? = state.withLock { state in
            guard state.transition(to: .closed) else { return nil }
            let streamsToClose = Array(state.streams.values)
            state.streams.removeAll()
            let run = state.runTask
            state.runTask = nil
            let keepalive = state.keepalive
            state.keepalive = nil
            return (streamsToClose, run, keepalive)
        }
        guard let drained else { return }
        drained.run?.cancel()
        drained.keepalive?.cancel()
        for stream in drained.streams {
            stream.markClosed(discardQueuedData: true, error: error)
        }
        record.close()
        factory?.closeAll()
        onClose?(self)
    }

    private func allocateStreamID() -> UInt32 {
        state.withLock { state in
            repeat { state.nextStreamID &+= 1 } while state.nextStreamID == 0
            return state.nextStreamID
        }
    }

    private func sendKeepaliveIfIdle() {
        if usesHTTPMaskControlFrames {
            let timedOut = state.withLock { state in
                state.phase == .open && state.lastPong.duration(to: ContinuousClock.now) >= .seconds(Self.keepaliveInterval * 3)
            }
            if timedOut {
                close(error: AnywhereError.proxy(.sudoku, .connectionClosed(detail: "mux keepalive timeout")))
                return
            }
            Task { [weak self] in try? await self?.sendFrame(type: 0x05, streamID: 0, payload: Data()) }
            return
        }
        let shouldSend = state.withLock { state in
            state.phase == .open && state.lastWrite.duration(to: ContinuousClock.now) >= .seconds(Self.keepaliveInterval)
        }
        if shouldSend {
            Task { [weak self] in try? await self?.sendFrame(type: 0x02, streamID: 0, payload: Data()) }
        }
    }

    private func readerLoop() async {
        while true {
            do {
                let header = try await record.readExact(9)
                let type = header.uint8(at: 0)
                let streamID = header.uint32BE(at: 1)
                let length = Int(header.uint32BE(at: 5))
                guard length <= 256 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "mux frame too large")) }
                let payload = try await record.readExact(length)
                let stream = state.withLock { $0.streams[streamID] }
                switch type {
                case 0x05:
                    guard streamID == 0, payload.isEmpty else {
                        throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "invalid mux ping frame"))
                    }
                    Task { [weak self] in try? await self?.sendFrame(type: 0x06, streamID: 0, payload: Data()) }
                case 0x06:
                    guard streamID == 0, payload.isEmpty else {
                        throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "invalid mux pong frame"))
                    }
                    state.withLock { $0.lastPong = ContinuousClock.now }
                case 0x02:
                    guard let stream, !payload.isEmpty else { continue }
                    if case .overflow = stream.enqueue(payload) {
                        let error = AnywhereError.proxy(.sudoku, .connectionClosed(detail: "mux receive queue full"))
                        sudokuLogger.warning("[Sudoku] Mux receive queue full")
                        stream.markClosed(discardQueuedData: true, error: error)
                        removeStream(id: streamID)
                        Task { [weak self] in
                            try? await self?.sendFrame(type: 0x04, streamID: streamID, payload: Data("receive queue full".utf8))
                            try? await self?.sendFrame(type: 0x03, streamID: streamID, payload: Data())
                        }
                    }
                case 0x03:
                    if stream?.markRemoteWriteClosed() == true {
                        removeStream(id: streamID)
                    }
                case 0x04:
                    let rawMessage = String(data: payload, encoding: .utf8)?
                        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                    let message = rawMessage.isEmpty ? "mux stream reset" : rawMessage
                    stream?.markClosed(
                        discardQueuedData: true,
                        error: AnywhereError.proxy(.sudoku, .connectionClosed(detail: message))
                    )
                    removeStream(id: streamID)
                default: throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad mux frame"))
                }
            } catch AnywhereError.proxy(.sudoku, .connectionClosed(nil)) {
                close()
                return
            } catch {
                let wasClosed = state.withLock { $0.phase == .closed }
                if !wasClosed {
                    sudokuLogger.report("[Sudoku] Mux read failed", error: error)
                }
                close(error: error)
                return
            }
        }
    }
}

nonisolated final class SudokuMuxStream: Sendable {
    enum EnqueueResult {
        case accepted
        case ignored
        case overflow
    }

    let id: UInt32
    private struct WeakClient { weak var value: SudokuMuxClient? }
    private let clientBox: Mutex<WeakClient>
    private let sendChain = SerialSender()
    
    private func chainedSend(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await sendChain.run(body)
    }

    private enum Phase: PhaseTransitionable {
        case open
        case remoteWriteClosed
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .remoteWriteClosed):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }

        var isClosed: Bool { self == .closed }
        var readsFinished: Bool { self != .open }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .open

        var queue = SudokuDataQueue()
        var terminalError: Error?
        var receiveWaiter: AsyncStream<Void>.Continuation?
    }
    private let state = Mutex(State())
    
    private func wakeReceiveWaiterLocked(_ state: inout State) {
        state.receiveWaiter?.finish()
        state.receiveWaiter = nil
    }

    init(client: SudokuMuxClient, id: UInt32) { self.clientBox = Mutex(WeakClient(value: client)); self.id = id }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await chainedSend { [self] in
            guard let client = clientBox.withLock({ $0.value }) else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
            let (cannotWrite, error) = state.withLock { state in
                (state.phase.isClosed, state.terminalError)
            }
            if let error { throw error }
            guard !cannotWrite else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }

            var offset = 0
            while offset < data.count {
                let count = min(128 * 1024, data.count - offset)
                try await client.sendFrame(type: 0x02, streamID: id, payload: data.rangeData(offset: offset, count: count))
                offset += count
            }
        }
    }
    
    func receive(max: Int) async throws -> Data? {
        enum Outcome { case data(Data), eof, error(Error), concurrent, wait(AsyncStream<Void>) }
        while true {
            let outcome: Outcome = state.withLock { state in
                if !state.queue.isEmpty {
                    return .data(state.queue.read(max: max))
                }
                if state.phase.isClosed {
                    if let error = state.terminalError { return .error(error) }
                    return .eof
                }
                if state.phase.readsFinished {
                    return .eof
                }
                if state.receiveWaiter != nil {
                    return .concurrent
                }
                let (stream, continuation) = AsyncStream<Void>.makeStream()
                state.receiveWaiter = continuation
                return .wait(stream)
            }
            switch outcome {
            case .data(let out): return out
            case .eof: return nil
            case .error(let error): throw error
            case .concurrent: throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "concurrent mux receive"))
            case .wait(let stream):
                for await _ in stream { break }
                try Task.checkCancellation()
            }
        }
    }

    func enqueue(_ data: Data) -> EnqueueResult {
        state.withLock { state in
            if state.phase.readsFinished {
                return .ignored
            }
            guard state.queue.count + data.count <= sudokuMuxMaxQueueBytes else {
                return .overflow
            }
            state.queue.append(data)
            wakeReceiveWaiterLocked(&state)
            return .accepted
        }
    }

    func close() {
        let closedNow: Bool = state.withLock { state in
            guard state.transition(to: .closed) else { return false }
            state.terminalError = nil
            state.queue.removeAll(keepingCapacity: false)
            wakeReceiveWaiterLocked(&state)
            return true
        }
        guard closedNow else { return }

        if let client = clientBox.withLock({ $0.value }) {
            Task { await self.sendCloseFrame(to: client) }
            client.removeStream(id: id)
        }
    }

    private func sendCloseFrame(to client: SudokuMuxClient) async {
        try? await chainedSend { [self] in
            try? await client.sendFrame(type: 0x03, streamID: id, payload: Data())
        }
    }

    @discardableResult
    func markRemoteWriteClosed() -> Bool {
        state.withLock { state in
            guard state.transition(to: .remoteWriteClosed) else { return false }
            if state.queue.isEmpty {
                wakeReceiveWaiterLocked(&state)
            }
            return state.phase.isClosed
        }
    }

    func markClosed(discardQueuedData: Bool = false, error: Error? = nil) {
        let closedNow: Bool = state.withLock { state in
            guard state.transition(to: .closed) else { return false }
            state.terminalError = error
            if discardQueuedData {
                state.queue.removeAll(keepingCapacity: false)
            }
            wakeReceiveWaiterLocked(&state)
            return true
        }
        guard closedNow else { return }
        sendChain.cancel()
    }
}
