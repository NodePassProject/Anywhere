//
//  NaiveHTTP2Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Multiplexer")

nonisolated final class NaiveHTTP2Multiplexer: Multiplexer, Sendable {

    // MARK: - Phase

    enum Phase: Equatable {
        case idle
        case connecting
        /// Connection preface + SETTINGS sent, waiting for server SETTINGS.
        case prefaceSent
        /// SETTINGS exchanged, ready to open streams.
        case ready
        /// GOAWAY received — existing streams continue, no new streams.
        case goingAway
        case closed
    }

    // MARK: - Properties
    
    let host: String
    let port: UInt16
    let sni: String

    private let transport: TLSStreamTransport
    
    private let sendChain = SerialSender()
    private func chainSend(_ data: Data) -> SerialSender.Pending {
        let transport = self.transport
        return sendChain.submit { try await transport.send(data) }
    }
    
    private let connectHeaders: @Sendable () -> [(name: String, value: String)]
    
    private struct State {
        var phase: Phase = .idle
        var streams: [UInt32: NaiveHTTP2Stream] = [:]
        var sendWindows: [UInt32: Int] = [:]
        var nextStreamID: UInt32 = 1
        var maxConcurrentStreams: UInt32 = 100

        var connectionSendWindow: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize
        var connectionReceiveConsumed: Int = 0
        var connectionReceiveWindowSize: Int = NaiveHTTP2FlowControl.naiveSessionMaxReceiveWindow
        var peerInitialWindowSize: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize

        var receiveBuffer = Data()
        
        var flowGate = H2FlowGate()
        
        var sessionTask: Task<Void, Never>?
    }
    private let lock = Mutex(State())

    private static let maxReceiveBufferSize = 2_097_152
    
    private struct PoolSnapshot {
        var state: Phase = .idle
        var streamCount: Int = 0
        var maxConcurrent: UInt32 = 100
    }
    private let _poolSnapshot = Mutex(PoolSnapshot())
    
    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>
    
    private let onClose: (@Sendable (NaiveHTTP2Multiplexer) -> Void)?

    // MARK: - Initialization

    init(host: String, port: UInt16, sni: String, tunnel: ProxyConnection?,
         connectHeaders: @escaping @Sendable () -> [(name: String, value: String)],
         onClose: (@Sendable (NaiveHTTP2Multiplexer) -> Void)? = nil) {
        self.host = host
        self.port = port
        self.sni = sni
        self.connectHeaders = connectHeaders
        self.onClose = onClose
        self.transport = TLSStreamTransport(
            host: host,
            port: port,
            sni: sni,
            alpn: ["h2"],
            tunnel: tunnel
        )
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
    }

    // MARK: - Capacity

    /// Thread-safe count read off-lock by the idle sweep.
    var activeStreamCount: Int { _poolSnapshot.withLock { $0.streamCount } }

    /// Thread-safe: whether this multiplexer appears closed to the pool.
    var isClosed: Bool { _poolSnapshot.withLock { $0.state == .closed } }

    /// Thread-safe: whether this multiplexer has received GOAWAY.
    var poolIsGoingAway: Bool { _poolSnapshot.withLock { $0.state == .goingAway } }

    /// Atomically checks capacity and reserves a stream slot; accepts in-progress multiplexers
    /// so burst requests coalesce behind one handshake. Caller must follow up with `openStream`.
    func tryReserveStream() -> Bool {
        _poolSnapshot.withLock { snapshot in
            switch snapshot.state {
            case .idle, .connecting, .prefaceSent, .ready:
                break
            case .goingAway, .closed:
                return false
            }
            guard UInt32(snapshot.streamCount) < snapshot.maxConcurrent else { return false }
            snapshot.streamCount += 1
            return true
        }
    }

    /// Republishes the pool-visible snapshot. Reads `lock` and writes `_poolSnapshot` sequentially
    /// (never nested) so the two mutexes can't deadlock.
    private func refreshPoolSnapshot() {
        let (phase, count, maxConcurrent) = lock.withLock { ($0.phase, $0.streams.count, $0.maxConcurrentStreams) }
        _poolSnapshot.withLock { snapshot in
            snapshot.state = phase
            snapshot.streamCount = count
            snapshot.maxConcurrent = maxConcurrent
        }
    }

    // MARK: - Session Setup
    
    func ensureReady() async throws {
        enum Action { case ready; case park; case beginAndPark; case fail }
        let action: Action = lock.withLock { state in
            switch state.phase {
            case .ready:
                return .ready
            case .idle:
                state.phase = .connecting
                return .beginAndPark
            case .connecting, .prefaceSent:
                return .park
            case .goingAway, .closed:
                return .fail
            }
        }
        switch action {
        case .ready:
            return
        case .fail:
            throw AnywhereError.proxy(.naive, .notReady)
        case .beginAndPark:
            refreshPoolSnapshot()
            beginSetup()
            try await readyTask.value
        case .park:
            try await readyTask.value
        }
    }

    private func beginSetup() {
        let task = Task {
            do {
                try await transport.connect()
            } catch {
                let readyFail: Bool = lock.withLock { state in
                    guard state.phase != .closed else { return false }
                    state.phase = .closed
                    return true
                }
                if readyFail {
                    refreshPoolSnapshot()
                    completeReadyContinuations(error)
                }
                return
            }
            guard await sendConnectionPreface() else { return }
            await runReadLoop()
        }
        lock.withLock { state in
            if state.phase == .closed {
                task.cancel()
            } else {
                state.sessionTask = task
            }
        }
    }

    // MARK: - Stream Lifecycle

    /// Creates and registers a new logical stream. Locks internally, so the pool calls it directly
    /// (no queue hop). The stream's send window is seeded at the default and reconciled by SETTINGS.
    func openStream(destination: String) -> NaiveHTTP2Stream {
        let stream: NaiveHTTP2Stream = lock.withLock { state in
            let streamID = state.nextStreamID
            state.nextStreamID += 2  // Client streams are odd-numbered
            let stream = NaiveHTTP2Stream(
                streamID: streamID,
                multiplexer: self,
                destination: destination
            )
            state.streams[streamID] = stream
            state.sendWindows[streamID] = state.peerInitialWindowSize
            return stream
        }
        refreshPoolSnapshot()
        return stream
    }

    func removeStream(_ stream: NaiveHTTP2Stream) {
        lock.withLock { state in
            state.streams.removeValue(forKey: stream.streamID)
            state.sendWindows.removeValue(forKey: stream.streamID)
        }
        refreshPoolSnapshot()
    }

    /// Reseeds a stream's send window to the peer's INITIAL_WINDOW_SIZE once the handshake is done
    /// (the stream calls this from `openTunnel`, mirroring the former on-queue `sendWindow` seed).
    func reseedStreamSendWindow(_ streamID: UInt32) {
        lock.withLock { state in
            if state.sendWindows[streamID] != nil {
                state.sendWindows[streamID] = state.peerInitialWindowSize
            }
        }
    }

    // MARK: - Connection Preface

    private static let connectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".data(using: .ascii)!
    
    private func sendConnectionPreface() async -> Bool {
        var data = Data()

        data.append(Self.connectionPreface)
        
        let settings = NaiveHTTP2Framer.settingsFrame([
            (id: 0x1, value: 65536),     // HEADER_TABLE_SIZE
            (id: 0x2, value: 0),         // ENABLE_PUSH
            (id: 0x3, value: 100),       // MAX_CONCURRENT_STREAMS
            (id: 0x4, value: UInt32(NaiveHTTP2FlowControl.naiveInitialWindowSize)),
            (id: 0x5, value: 16384),     // MAX_FRAME_SIZE
            (id: 0x6, value: 262144),    // MAX_HEADER_LIST_SIZE
        ])
        data.append(settings.serialized)
        
        let windowUpdate = NaiveHTTP2Framer.windowUpdateFrame(
            streamID: 0,
            increment: NaiveHTTP2FlowControl.connectionWindowUpdateIncrement
        )
        data.append(windowUpdate.serialized)

        let prefaceSend = chainSend(data)
        do {
            try await prefaceSend.value()
        } catch {
            let failed: Bool = lock.withLock { state in
                guard state.phase != .closed else { return false }
                state.phase = .closed
                return true
            }
            if failed {
                transport.cancel()
                refreshPoolSnapshot()
                completeReadyContinuations(error)
            }
            return false
        }
        let proceed: Bool = lock.withLock { state in
            guard state.phase == .connecting else { return false }
            state.phase = .prefaceSent
            return true
        }
        guard proceed else { return false }
        refreshPoolSnapshot()
        return true
    }

    // MARK: - Read Loop
    
    private func runReadLoop() async {
        let hpackDecoder = HPACKDecoder()
        while true {
            if lock.withLock({ $0.phase == .closed }) { return }

            let data: Data?
            do { data = try await transport.receive() }
            catch { handleSessionError(error); return }

            guard let data, !data.isEmpty else {
                handleSessionError(AnywhereError.proxy(.naive, .connectionClosed(detail: "Connection closed")))
                return
            }

            let overflow: Bool = lock.withLock { state in
                guard state.phase != .closed else { return false }
                state.receiveBuffer.append(data)
                if state.receiveBuffer.count > Self.maxReceiveBufferSize {
                    state.receiveBuffer.removeAll()
                    return true
                }
                return false
            }
            if overflow {
                handleSessionError(AnywhereError.proxy(.naive, .connectionClosed(detail: "Receive buffer exceeded \(Self.maxReceiveBufferSize) bytes")))
                return
            }

            drainFrames(hpackDecoder: hpackDecoder)
        }
    }
    
    private func drainFrames(hpackDecoder: HPACKDecoder) {
        while true {
            let frame: NaiveHTTP2Frame? = lock.withLock { state in
                guard state.phase != .closed else { return nil }
                return NaiveHTTP2Framer.deserialize(from: &state.receiveBuffer)
            }
            guard let frame else { break }
            routeFrame(frame, hpackDecoder: hpackDecoder)
        }
        lock.withLock { state in
            if state.receiveBuffer.isEmpty { state.receiveBuffer = Data() }
        }
    }

    private func routeFrame(_ frame: NaiveHTTP2Frame, hpackDecoder: HPACKDecoder) {
        switch frame.type {
        case .settings:
            handleSettings(frame)

        case .ping:
            if !frame.hasFlag(NaiveHTTP2FrameFlags.ack) {
                sendControlFrame(NaiveHTTP2Framer.pingAckFrame(opaqueData: frame.payload))
            }

        case .goaway:
            handleGoaway(frame)

        case .windowUpdate:
            handleWindowUpdate(frame)

        case .headers:
            let stream: NaiveHTTP2Stream? = lock.withLock { $0.streams[frame.streamID] }
            guard let stream else { break }
            if let decoded = hpackDecoder.decodeHeaders(from: frame.payload) {
                stream.handleHeaders(fields: decoded.fields)
            } else {
                stream.handleStreamError(AnywhereError.proxy(.naive, .protocolViolation(detail: "Failed to decode headers on stream \(frame.streamID)")))
            }

        case .data:
            let endStream = frame.hasFlag(NaiveHTTP2FrameFlags.endStream)
            let stream: NaiveHTTP2Stream? = lock.withLock { $0.streams[frame.streamID] }
            stream?.handleData(frame.payload, endStream: endStream)

        case .rstStream:
            let stream: NaiveHTTP2Stream? = lock.withLock { $0.streams[frame.streamID] }
            if let stream {
                let errorCode = NaiveHTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                stream.handleReset(errorCode: errorCode)
            }

        case .continuation:
            break
        }
    }

    // MARK: - Frame Handlers

    private func handleSettings(_ frame: NaiveHTTP2Frame) {
        if frame.hasFlag(NaiveHTTP2FrameFlags.ack) { return }

        var becameReady = false
        lock.withLock { state in
            let settings = NaiveHTTP2Framer.parseSettings(payload: frame.payload)
            for (id, value) in settings {
                switch id {
                case 0x3: // MAX_CONCURRENT_STREAMS
                    state.maxConcurrentStreams = value
                case 0x4: // INITIAL_WINDOW_SIZE — adjusts every live stream's send window.
                    let delta = Int(value) - state.peerInitialWindowSize
                    state.peerInitialWindowSize = Int(value)
                    for sid in state.sendWindows.keys { state.sendWindows[sid]! += delta }
                default:
                    break
                }
            }
            if state.phase == .prefaceSent {
                state.phase = .ready
                becameReady = true
            }
        }

        sendControlFrame(NaiveHTTP2Framer.settingsAckFrame())

        if becameReady {
            completeReadyContinuations(nil)
        }
        refreshPoolSnapshot()
    }

    private func handleGoaway(_ frame: NaiveHTTP2Frame) {
        let parsed = NaiveHTTP2Framer.parseGoaway(payload: frame.payload)
        if let parsed {
            logger.warning("[NaiveHTTP2Multiplexer] GOAWAY: lastStreamID=\(parsed.lastStreamID), errorCode=\(parsed.errorCode)")
        }

        var doomed: [NaiveHTTP2Stream] = []
        let failReady: Bool = lock.withLock { state in
            let previousState = state.phase
            state.phase = .goingAway
            if let parsed {
                for (id, stream) in state.streams where id > parsed.lastStreamID {
                    doomed.append(stream)
                }
            }
            return previousState == .prefaceSent || previousState == .connecting
        }

        refreshPoolSnapshot()
        for stream in doomed { stream.handleSessionError(AnywhereError.proxy(.naive, .goaway)) }
        if failReady {
            completeReadyContinuations(AnywhereError.proxy(.naive, .goaway))
        }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload) else { return }
        lock.withLock { state in
            if frame.streamID == 0 {
                state.connectionSendWindow += Int(increment)
            } else if state.sendWindows[frame.streamID] != nil {
                state.sendWindows[frame.streamID]! += Int(increment)
            }
            // A re-opened window (connection- or stream-level) wakes parked sends; each re-checks its
            // own min(connection, stream) window before building frames.
            state.flowGate.wakeAll()
        }
    }
    
    func acknowledgeReceivedData(count: Int) {
        let update: NaiveHTTP2Frame? = lock.withLock { state in
            state.connectionReceiveConsumed += count
            guard state.connectionReceiveConsumed >= state.connectionReceiveWindowSize / 2 else { return nil }
            let increment = UInt32(state.connectionReceiveConsumed)
            state.connectionReceiveConsumed = 0
            return NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment)
        }
        if let update { sendControlFrame(update) }
    }

    // MARK: - Send

    func sendConnect(stream: NaiveHTTP2Stream) async throws {
        let extraHeaders = connectHeaders()

        let headerBlock = HPACKEncoder.encodeConnectRequest(
            authority: stream.destination,
            extraHeaders: extraHeaders
        )
        let headersFrame = NaiveHTTP2Framer.headersFrame(
            streamID: stream.streamID,
            headerBlock: headerBlock,
            endStream: false
        )

        try await enqueueOrdered(headersFrame.serialized)
    }

    /// One outcome of a flow-control-bounded frame-build pass, decided under `lock`.
    private enum SendStep {
        case closed
        case park
        case built(frames: Data, nextOffset: Int)
    }

    /// Sends DATA frames for a stream, respecting connection + stream flow control. When the
    /// window is exhausted it parks on a continuation resumed by the next WINDOW_UPDATE, instead
    /// of the old 50 ms poll.
    func sendData(_ data: Data, on stream: NaiveHTTP2Stream) async throws {
        var offset = 0
        while offset < data.count {
            let step = buildDataStep(data, on: stream, offset: offset)
            switch step {
            case .closed:
                throw AnywhereError.proxy(.naive, .notReady)
            case .park:
                await parkForFlow(stream: stream)
            case .built(let frames, let nextOffset):
                try await enqueueOrdered(frames)
                offset = nextOffset
            }
        }
    }

    /// Builds as many DATA frames as the current flow window allows, debiting the connection- and
    /// stream-level windows atomically under `lock`; returns `.park` when the window is exhausted.
    private func buildDataStep(_ data: Data, on stream: NaiveHTTP2Stream, offset: Int) -> SendStep {
        lock.withLock { state in
            guard state.phase != .closed else { return .closed }
            guard let streamSendWindow = state.sendWindows[stream.streamID] else { return .closed }

            let maxPayload = NaiveHTTP2Framer.maxDataPayload
            var currentOffset = offset
            var frames = Data()
            var streamWindow = streamSendWindow

            while currentOffset < data.count {
                let remaining = data.count - currentOffset
                let maxByFlow = min(state.connectionSendWindow, streamWindow)
                let chunkSize = min(remaining, min(maxPayload, maxByFlow))

                guard chunkSize > 0 else { break }

                state.connectionSendWindow -= chunkSize
                streamWindow -= chunkSize

                let chunk = Data(data[data.startIndex + currentOffset ..< data.startIndex + currentOffset + chunkSize])
                let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk)
                frames.append(frame.serialized)
                currentOffset += chunkSize
            }
            state.sendWindows[stream.streamID] = streamWindow

            if frames.isEmpty {
                return .park
            } else {
                return .built(frames: frames, nextOffset: currentOffset)
            }
        }
    }

    /// Suspends until a WINDOW_UPDATE re-opens the send window (or the session closes). Re-checks
    /// under `lock` before parking so a window re-open racing the caller isn't missed.
    private func parkForFlow(stream: NaiveHTTP2Stream) async {
        await H2FlowGate.park {
            lock.withLock { state -> AsyncStream<Never>? in
                if state.phase == .closed { return nil }
                guard let streamSendWindow = state.sendWindows[stream.streamID] else { return nil }
                if min(state.connectionSendWindow, streamSendWindow) > 0 { return nil }
                return state.flowGate.enroll()
            }
        }
    }

    /// Submits one ordered send onto the pipeline and awaits it (submission order preserved).
    private func enqueueOrdered(_ data: Data) async throws {
        try await chainSend(data).value()
    }

    /// Sends a control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE). Fire-and-forget.
    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        let pending = chainSend(frame.serialized)
        Task {
            do {
                try await pending.value()
            } catch {
                logger.warning("[NaiveHTTP2Multiplexer] Failed to send control frame: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Error Handling

    private func handleSessionError(_ error: Error) {
        teardown(reason: error)
    }

    private func completeReadyContinuations(_ error: Error?) {
        if let error { readySignal.finish(throwing: error) } else { readySignal.finish() }
    }

    func close(error: Error? = nil) {
        teardown(reason: error ?? AnywhereError.proxy(.naive, .connectionClosed(detail: "Session closed")))
    }
    
    private func teardown(reason: Error) {
        typealias Teardown = (victims: [NaiveHTTP2Stream], sessionTask: Task<Void, Never>?)
        let teardownState: Teardown? = lock.withLock { state in
            guard state.phase != .closed else { return nil }
            state.phase = .closed
            state.flowGate.wakeAll()
            let victims = Array(state.streams.values)
            state.streams.removeAll()
            state.sendWindows.removeAll()
            let session = state.sessionTask
            state.sessionTask = nil
            return (victims, session)
        }
        guard let (victims, sessionTask) = teardownState else { return }
        sessionTask?.cancel()
        transport.cancel()
        completeReadyContinuations(reason)
        for stream in victims { stream.handleSessionError(reason) }
        refreshPoolSnapshot()
        onClose?(self)
    }
}
