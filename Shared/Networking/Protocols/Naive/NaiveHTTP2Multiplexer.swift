//
//  NaiveHTTP2Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Multiplexer")

nonisolated class NaiveHTTP2Multiplexer: Multiplexer, @unchecked Sendable {

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

    /// Server identity used as pool key.
    let host: String
    let port: UInt16
    let sni: String

    private let transport: TLSStreamTransport
    /// Tail of the ordered wire-send chain over the TLS transport. Each frame links after the
    /// previous and runs only once it finishes, so frames reach the wire in submission order
    /// without a lock held across the write.
    private let sendChain = SerialSendChain()

    /// Links a wire send onto the ordered chain; the returned task's `value` carries backpressure
    /// and the send's error to whoever awaits it.
    private func chainSend(_ data: Data) -> Task<Void, Error> {
        let transport = self.transport
        return sendChain.enqueue { try await transport.send(data) }
    }
    /// Invoked once per stream so randomized values (auth, padding) differ per request.
    private let connectHeaders: () -> [(name: String, value: String)]

    /// Guards all mutable multiplexer + per-stream *send*-window state. Never held across a call
    /// into a stream, a chained send, or a continuation resume; effects are computed under the
    /// lock and performed after it is released. (Per-stream *response* state lives in the stream
    /// under its own lock, so a stream only ever calls back with no lock held: stream → multiplexer.)
    private struct State {
        var phase: Phase = .idle
        var streams: [UInt32: NaiveHTTP2Stream] = [:]
        /// Per-stream send flow window; presence tracks liveness for a build/park pass.
        var sendWindows: [UInt32: Int] = [:]
        var nextStreamID: UInt32 = 1
        var maxConcurrentStreams: UInt32 = 100

        var connectionSendWindow: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize
        var connectionRecvConsumed: Int = 0
        var connectionRecvWindowSize: Int = NaiveHTTP2FlowControl.naiveSessionMaxRecvWindow
        /// The INITIAL_WINDOW_SIZE the peer advertised (for new streams).
        var peerInitialWindowSize: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize

        var receiveBuffer = Data()

        /// Send-side parks waiting on a WINDOW_UPDATE that re-opens flow control. Replaces the old
        /// 50 ms flow-control retry poll.
        var flowResumptions: [CheckedContinuation<Void, Never>] = []
    }
    private let lock = Mutex(State())

    /// Connection-scoped HPACK decoder; the dynamic table is shared across all streams (RFC 7541 §2.2).
    /// Touched only by the single read-loop task, so it needs no separate lock.
    let hpackDecoder = HPACKDecoder()

    private static let maxReceiveBufferSize = 2_097_152

    // Pool-visible snapshot behind its own mutex: the pool reads off-lock, the multiplexer maintains it.
    private struct PoolSnapshot {
        var state: Phase = .idle
        var streamCount: Int = 0
        var maxConcurrent: UInt32 = 100
    }
    private let _poolSnapshot = Mutex(PoolSnapshot())

    /// Readiness awaiters coalesced behind one handshake; resolves at `.ready` or on fail/close.
    /// The waiter continuations live in the gate (async infra), not the locked layer.
    /// Readiness latch: the ready/teardown path finishes `readySignal` (throwing on failure);
    /// every awaiter gets that one outcome via `readyTask.value` (broadcast, cached once resolved).
    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    /// Called when the multiplexer becomes permanently unusable so the pool can evict it.
    var onClose: (() -> Void)?

    // MARK: - Initialization

    init(host: String, port: UInt16, sni: String, tunnel: ProxyConnection?,
         connectHeaders: @escaping () -> [(name: String, value: String)]) {
        self.host = host
        self.port = port
        self.sni = sni
        self.connectHeaders = connectHeaders
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

    /// Coalesces awaiters behind one handshake; resolves at `.ready` or on fail/close. Kicks the
    /// handshake, then parks on the gate — callable from any async context.
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
            throw NaiveHTTP2Error.notReady
        case .beginAndPark:
            refreshPoolSnapshot()
            beginSetup()
            try await readyTask.value
        case .park:
            try await readyTask.value
        }
    }

    private func beginSetup() {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.transport.connect()
                self.sendConnectionPreface()
            } catch {
                let readyFail: Bool = self.lock.withLock { state in
                    guard state.phase != .closed else { return false }
                    state.phase = .closed
                    return true
                }
                if readyFail {
                    self.refreshPoolSnapshot()
                    self.completeReadyContinuations(error)
                }
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

    private func sendConnectionPreface() {
        var data = Data()

        data.append(Self.connectionPreface)

        // SETTINGS chosen to match a common browser profile (probe resistance)
        let settings = NaiveHTTP2Framer.settingsFrame([
            (id: 0x1, value: 65536),     // HEADER_TABLE_SIZE
            (id: 0x2, value: 0),         // ENABLE_PUSH
            (id: 0x3, value: 100),       // MAX_CONCURRENT_STREAMS
            (id: 0x4, value: UInt32(NaiveHTTP2FlowControl.naiveInitialWindowSize)),
            (id: 0x5, value: 16384),     // MAX_FRAME_SIZE
            (id: 0x6, value: 262144),    // MAX_HEADER_LIST_SIZE
        ])
        data.append(settings.serialized)

        // Expand connection receive window to 128 MB
        let windowUpdate = NaiveHTTP2Framer.windowUpdateFrame(
            streamID: 0,
            increment: NaiveHTTP2FlowControl.connectionWindowUpdateIncrement
        )
        data.append(windowUpdate.serialized)

        let prefaceTask = chainSend(data)
        Task { [weak self] in
            guard let self else { return }
            do {
                try await prefaceTask.value
            } catch {
                let failed: Bool = self.lock.withLock { state in
                    guard state.phase != .closed else { return false }
                    state.phase = .closed
                    return true
                }
                if failed {
                    self.transport.cancel()
                    self.refreshPoolSnapshot()
                    self.completeReadyContinuations(error)
                }
                return
            }
            let proceed: Bool = self.lock.withLock { state in
                guard state.phase == .connecting else { return false }
                state.phase = .prefaceSent
                return true
            }
            guard proceed else { return }
            self.refreshPoolSnapshot()
            self.startReadLoop()
        }
    }

    // MARK: - Read Loop

    /// Persistent read loop; runs from `prefaceSent` until `closed`. Each iteration reads the next
    /// transport chunk, appends it, and drains every complete frame (replacing the former per-read
    /// recursive `Task` + `queue.async`).
    private func startReadLoop() {
        Task { [weak self] in
            while true {
                guard let self else { return }
                if self.lock.withLock({ $0.phase == .closed }) { return }

                let data: Data?
                do { data = try await self.transport.receive() }
                catch { self.handleSessionError(error); return }

                guard let data, !data.isEmpty else {
                    self.handleSessionError(NaiveHTTP2Error.connectionFailed("Connection closed"))
                    return
                }

                let overflow: Bool = self.lock.withLock { state in
                    guard state.phase != .closed else { return false }
                    state.receiveBuffer.append(data)
                    if state.receiveBuffer.count > Self.maxReceiveBufferSize {
                        state.receiveBuffer.removeAll()
                        return true
                    }
                    return false
                }
                if overflow {
                    self.handleSessionError(NaiveHTTP2Error.connectionFailed("Receive buffer exceeded \(Self.maxReceiveBufferSize) bytes"))
                    return
                }

                self.drainFrames()
            }
        }
    }

    /// Pops and routes each complete frame from the receive buffer. Runs on the read-loop task, so
    /// frames are processed strictly one at a time; each `routeFrame` does its state work under
    /// `lock` and performs stream/send effects with the lock released.
    private func drainFrames() {
        while true {
            let frame: NaiveHTTP2Frame? = lock.withLock { state in
                guard state.phase != .closed else { return nil }
                return NaiveHTTP2Framer.deserialize(from: &state.receiveBuffer)
            }
            guard let frame else { break }
            routeFrame(frame)
        }
        lock.withLock { state in
            if state.receiveBuffer.isEmpty { state.receiveBuffer = Data() }  // Release backing store
        }
    }

    private func routeFrame(_ frame: NaiveHTTP2Frame) {
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
            // Decode on the read-loop task (hpackDecoder is single-task), then hand the fields to
            // the stream with no lock held.
            let stream: NaiveHTTP2Stream? = lock.withLock { $0.streams[frame.streamID] }
            guard let stream else { break }
            if let decoded = hpackDecoder.decodeHeaders(from: frame.payload) {
                stream.handleHeaders(fields: decoded.fields)
            } else {
                stream.handleStreamError(NaiveHTTP2Error.protocolError("Failed to decode headers on stream \(frame.streamID)"))
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
            // CONNECT tunnels never split HEADERS across CONTINUATION; nothing to do.
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
        for stream in doomed { stream.handleSessionError(NaiveHTTP2Error.goaway) }
        if failReady {
            completeReadyContinuations(NaiveHTTP2Error.goaway)
        }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload) else { return }
        let parks: [CheckedContinuation<Void, Never>] = lock.withLock { state in
            if frame.streamID == 0 {
                state.connectionSendWindow += Int(increment)
            } else if state.sendWindows[frame.streamID] != nil {
                state.sendWindows[frame.streamID]! += Int(increment)
            }
            // A re-opened window (connection- or stream-level) wakes parked sends; each re-checks its
            // own min(connection, stream) window before building frames.
            let parks = state.flowResumptions
            state.flowResumptions.removeAll()
            return parks
        }
        for continuation in parks { continuation.resume() }
    }

    /// Acknowledges only bytes actually delivered to the consumer; called by a stream.
    func acknowledgeReceivedData(count: Int) {
        let update: NaiveHTTP2Frame? = lock.withLock { state in
            state.connectionRecvConsumed += count
            guard state.connectionRecvConsumed >= state.connectionRecvWindowSize / 2 else { return nil }
            let increment = UInt32(state.connectionRecvConsumed)
            state.connectionRecvConsumed = 0
            return NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment)
        }
        if let update { sendControlFrame(update) }
    }

    // MARK: - Send (called by streams)

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
                throw NaiveHTTP2Error.notReady
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
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let resumeNow: Bool = lock.withLock { state in
                if state.phase == .closed { return true }
                guard let streamSendWindow = state.sendWindows[stream.streamID] else { return true }
                if min(state.connectionSendWindow, streamSendWindow) > 0 { return true }
                state.flowResumptions.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    /// Links one ordered send onto the chain and awaits it (submission order preserved).
    private func enqueueOrdered(_ data: Data) async throws {
        try await chainSend(data).value
    }

    /// Sends a control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE). Fire-and-forget.
    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        let task = chainSend(frame.serialized)
        Task {
            do {
                try await task.value
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
        teardown(reason: error ?? NaiveHTTP2Error.connectionFailed("Session closed"))
    }

    /// Central close/teardown: flips to `.closed`, cancels the transport/pump, and fails every
    /// waiter, park, and live stream. Idempotent.
    private func teardown(reason: Error) {
        var parks: [CheckedContinuation<Void, Never>] = []
        var victims: [NaiveHTTP2Stream] = []
        let proceed: Bool = lock.withLock { state in
            guard state.phase != .closed else { return false }
            state.phase = .closed
            parks = state.flowResumptions
            state.flowResumptions.removeAll()
            victims = Array(state.streams.values)
            state.streams.removeAll()
            state.sendWindows.removeAll()
            return true
        }
        guard proceed else { return }

        transport.cancel()
        completeReadyContinuations(reason)
        for continuation in parks { continuation.resume() }
        for stream in victims { stream.handleSessionError(reason) }
        refreshPoolSnapshot()
        onClose?()
    }
}
