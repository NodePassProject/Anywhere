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

    // MARK: - State

    enum State: Equatable {
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
    /// Ordered async send funnel over the TLS transport — frames reach the wire in
    /// submission order (the callback `transport.send` this replaced serialized likewise).
    private var sendPump: AsyncSendPump!
    /// Invoked once per stream so randomized values (auth, padding) differ per request.
    private let connectHeaders: () -> [(name: String, value: String)]

    private(set) var state: State = .idle

    // Pool-visible snapshot behind its own mutex: the pool reads off-queue, the multiplexer writes on `queue`.
    private struct PoolSnapshot {
        var state: State = .idle
        var streamCount: Int = 0
        var maxConcurrent: UInt32 = 100
    }
    private let _poolSnapshot = Mutex(PoolSnapshot())

    /// Serial queue guarding all mutable multiplexer + stream state; `.userInitiated` to match the data-plane chain.
    let queue = DispatchQueue(label: AWCore.Identifier.http2SessionQueue, qos: .userInitiated)

    /// Runs `body` on ``queue`` and awaits its result — this multiplexer's own bridge hop, so its
    /// streams/pool stay free of raw `queue.async`+continuation. This ONE helper is where the
    /// continuation-wrapping-`queue.async` lives.
    func run<T>(_ body: @escaping () -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: body()) }
        }
    }
    func run<T>(_ body: @escaping () -> Result<T, Error>) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: body()) }
        }
    }

    private var streams: [UInt32: NaiveHTTP2Stream] = [:]
    private var nextStreamID: UInt32 = 1
    private var maxConcurrentStreams: UInt32 = 100

    /// Connection-scoped HPACK decoder; the dynamic table is shared across all streams (RFC 7541 §2.2).
    let hpackDecoder = HPACKDecoder()

    private var connectionSendWindow: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize
    private var connectionRecvConsumed: Int = 0
    private var connectionRecvWindowSize: Int = NaiveHTTP2FlowControl.naiveSessionMaxRecvWindow
    /// The INITIAL_WINDOW_SIZE the peer advertised (for new streams).
    private(set) var peerInitialWindowSize: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize

    private var receiveBuffer = Data()
    private static let maxReceiveBufferSize = 2_097_152

    /// Readiness awaiters coalesced behind one handshake; resolves at `.ready` or on fail/close.
    /// The waiter continuations live in the gate (async infra), not this queue-confined layer.
    private let readyGate = AsyncReadinessGate()

    /// Send-side parks waiting on a WINDOW_UPDATE that re-opens flow control. Queue-confined;
    /// replaces the old 50 ms flow-control retry poll (mirrors GRPCConnection.parkForFlowWindow).
    private var flowResumptions: [CheckedContinuation<Void, Never>] = []

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
        // Weak self so the pump task doesn't retain the multiplexer; it's stopped by close().
        sendPump = AsyncSendPump(
            send: { [weak self] data in
                guard let self else { throw CancellationError() }
                try await self.transport.send(data)
            },
            finish: {}
        )
    }

    // MARK: - Capacity

    /// Thread-safe count read off-queue by the idle sweep; don't use `streams.count` (queue-confined).
    var activeStreamCount: Int { _poolSnapshot.withLock { $0.streamCount } }

    /// Whether the multiplexer can accept another stream (on-queue only).
    var hasCapacity: Bool {
        state == .ready && UInt32(streams.count) < maxConcurrentStreams
    }

    /// Thread-safe: whether this multiplexer appears closed to the pool.
    var isClosed: Bool {
        _poolSnapshot.withLock { $0.state == .closed }
    }

    /// Thread-safe: whether this multiplexer has received GOAWAY.
    var poolIsGoingAway: Bool {
        _poolSnapshot.withLock { $0.state == .goingAway }
    }

    /// Atomically checks capacity and reserves a stream slot; accepts in-progress multiplexers
    /// so burst requests coalesce behind one handshake. Caller must follow up with `openStream` on `queue`.
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

    /// Syncs the pool-visible snapshot; must be called on `queue`.
    private func updatePoolSnapshot() {
        _poolSnapshot.withLock { snapshot in
            snapshot.state = state
            snapshot.streamCount = streams.count
            snapshot.maxConcurrent = maxConcurrentStreams
        }
    }

    // MARK: - Session Setup

    /// Coalesces awaiters behind one handshake; resolves at `.ready` or on fail/close. Kicks the
    /// handshake on `queue`, then parks on the gate — callable from any async context.
    func ensureReady() async throws {
        let alreadyReady: Bool = try await run { [self] () -> Result<Bool, Error> in
            switch state {
            case .ready:
                return .success(true)
            case .idle:
                beginSetup()
                return .success(false)
            case .connecting, .prefaceSent:
                return .success(false)
            case .goingAway, .closed:
                return .failure(NaiveHTTP2Error.notReady)
            }
        }
        if !alreadyReady { try await readyGate.wait() }
    }

    private func beginSetup() {
        state = .connecting
        updatePoolSnapshot()
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.transport.connect()
                self.queue.async { self.sendConnectionPreface() }
            } catch {
                self.queue.async {
                    self.state = .closed
                    self.updatePoolSnapshot()
                    self.completeReadyContinuations(error)
                }
            }
        }
    }

    // MARK: - Stream Lifecycle

    /// Must be called on `queue`.
    func openStream(destination: String) -> NaiveHTTP2Stream {
        let streamID = nextStreamID
        nextStreamID += 2  // Client streams are odd-numbered
        let stream = NaiveHTTP2Stream(
            streamID: streamID,
            multiplexer: self,
            destination: destination
        )
        streams[streamID] = stream
        updatePoolSnapshot()
        return stream
    }

    /// Must be called on `queue`.
    func removeStream(_ stream: NaiveHTTP2Stream) {
        streams.removeValue(forKey: stream.streamID)
        updatePoolSnapshot()
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

        sendPump.enqueueSend(data) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.state = .closed
                    self.transport.cancel()
                    self.sendPump.finish()
                    self.updatePoolSnapshot()
                    self.completeReadyContinuations(error)
                    return
                }
                self.state = .prefaceSent
                self.updatePoolSnapshot()
                self.startReadLoop()
            }
        }
    }

    // MARK: - Read Loop

    /// Persistent read loop; runs from `prefaceSent` until `closed`. Each iteration processes
    /// buffered frames on `queue`, then reads the next chunk via a `Task` (one per read, not
    /// stack recursion), hopping back to `queue` to append and re-enter.
    private func startReadLoop() {
        handleInbound()

        guard state != .closed else { return }

        Task { [weak self] in
            guard let self else { return }
            do {
                let data = try await self.transport.receive()
                self.queue.async {
                    guard self.state != .closed else { return }
                    guard let data, !data.isEmpty else {
                        self.handleSessionError(NaiveHTTP2Error.connectionFailed("Connection closed"))
                        return
                    }
                    self.receiveBuffer.append(data)
                    if self.receiveBuffer.count > Self.maxReceiveBufferSize {
                        self.receiveBuffer.removeAll()
                        self.handleSessionError(NaiveHTTP2Error.connectionFailed("Receive buffer exceeded \(Self.maxReceiveBufferSize) bytes"))
                        return
                    }
                    self.startReadLoop()
                }
            } catch {
                self.queue.async {
                    guard self.state != .closed else { return }
                    self.handleSessionError(error)
                }
            }
        }
    }

    private func handleInbound() {
        while let frame = NaiveHTTP2Framer.deserialize(from: &receiveBuffer) {
            routeFrame(frame)
        }

        if receiveBuffer.isEmpty {
            receiveBuffer = Data()  // Release backing store
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
            if let stream = streams[frame.streamID] {
                stream.handleHeaders(frame)
            }

        case .data:
            if let stream = streams[frame.streamID] {
                handleDataFrame(frame, stream: stream)
            }

        case .rstStream:
            if let stream = streams[frame.streamID] {
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

        let settings = NaiveHTTP2Framer.parseSettings(payload: frame.payload)
        for (id, value) in settings {
            switch id {
            case 0x3: // MAX_CONCURRENT_STREAMS
                maxConcurrentStreams = value
            case 0x4: // INITIAL_WINDOW_SIZE
                let delta = Int(value) - peerInitialWindowSize
                peerInitialWindowSize = Int(value)
                for (_, stream) in streams {
                    stream.adjustSendWindow(delta: delta)
                }
            default:
                break
            }
        }

        sendControlFrame(NaiveHTTP2Framer.settingsAckFrame())

        if state == .prefaceSent {
            state = .ready
            completeReadyContinuations(nil)
        }
        updatePoolSnapshot()
    }

    private func handleGoaway(_ frame: NaiveHTTP2Frame) {
        let previousState = state
        state = .goingAway
        updatePoolSnapshot()
        if let parsed = NaiveHTTP2Framer.parseGoaway(payload: frame.payload) {
            logger.warning("[NaiveHTTP2Multiplexer] GOAWAY: lastStreamID=\(parsed.lastStreamID), errorCode=\(parsed.errorCode)")
            for (id, stream) in streams where id > parsed.lastStreamID {
                stream.handleSessionError(NaiveHTTP2Error.goaway)
            }
        }
        if previousState == .prefaceSent || previousState == .connecting {
            completeReadyContinuations(NaiveHTTP2Error.goaway)
        }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload) else { return }
        if frame.streamID == 0 {
            connectionSendWindow += Int(increment)
        } else if let stream = streams[frame.streamID] {
            stream.adjustSendWindow(delta: Int(increment))
        }
        // A re-opened window (connection- or stream-level) wakes parked sends; each re-checks
        // its own min(connection, stream) window before building frames.
        resumeFlowParks()
    }

    /// Wakes every parked send so it re-evaluates flow control. Queue-confined.
    private func resumeFlowParks() {
        guard !flowResumptions.isEmpty else { return }
        let resumptions = flowResumptions
        flowResumptions.removeAll()
        for continuation in resumptions { continuation.resume() }
    }

    private func handleDataFrame(_ frame: NaiveHTTP2Frame, stream: NaiveHTTP2Stream) {
        let endStream = frame.hasFlag(NaiveHTTP2FrameFlags.endStream)
        stream.handleData(frame.payload, endStream: endStream)
    }

    /// Acknowledges only bytes actually delivered to the consumer; must be called on `queue`.
    func acknowledgeReceivedData(count: Int) {
        connectionRecvConsumed += count
        if connectionRecvConsumed >= connectionRecvWindowSize / 2 {
            let increment = UInt32(connectionRecvConsumed)
            connectionRecvConsumed = 0
            sendControlFrame(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment))
        }
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

    /// One outcome of a flow-control-bounded frame-build pass, decided on `queue`.
    private enum SendStep {
        case closed
        case park
        case built(frames: Data, nextOffset: Int)
    }

    /// Sends DATA frames for a stream, respecting connection + stream flow control. When the
    /// window is exhausted it parks on a continuation resumed by the next WINDOW_UPDATE, instead
    /// of the old 50 ms poll (mirrors GRPCConnection.sendH2Data / XHTTPH2Multiplexer.sendData).
    func sendData(_ data: Data, on stream: NaiveHTTP2Stream) async throws {
        var offset = 0
        while offset < data.count {
            let step: SendStep = await buildDataStep(data, on: stream, offset: offset)
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

    /// Builds as many DATA frames as the current flow window allows, debiting the windows. Runs on
    /// `queue`; returns `.park` when the window is exhausted so the caller can suspend off-queue.
    private func buildDataStep(_ data: Data, on stream: NaiveHTTP2Stream, offset: Int) async -> SendStep {
        await run { [self] in
            guard state != .closed else { return .closed }

            let maxPayload = NaiveHTTP2Framer.maxDataPayload
            var currentOffset = offset
            var frames = Data()

            while currentOffset < data.count {
                let remaining = data.count - currentOffset
                let maxByFlow = min(connectionSendWindow, stream.sendWindow)
                let chunkSize = min(remaining, min(maxPayload, maxByFlow))

                guard chunkSize > 0 else { break }

                connectionSendWindow -= chunkSize
                stream.consumeSendWindow(chunkSize)

                let chunk = Data(data[data.startIndex + currentOffset ..< data.startIndex + currentOffset + chunkSize])
                let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk)
                frames.append(frame.serialized)
                currentOffset += chunkSize
            }

            if frames.isEmpty {
                return .park
            } else {
                return .built(frames: frames, nextOffset: currentOffset)
            }
        }
    }

    /// Suspends until a WINDOW_UPDATE re-opens the send window (or the session closes). Re-checks
    /// under `queue` before parking so a window re-open racing the caller isn't missed.
    private func parkForFlow(stream: NaiveHTTP2Stream) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async { [self] in
                if state == .closed { continuation.resume(); return }
                if min(connectionSendWindow, stream.sendWindow) > 0 { continuation.resume(); return }
                flowResumptions.append(continuation)
            }
        }
    }

    /// Enqueues one ordered send on the pump and awaits its completion (bridges the pump's
    /// single-shot completion into async; the pump preserves submission order).
    private func enqueueOrdered(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            sendPump.enqueueSend(data) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    /// Sends a control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE). Fire-and-forget.
    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        sendPump.enqueueSend(frame.serialized) { error in
            if let error {
                logger.warning("[NaiveHTTP2Multiplexer] Failed to send control frame: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Error Handling

    private func handleSessionError(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        transport.cancel()
        sendPump.finish()
        completeReadyContinuations(error)
        resumeFlowParks()
        for (_, stream) in streams {
            stream.handleSessionError(error)
        }
        streams.removeAll()
        updatePoolSnapshot()
        onClose?()
    }

    private func completeReadyContinuations(_ error: Error?) {
        if let error { readyGate.signalFailure(error) } else { readyGate.signalSuccess() }
    }

    func close(error: Error? = nil) {
        queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            transport.cancel()
            sendPump.finish()
            completeReadyContinuations(NaiveHTTP2Error.connectionFailed("Session closed"))
            resumeFlowParks()
            for (_, stream) in streams {
                stream.handleSessionError(NaiveHTTP2Error.connectionFailed("Session closed"))
            }
            streams.removeAll()
            updatePoolSnapshot()
            onClose?()
        }
    }
}
