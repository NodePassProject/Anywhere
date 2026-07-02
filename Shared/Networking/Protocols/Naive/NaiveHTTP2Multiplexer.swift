//
//  NaiveHTTP2Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Multiplexer")

nonisolated class NaiveHTTP2Multiplexer: Multiplexer {

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
    /// Invoked once per stream so randomized values (auth, padding) differ per request.
    private let connectHeaders: () -> [(name: String, value: String)]

    private(set) var state: State = .idle

    // Pool-visible snapshot guarded by `_poolLock`: the pool reads off-queue, the multiplexer writes on `queue`.
    private let _poolLock = UnfairLock()
    private var _poolState: State = .idle
    private var _poolStreamCount: Int = 0
    private var _poolMaxConcurrent: UInt32 = 100

    /// Serial queue guarding all mutable multiplexer + stream state; `.userInitiated` to match the data-plane chain.
    let queue = DispatchQueue(label: AWCore.Identifier.http2SessionQueue, qos: .userInitiated)

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

    private var readyCallbacks: [(Error?) -> Void] = []

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
    }

    // MARK: - Capacity

    /// Thread-safe count read off-queue by the idle sweep; don't use `streams.count` (queue-confined).
    var activeStreamCount: Int { _poolLock.withLock { _poolStreamCount } }

    /// Whether the multiplexer can accept another stream (on-queue only).
    var hasCapacity: Bool {
        state == .ready && UInt32(streams.count) < maxConcurrentStreams
    }

    /// Thread-safe: whether this multiplexer appears closed to the pool.
    var isClosed: Bool {
        _poolLock.withLock { _poolState == .closed }
    }

    /// Thread-safe: whether this multiplexer has received GOAWAY.
    var poolIsGoingAway: Bool {
        _poolLock.withLock { _poolState == .goingAway }
    }

    /// Atomically checks capacity and reserves a stream slot; accepts in-progress multiplexers
    /// so burst requests coalesce behind one handshake. Caller must follow up with `openStream` on `queue`.
    func tryReserveStream() -> Bool {
        _poolLock.withLock {
            switch _poolState {
            case .idle, .connecting, .prefaceSent, .ready:
                break
            case .goingAway, .closed:
                return false
            }
            guard UInt32(_poolStreamCount) < _poolMaxConcurrent else { return false }
            _poolStreamCount += 1
            return true
        }
    }

    /// Syncs the pool-visible snapshot; must be called on `queue`.
    private func updatePoolSnapshot() {
        _poolLock.withLock {
            _poolState = state
            _poolStreamCount = streams.count
            _poolMaxConcurrent = maxConcurrentStreams
        }
    }

    // MARK: - Session Setup

    /// Must be called on `queue`.
    func ensureReady(completion: @escaping (Error?) -> Void) {
        switch state {
        case .ready:
            completion(nil)
        case .idle:
            readyCallbacks.append(completion)
            beginSetup()
        case .connecting, .prefaceSent:
            readyCallbacks.append(completion)
        case .goingAway, .closed:
            completion(NaiveHTTP2Error.notReady)
        }
    }

    private func beginSetup() {
        state = .connecting
        updatePoolSnapshot()
        transport.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.state = .closed
                    self.updatePoolSnapshot()
                    self.completeReadyCallbacks(error)
                    return
                }
                self.sendConnectionPreface()
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

        transport.send(data: data) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.state = .closed
                    self.updatePoolSnapshot()
                    self.completeReadyCallbacks(error)
                    return
                }
                self.state = .prefaceSent
                self.updatePoolSnapshot()
                self.startReadLoop()
            }
        }
    }

    // MARK: - Read Loop

    /// Persistent read loop; runs from `prefaceSent` until `closed`.
    private func startReadLoop() {
        handleInbound()

        guard state != .closed else { return }

        readFromTransport { [weak self] error in
            guard let self else { return }
            if let error {
                self.handleSessionError(error)
                return
            }
            self.startReadLoop()
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
            completeReadyCallbacks(nil)
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
            completeReadyCallbacks(NaiveHTTP2Error.goaway)
        }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload) else { return }
        if frame.streamID == 0 {
            connectionSendWindow += Int(increment)
        } else if let stream = streams[frame.streamID] {
            stream.adjustSendWindow(delta: Int(increment))
        }
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

    func sendConnect(stream: NaiveHTTP2Stream, completion: @escaping (Error?) -> Void) {
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

        transport.send(data: headersFrame.serialized, completion: completion)
    }

    /// Sends DATA frames for a stream, respecting connection + stream flow control.
    func sendData(_ data: Data, on stream: NaiveHTTP2Stream, offset: Int = 0,
                  completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

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

            let chunk = Data(data[currentOffset..<(currentOffset + chunkSize)])
            let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk)
            frames.append(frame.serialized)
            currentOffset += chunkSize
        }

        if frames.isEmpty {
            // Flow control window exhausted — wait for WINDOW_UPDATE and retry
            queue.asyncAfter(deadline: .now() + .milliseconds(50)) { [weak self] in
                self?.sendData(data, on: stream, offset: offset, completion: completion)
            }
            return
        }

        let nextOffset = currentOffset
        transport.send(data: frames) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    completion(error)
                    return
                }
                if nextOffset < data.count {
                    self.sendData(data, on: stream, offset: nextOffset, completion: completion)
                } else {
                    completion(nil)
                }
            }
        }
    }

    /// Sends a control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE). Fire-and-forget.
    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        transport.send(data: frame.serialized) { error in
            if let error {
                logger.warning("[NaiveHTTP2Multiplexer] Failed to send control frame: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Transport I/O

    private func readFromTransport(completion: @escaping (Error?) -> Void) {
        transport.receive { [weak self] data, error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    completion(error)
                    return
                }
                guard let data, !data.isEmpty else {
                    completion(NaiveHTTP2Error.connectionFailed("Connection closed"))
                    return
                }
                self.receiveBuffer.append(data)
                if self.receiveBuffer.count > Self.maxReceiveBufferSize {
                    self.receiveBuffer.removeAll()
                    completion(NaiveHTTP2Error.connectionFailed("Receive buffer exceeded \(Self.maxReceiveBufferSize) bytes"))
                    return
                }
                completion(nil)
            }
        }
    }

    // MARK: - Error Handling

    private func handleSessionError(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        transport.cancel()
        completeReadyCallbacks(error)
        for (_, stream) in streams {
            stream.handleSessionError(error)
        }
        streams.removeAll()
        updatePoolSnapshot()
        onClose?()
    }

    private func completeReadyCallbacks(_ error: Error?) {
        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for callback in callbacks {
            callback(error)
        }
    }

    func close(error: Error? = nil) {
        queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            transport.cancel()
            for (_, stream) in streams {
                stream.handleSessionError(NaiveHTTP2Error.connectionFailed("Session closed"))
            }
            streams.removeAll()
            updatePoolSnapshot()
            onClose?()
        }
    }
}
