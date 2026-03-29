//
//  HTTP2Session.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/18/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "HTTP2Session")

/// Multiplexed HTTP/2 session that hosts multiple concurrent CONNECT tunnels.
///
/// Manages the TLS transport, connection preface, SETTINGS exchange,
/// connection-level flow control, and a persistent read loop that
/// demultiplexes incoming frames to individual ``HTTP2Stream`` instances.
///
/// Modelled after Chromium's `SpdySession`: one TCP/TLS connection carries
/// many independent CONNECT streams, each with its own flow-control window
/// and padding state.
class HTTP2Session {

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

    private let transport: NaiveTLSTransport
    private let configuration: NaiveConfiguration

    private(set) var state: State = .idle

    // Pool-visible snapshot protected by `_poolLock`.
    // HTTP2SessionPool reads these off-queue; the session updates them on `queue`.
    private let _poolLock = UnfairLock()
    private var _poolState: State = .idle
    private var _poolStreamCount: Int = 0
    private var _poolMaxConcurrent: UInt32 = 100

    /// Serial queue protecting all mutable state (session + streams).
    let queue = DispatchQueue(label: "com.argsment.Anywhere.http2session")

    // Stream management
    private var streams: [UInt32: HTTP2Stream] = [:]
    private var nextStreamID: UInt32 = 1
    private var maxConcurrentStreams: UInt32 = 100

    /// Connection-scoped HPACK decoder (RFC 7541 §2.2).
    /// The dynamic table is shared across all streams on this session.
    let hpackDecoder = HPACKDecoder()

    // Connection-level flow control
    private var connectionSendWindow: Int = HTTP2FlowControl.defaultInitialWindowSize
    private var connectionRecvConsumed: Int = 0
    private var connectionRecvWindowSize: Int = HTTP2FlowControl.naiveSessionMaxRecvWindow
    /// The INITIAL_WINDOW_SIZE the peer advertised (for new streams).
    private(set) var peerInitialWindowSize: Int = HTTP2FlowControl.defaultInitialWindowSize

    // Read buffer
    private var receiveBuffer = Data()
    private static let maxReceiveBufferSize = 2_097_152

    // Callbacks waiting for session to reach .ready
    private var readyCallbacks: [(Error?) -> Void] = []

    /// Called when the session becomes permanently unusable so the pool can evict it.
    var onClose: (() -> Void)?

    // MARK: - Initialization

    init(host: String, port: UInt16, sni: String, tunnel: ProxyConnection?,
         configuration: NaiveConfiguration) {
        self.host = host
        self.port = port
        self.sni = sni
        self.configuration = configuration
        self.transport = NaiveTLSTransport(
            host: host,
            port: port,
            sni: sni,
            alpn: ["h2"],
            tunnel: tunnel
        )
    }

    // MARK: - Capacity

    /// Number of active streams on this session.
    var activeStreamCount: Int { streams.count }

    /// Whether the session can accept another stream (on-queue only).
    var hasCapacity: Bool {
        state == .ready && UInt32(streams.count) < maxConcurrentStreams
    }

    /// Thread-safe: whether this session appears closed to the pool.
    var poolIsClosed: Bool {
        _poolLock.withLock { _poolState == .closed }
    }

    /// Thread-safe: whether this session has received GOAWAY.
    var poolIsGoingAway: Bool {
        _poolLock.withLock { _poolState == .goingAway }
    }

    /// Thread-safe: atomically checks capacity and reserves a stream slot.
    /// Returns `true` if a slot was reserved; caller must follow up with
    /// `createStream` on `queue`.
    ///
    /// Accepts sessions that are still setting up (`.idle`, `.connecting`,
    /// `.prefaceSent`) so that burst requests coalesce behind a single
    /// TLS/H2 handshake instead of each spawning its own session.
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

    /// Syncs the pool-visible snapshot with current state. Must be called on `queue`.
    private func updatePoolSnapshot() {
        _poolLock.withLock {
            _poolState = state
            _poolStreamCount = streams.count
            _poolMaxConcurrent = maxConcurrentStreams
        }
    }

    // MARK: - Session Setup

    /// Ensures the session is connected and SETTINGS-exchanged.
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
            completion(HTTP2Error.notReady)
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

    /// Creates and registers a new stream for a CONNECT tunnel.
    /// Must be called on `queue`.
    func createStream(destination: String) -> HTTP2Stream {
        let streamID = nextStreamID
        nextStreamID += 2  // Client streams are odd-numbered
        let stream = HTTP2Stream(
            streamID: streamID,
            session: self,
            configuration: configuration,
            destination: destination
        )
        streams[streamID] = stream
        updatePoolSnapshot()
        return stream
    }

    /// Removes a stream from the active map.
    /// Must be called on `queue`.
    func removeStream(_ stream: HTTP2Stream) {
        streams.removeValue(forKey: stream.streamID)
        updatePoolSnapshot()
    }

    // MARK: - Connection Preface

    private static let connectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".data(using: .ascii)!

    /// Chrome-like User-Agent for CONNECT requests.
    static let userAgent = "Mozilla/5.0 (iPhone16,2; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Resorts/4.7.5"

    private func sendConnectionPreface() {
        var data = Data()

        // Connection preface
        data.append(Self.connectionPreface)

        // SETTINGS matching Chrome/NaiveProxy defaults
        let settings = HTTP2Framer.settingsFrame([
            (id: 0x1, value: 65536),     // HEADER_TABLE_SIZE
            (id: 0x2, value: 0),         // ENABLE_PUSH
            (id: 0x3, value: 100),       // MAX_CONCURRENT_STREAMS
            (id: 0x4, value: UInt32(HTTP2FlowControl.naiveInitialWindowSize)),
            (id: 0x5, value: 16384),     // MAX_FRAME_SIZE
            (id: 0x6, value: 262144),    // MAX_HEADER_LIST_SIZE
        ])
        data.append(HTTP2Framer.serialize(settings))

        // Expand connection receive window to 128 MB
        let windowUpdate = HTTP2Framer.windowUpdateFrame(
            streamID: 0,
            increment: HTTP2FlowControl.connectionWindowUpdateIncrement
        )
        data.append(HTTP2Framer.serialize(windowUpdate))

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

    /// Persistent read loop. Processes all frames and dispatches to streams.
    /// Runs from `prefaceSent` until `closed`.
    private func startReadLoop() {
        processAvailableFrames()

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

    /// Parses and routes all complete frames in the receive buffer.
    private func processAvailableFrames() {
        while let frame = HTTP2Framer.deserialize(from: &receiveBuffer) {
            routeFrame(frame)
        }

        if receiveBuffer.isEmpty {
            receiveBuffer = Data()  // Release backing store
        }
    }

    /// Routes a single frame to the appropriate handler.
    private func routeFrame(_ frame: HTTP2Frame) {
        switch frame.type {
        case .settings:
            handleSettings(frame)

        case .ping:
            if !frame.hasFlag(HTTP2FrameFlags.ack) {
                sendControlFrame(HTTP2Framer.pingAckFrame(opaqueData: frame.payload))
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
                let errorCode = HTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                stream.handleReset(errorCode: errorCode)
            }
        }
    }

    // MARK: - Frame Handlers

    private func handleSettings(_ frame: HTTP2Frame) {
        if frame.hasFlag(HTTP2FrameFlags.ack) { return }

        let settings = HTTP2Framer.parseSettings(payload: frame.payload)
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

        sendControlFrame(HTTP2Framer.settingsAckFrame())

        if state == .prefaceSent {
            state = .ready
            completeReadyCallbacks(nil)
        }
        updatePoolSnapshot()
    }

    private func handleGoaway(_ frame: HTTP2Frame) {
        let previousState = state
        state = .goingAway
        updatePoolSnapshot()
        if let parsed = HTTP2Framer.parseGoaway(payload: frame.payload) {
            logger.warning("[HTTP2Session] GOAWAY: lastStreamID=\(parsed.lastStreamID), errorCode=\(parsed.errorCode)")
            // Streams with ID > lastStreamID are rejected by the server
            for (id, stream) in streams where id > parsed.lastStreamID {
                stream.handleSessionError(HTTP2Error.goaway)
            }
        }
        // If we were still setting up, fail any waiting callbacks
        if previousState == .prefaceSent || previousState == .connecting {
            completeReadyCallbacks(HTTP2Error.goaway)
        }
    }

    private func handleWindowUpdate(_ frame: HTTP2Frame) {
        guard let increment = HTTP2Framer.parseWindowUpdate(payload: frame.payload) else { return }
        if frame.streamID == 0 {
            connectionSendWindow += Int(increment)
        } else if let stream = streams[frame.streamID] {
            stream.adjustSendWindow(delta: Int(increment))
        }
    }

    private func handleDataFrame(_ frame: HTTP2Frame, stream: HTTP2Stream) {
        let endStream = frame.hasFlag(HTTP2FrameFlags.endStream)
        stream.handleData(frame.payload, endStream: endStream)
    }

    /// Acknowledges consumed receive data at the connection level.
    /// Called by streams when data is actually delivered to the consumer.
    /// Must be called on `queue`.
    func acknowledgeReceivedData(count: Int) {
        connectionRecvConsumed += count
        if connectionRecvConsumed >= connectionRecvWindowSize / 2 {
            let increment = UInt32(connectionRecvConsumed)
            connectionRecvConsumed = 0
            sendControlFrame(HTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment))
        }
    }

    // MARK: - Send (called by streams)

    /// Sends CONNECT HEADERS for a stream.
    func sendConnect(stream: HTTP2Stream, completion: @escaping (Error?) -> Void) {
        var extraHeaders: [(name: String, value: String)] = []

        if let auth = configuration.basicAuth {
            extraHeaders.append((name: "proxy-authorization", value: "Basic \(auth)"))
        }
        extraHeaders.append((name: "user-agent", value: Self.userAgent))
        extraHeaders.append(contentsOf: NaivePaddingNegotiator.requestHeaders())

        let headerBlock = HPACKEncoder.encodeConnectRequest(
            authority: stream.destination,
            extraHeaders: extraHeaders
        )
        let headersFrame = HTTP2Framer.headersFrame(
            streamID: stream.streamID,
            headerBlock: headerBlock,
            endStream: false
        )

        transport.send(data: HTTP2Framer.serialize(headersFrame), completion: completion)
    }

    /// Sends DATA frames for a stream, respecting connection + stream flow control.
    func sendData(_ data: Data, on stream: HTTP2Stream, offset: Int = 0,
                  completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        let maxPayload = HTTP2Framer.maxDataPayload
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
            let frame = HTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk)
            frames.append(HTTP2Framer.serialize(frame))
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
    func sendControlFrame(_ frame: HTTP2Frame) {
        transport.send(data: HTTP2Framer.serialize(frame)) { error in
            if let error {
                logger.warning("[HTTP2Session] Failed to send control frame: \(error.localizedDescription, privacy: .public)")
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
                    completion(HTTP2Error.connectionFailed("Connection closed"))
                    return
                }
                self.receiveBuffer.append(data)
                if self.receiveBuffer.count > Self.maxReceiveBufferSize {
                    self.receiveBuffer.removeAll()
                    completion(HTTP2Error.connectionFailed("Receive buffer exceeded \(Self.maxReceiveBufferSize) bytes"))
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
        for cb in callbacks {
            cb(error)
        }
    }

    /// Closes the session and all streams.
    func close() {
        queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            transport.cancel()
            for (_, stream) in streams {
                stream.handleSessionError(HTTP2Error.connectionFailed("Session closed"))
            }
            streams.removeAll()
            updatePoolSnapshot()
            onClose?()
        }
    }
}
