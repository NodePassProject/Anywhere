//
//  HTTP2Connection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "HTTP2")

// MARK: - Error

enum HTTP2Error: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case protocolError(String)
    case tunnelFailed(statusCode: String)
    case authenticationRequired
    case goaway
    case streamReset(UInt32)

    var errorDescription: String? {
        switch self {
        case .notReady: return "HTTP/2 connection not ready"
        case .connectionFailed(let msg): return "HTTP/2 connection failed: \(msg)"
        case .protocolError(let msg): return "HTTP/2 protocol error: \(msg)"
        case .tunnelFailed(let code): return "HTTP/2 CONNECT tunnel failed with status \(code)"
        case .authenticationRequired: return "HTTP/2 proxy authentication required (407)"
        case .goaway: return "HTTP/2 GOAWAY received"
        case .streamReset(let sid): return "HTTP/2 stream \(sid) reset"
        }
    }
}

// MARK: - HTTP2Connection

/// HTTP/2 session manager for a single CONNECT tunnel through a NaiveProxy server.
///
/// Handles the full HTTP/2 lifecycle:
/// 1. Send connection preface and SETTINGS
/// 2. Exchange SETTINGS with the server
/// 3. Open a CONNECT tunnel on stream 1 with padding negotiation
/// 4. Bidirectional DATA relay through the tunnel
///
/// Flow control uses NaiveProxy's window sizes (64 MB stream, 128 MB connection).
class HTTP2Connection {

    // MARK: State

    enum State {
        case idle
        case connecting
        /// Connection preface + SETTINGS sent, waiting for server SETTINGS.
        case prefaceSent
        /// SETTINGS exchanged, ready to send CONNECT.
        case ready
        /// CONNECT request sent, waiting for response.
        case tunnelPending
        /// Tunnel established, data can flow.
        case tunnelOpen
        case closed
    }

    // MARK: Properties

    private let transport: NaiveTLSTransport
    private let configuration: NaiveConfiguration
    /// The target `host:port` for the CONNECT tunnel.
    private let destination: String

    private var state: State = .idle
    /// Serial queue protecting all mutable state.
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.http2")

    private var flowControl = HTTP2FlowControl()
    private var receiveBuffer = Data()

    /// The padding type negotiated with the server during CONNECT.
    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    /// Whether the tunnel is open and ready for data transfer.
    var isConnected: Bool { state == .tunnelOpen }

    // MARK: Initialization

    /// Creates an HTTP/2 connection for a CONNECT tunnel.
    ///
    /// - Parameters:
    ///   - transport: The TLS transport to the proxy server.
    ///   - configuration: NaiveProxy configuration (credentials, etc.).
    ///   - destination: The target `host:port` for the CONNECT tunnel.
    init(transport: NaiveTLSTransport, configuration: NaiveConfiguration, destination: String) {
        self.transport = transport
        self.configuration = configuration
        self.destination = destination
    }

    // MARK: - Open Tunnel

    /// Establishes the HTTP/2 connection and opens a CONNECT tunnel.
    ///
    /// Performs the full setup sequence:
    /// 1. TLS connection to the proxy server
    /// 2. HTTP/2 connection preface and SETTINGS exchange
    /// 3. Connection-level WINDOW_UPDATE (expand to 128 MB)
    /// 4. CONNECT request with padding negotiation headers
    /// 5. Receives and validates the 200 OK response
    ///
    /// - Parameter completion: Called with `nil` on success or an error on failure.
    func openTunnel(completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            guard state == .idle else {
                completion(HTTP2Error.protocolError("Invalid state for openTunnel"))
                return
            }
            state = .connecting

            transport.connect { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    if let error {
                        self.state = .closed
                        completion(error)
                        return
                    }
                    self.sendConnectionPreface(completion: completion)
                }
            }
        }
    }

    // MARK: - Data Transfer

    /// Sends data through the CONNECT tunnel as HTTP/2 DATA frames.
    ///
    /// Data is split into frames of at most 16,384 bytes (the HTTP/2 default
    /// `SETTINGS_MAX_FRAME_SIZE`). Respects both connection and stream send windows.
    ///
    /// - Parameters:
    ///   - data: The data to send through the tunnel.
    ///   - completion: Called with `nil` on success or an error on failure.
    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            guard state == .tunnelOpen else {
                completion(HTTP2Error.notReady)
                return
            }
            sendDataFrames(data: data, offset: 0, completion: completion)
        }
    }

    /// Receives the next chunk of data from the CONNECT tunnel.
    ///
    /// Reads and processes HTTP/2 frames until a DATA frame for stream 1 is found.
    /// Control frames (PING, WINDOW_UPDATE, SETTINGS) are handled transparently.
    ///
    /// - Parameter completion: Called with `(data, nil)` on success, `(nil, nil)` for EOF,
    ///   or `(nil, error)` on failure.
    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        queue.async { [self] in
            guard state == .tunnelOpen else {
                completion(nil, HTTP2Error.notReady)
                return
            }
            readNextDataFrame(completion: completion)
        }
    }

    /// Closes the HTTP/2 connection.
    func close() {
        queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            transport.cancel()
        }
    }

    // MARK: - Connection Preface

    /// The HTTP/2 connection preface (RFC 7540 §3.5).
    private static let connectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".data(using: .ascii)!

    /// Sends the connection preface, initial SETTINGS, and connection-level WINDOW_UPDATE.
    private func sendConnectionPreface(completion: @escaping (Error?) -> Void) {
        var data = Data()

        // Connection preface (24 bytes)
        data.append(Self.connectionPreface)

        // SETTINGS matching Chrome/NaiveProxy defaults
        let settings = HTTP2Framer.settingsFrame([
            (id: 0x1, value: 65536),     // HEADER_TABLE_SIZE
            (id: 0x2, value: 0),         // ENABLE_PUSH (disabled for CONNECT)
            (id: 0x3, value: 100),       // MAX_CONCURRENT_STREAMS
            (id: 0x4, value: UInt32(HTTP2FlowControl.naiveInitialWindowSize)), // INITIAL_WINDOW_SIZE = 64 MB
            (id: 0x5, value: 16384),     // MAX_FRAME_SIZE
            (id: 0x6, value: 262144),    // MAX_HEADER_LIST_SIZE
        ])
        data.append(HTTP2Framer.serialize(settings))

        // WINDOW_UPDATE on stream 0: expand connection receive window to 128 MB
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
                    completion(error)
                    return
                }
                self.state = .prefaceSent
                self.processHandshake(completion: completion)
            }
        }
    }

    // MARK: - Handshake Processing

    /// Processes HTTP/2 frames during the handshake phase (SETTINGS exchange → CONNECT).
    ///
    /// Reads frames from the receive buffer, handles control frames, and advances
    /// through the state machine: `prefaceSent → ready → tunnelPending → tunnelOpen`.
    private func processHandshake(completion: @escaping (Error?) -> Void) {
        while let frame = HTTP2Framer.deserialize(from: &receiveBuffer) {
            switch frame.type {
            case .settings:
                if frame.hasFlag(HTTP2FrameFlags.ack) {
                    continue // Server ACK'd our SETTINGS
                }
                handleServerSettings(frame)
                sendFrame(HTTP2Framer.settingsAckFrame())

                if state == .prefaceSent {
                    state = .ready
                    sendConnectRequest { [weak self] error in
                        guard let self else { return }
                        self.queue.async {
                            if let error {
                                self.state = .closed
                                completion(error)
                                return
                            }
                            // Continue processing — response may already be buffered
                            self.processHandshake(completion: completion)
                        }
                    }
                    return
                }

            case .headers:
                if state == .tunnelPending && frame.streamID == 1 {
                    handleConnectResponse(frame, completion: completion)
                    return
                }

            case .windowUpdate:
                if let inc = HTTP2Framer.parseWindowUpdate(payload: frame.payload) {
                    flowControl.applyWindowUpdate(streamID: frame.streamID, increment: Int(inc))
                }

            case .ping:
                if !frame.hasFlag(HTTP2FrameFlags.ack) {
                    sendFrame(HTTP2Framer.pingAckFrame(opaqueData: frame.payload))
                }

            case .goaway:
                state = .closed
                if let parsed = HTTP2Framer.parseGoaway(payload: frame.payload) {
                    logger.warning("[HTTP2] GOAWAY: lastStreamID=\(parsed.lastStreamID), errorCode=\(parsed.errorCode)")
                }
                completion(HTTP2Error.goaway)
                return

            case .rstStream:
                if frame.streamID == 1 && state == .tunnelPending {
                    state = .closed
                    if let errorCode = HTTP2Framer.parseRstStream(payload: frame.payload) {
                        logger.error("[HTTP2] Stream 1 reset during CONNECT: errorCode=\(errorCode)")
                    }
                    completion(HTTP2Error.streamReset(frame.streamID))
                    return
                }

            default:
                break // Skip unknown frame types (RFC 7540 §4.1)
            }
        }

        // Need more data from transport
        readFromTransport { [weak self] error in
            guard let self else { return }
            if let error {
                self.state = .closed
                completion(error)
                return
            }
            self.processHandshake(completion: completion)
        }
    }

    // MARK: - CONNECT Request

    /// Chrome-like User-Agent for the CONNECT request.
    /// The reference NaiveProxy (Chromium) always includes User-Agent;
    /// Caddy's forwardproxy with probe_resistance may reject requests without it.
    private static let userAgent = "Mozilla/5.0 (iPhone16,2; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Resorts/4.7.5"

    /// Sends the HTTP/2 CONNECT request on stream 1 with padding negotiation headers.
    private func sendConnectRequest(completion: @escaping (Error?) -> Void) {
        var extraHeaders: [(name: String, value: String)] = []

        // Proxy-Authorization (Basic auth)
        if let auth = configuration.basicAuth {
            extraHeaders.append((name: "proxy-authorization", value: "Basic \(auth)"))
        }

        // User-Agent (required by some NaiveProxy servers for probe resistance)
        extraHeaders.append((name: "user-agent", value: Self.userAgent))

        // Padding negotiation headers
        extraHeaders.append(contentsOf: NaivePaddingNegotiator.requestHeaders())

        let headerBlock = HPACKEncoder.encodeConnectRequest(
            authority: destination,
            extraHeaders: extraHeaders
        )
        let headersFrame = HTTP2Framer.headersFrame(
            streamID: 1,
            headerBlock: headerBlock,
            endStream: false
        )

        state = .tunnelPending
        transport.send(data: HTTP2Framer.serialize(headersFrame), completion: completion)
    }

    // MARK: - CONNECT Response

    /// Handles the server's CONNECT response HEADERS frame.
    private func handleConnectResponse(_ frame: HTTP2Frame, completion: @escaping (Error?) -> Void) {
        guard let headers = HPACKEncoder.decodeHeaders(from: frame.payload) else {
            state = .closed
            completion(HTTP2Error.protocolError("Failed to decode CONNECT response headers"))
            return
        }

        guard let statusHeader = headers.first(where: { $0.name == ":status" }) else {
            state = .closed
            completion(HTTP2Error.protocolError("Missing :status in CONNECT response"))
            return
        }

        let status = statusHeader.value

        if status == "200" {
            negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers: headers)
            state = .tunnelOpen
            completion(nil)
        } else if status == "407" {
            state = .closed
            logger.error("[HTTP2] Proxy authentication required (407)")
            completion(HTTP2Error.authenticationRequired)
        } else {
            state = .closed
            logger.error("[HTTP2] CONNECT failed with status \(status, privacy: .public)")
            completion(HTTP2Error.tunnelFailed(statusCode: status))
        }
    }

    // MARK: - Server Settings

    /// Processes a SETTINGS frame from the server, applying relevant parameters.
    private func handleServerSettings(_ frame: HTTP2Frame) {
        let settings = HTTP2Framer.parseSettings(payload: frame.payload)
        for (id, value) in settings {
            switch id {
            case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE
                flowControl.applySettings(initialWindowSize: Int(value))
            default:
                break
            }
        }
    }

    // MARK: - Data Frame Send

    /// Sends data as one or more HTTP/2 DATA frames on stream 1.
    ///
    /// Splits at `SETTINGS_MAX_FRAME_SIZE` (16,384 bytes) and respects flow control.
    /// Recursively sends remaining data if the initial batch didn't cover it all.
    private func sendDataFrames(data: Data, offset: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        let maxPayload = HTTP2Framer.maxDataPayload
        var currentOffset = offset
        var frames = Data()

        while currentOffset < data.count {
            let remaining = data.count - currentOffset
            let chunkSize = min(remaining, min(maxPayload, flowControl.maxSendBytes))

            guard chunkSize > 0 else { break }
            guard flowControl.consumeSendWindow(bytes: chunkSize) else { break }

            let chunk = Data(data[currentOffset..<(currentOffset + chunkSize)])
            let frame = HTTP2Framer.dataFrame(streamID: 1, payload: chunk)
            frames.append(HTTP2Framer.serialize(frame))
            currentOffset += chunkSize
        }

        if frames.isEmpty {
            // Flow control blocked — should be extremely rare with 64 MB windows
            logger.warning("[HTTP2] Send blocked by flow control")
            completion(HTTP2Error.protocolError("Flow control blocked"))
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
                    self.sendDataFrames(data: data, offset: nextOffset, completion: completion)
                } else {
                    completion(nil)
                }
            }
        }
    }

    // MARK: - Data Frame Receive

    /// Reads HTTP/2 frames until a DATA frame for stream 1 is found.
    ///
    /// Control frames (PING, WINDOW_UPDATE, SETTINGS) are handled transparently.
    /// GOAWAY and RST_STREAM terminate the connection.
    private func readNextDataFrame(completion: @escaping (Data?, Error?) -> Void) {
        while let frame = HTTP2Framer.deserialize(from: &receiveBuffer) {
            switch frame.type {
            case .data:
                guard frame.streamID == 1 else { continue }

                // Flow control: track received bytes and send WINDOW_UPDATE when needed
                if frame.payload.count > 0 {
                    let increments = flowControl.consumeRecvWindow(bytes: frame.payload.count)
                    if let connInc = increments.connectionIncrement {
                        sendFrame(HTTP2Framer.windowUpdateFrame(streamID: 0, increment: connInc))
                    }
                    if let streamInc = increments.streamIncrement {
                        sendFrame(HTTP2Framer.windowUpdateFrame(streamID: 1, increment: streamInc))
                    }
                }

                if frame.hasFlag(HTTP2FrameFlags.endStream) {
                    state = .closed
                    if !frame.payload.isEmpty {
                        completion(frame.payload, nil)
                    } else {
                        completion(nil, nil) // EOF
                    }
                    return
                }

                if !frame.payload.isEmpty {
                    completion(frame.payload, nil)
                    return
                }
                // Empty DATA frame (no END_STREAM) — keep reading

            case .ping:
                if !frame.hasFlag(HTTP2FrameFlags.ack) {
                    sendFrame(HTTP2Framer.pingAckFrame(opaqueData: frame.payload))
                }

            case .windowUpdate:
                if let inc = HTTP2Framer.parseWindowUpdate(payload: frame.payload) {
                    flowControl.applyWindowUpdate(streamID: frame.streamID, increment: Int(inc))
                }

            case .settings:
                if !frame.hasFlag(HTTP2FrameFlags.ack) {
                    handleServerSettings(frame)
                    sendFrame(HTTP2Framer.settingsAckFrame())
                }

            case .goaway:
                state = .closed
                if let parsed = HTTP2Framer.parseGoaway(payload: frame.payload) {
                    logger.warning("[HTTP2] GOAWAY: lastStreamID=\(parsed.lastStreamID), errorCode=\(parsed.errorCode)")
                }
                completion(nil, HTTP2Error.goaway)
                return

            case .rstStream:
                if frame.streamID == 1 {
                    state = .closed
                    completion(nil, HTTP2Error.streamReset(frame.streamID))
                    return
                }

            default:
                break // Skip unknown frame types (RFC 7540 §4.1)
            }
        }

        // Need more data from transport
        readFromTransport { [weak self] error in
            guard let self else { return }
            if let error {
                self.state = .closed
                completion(nil, error)
                return
            }
            self.readNextDataFrame(completion: completion)
        }
    }

    // MARK: - Transport I/O

    /// Reads data from the transport and appends to the receive buffer.
    ///
    /// Dispatches the completion back to `self.queue` to ensure all state
    /// access is serialized.
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
                completion(nil)
            }
        }
    }

    /// Sends a single control frame (fire-and-forget).
    ///
    /// Used for SETTINGS ACK, PING ACK, and WINDOW_UPDATE frames where
    /// we don't need to wait for the send to complete.
    private func sendFrame(_ frame: HTTP2Frame) {
        transport.send(data: HTTP2Framer.serialize(frame)) { error in
            if let error {
                logger.warning("[HTTP2] Failed to send frame: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}
