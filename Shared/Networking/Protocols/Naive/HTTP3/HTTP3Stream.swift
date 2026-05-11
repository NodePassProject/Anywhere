//
//  HTTP3Stream.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP3Stream")

nonisolated class HTTP3Stream: NaiveTunnel {

    // MARK: - State

    enum StreamState {
        case idle, connectSent, open, closed
    }

    // MARK: - Properties

    let destination: String
    private(set) var quicStreamID: Int64?

    private weak var session: HTTP3Session?
    private let configuration: NaiveConfiguration

    private var state: StreamState = .idle
    private var headersReceived = false

    // Receive buffering. Each queued element carries the QUIC byte count
    // (frame header + payload) so flow control is extended in lockstep with
    // the chunk leaving our buffer — not in one big over-grant when any
    // chunk drains. Preserves the "backpressure when app is slow" invariant.
    private var receiveQueue: [(chunk: Data, quicBytes: Int)] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var endStreamReceived = false
    private var streamError: Error?

    // Partial HTTP/3 frame buffer (frames may span multiple QUIC deliveries).
    // Parsing advances `frameBufferOffset` in place; the buffer is compacted
    // lazily to keep parse-per-frame amortized O(1) instead of O(n) per frame.
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    // CONNECT handshake callback
    private var connectCompletion: ((Error?) -> Void)?

    // Padding
    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    var isConnected: Bool { state == .open }

    // MARK: - Init

    init(session: HTTP3Session, configuration: NaiveConfiguration, destination: String) {
        self.session = session
        self.configuration = configuration
        self.destination = destination
    }

    // MARK: - NaiveTunnel

    func openTunnel(completion: @escaping (Error?) -> Void) {
        guard let session else {
            completion(HTTP3Error.connectionFailed("No session"))
            return
        }

        session.queue.async { [self] in
            session.ensureReady { [weak self] error in
                guard let self, let session = self.session else { return }
                if let error {
                    self.state = .closed
                    completion(error)
                    return
                }

                // Open a bidirectional QUIC stream for this CONNECT tunnel
                guard let sid = session.openBidiStream() else {
                    self.state = .closed
                    session.markStreamBlocked()
                    completion(HTTP3Error.streamIdBlocked)
                    return
                }
                self.quicStreamID = sid
                session.registerStream(self, streamID: sid)

                // Build and send CONNECT HEADERS
                self.connectCompletion = completion
                self.state = .connectSent

                var extraHeaders: [(name: String, value: String)] = []
                extraHeaders.append((name: "user-agent", value: "Chrome/128.0.0.0"))
                if let auth = self.configuration.basicAuth {
                    extraHeaders.append((name: "proxy-authorization", value: "Basic \(auth)"))
                }
                let cachedType = NaivePaddingNegotiator.cachedPaddingType(
                    host: self.configuration.proxyHost,
                    port: self.configuration.proxyPort,
                    sni: self.configuration.effectiveSNI
                )
                extraHeaders.append(contentsOf: NaivePaddingNegotiator.requestHeaders(
                    fastOpen: cachedType != nil
                ))

                // Ensure we don't exceed the peer's advertised MAX_FIELD_SECTION_SIZE.
                var allHeaders = extraHeaders
                allHeaders.insert((name: ":method", value: "CONNECT"), at: 0)
                allHeaders.insert((name: ":authority", value: self.destination), at: 1)
                guard session.isWithinPeerFieldSectionLimit(allHeaders) else {
                    self.handleStreamError(HTTP3Error.connectionFailed("Request headers exceed peer MAX_FIELD_SECTION_SIZE"))
                    return
                }

                let headerBlock = QPACKEncoder.encodeConnectHeaders(
                    authority: self.destination, extraHeaders: extraHeaders
                )
                let headersFrame = HTTP3Framer.headersFrame(headerBlock: headerBlock)

                session.writeStream(sid, data: headersFrame) { [weak self] error in
                    if let error {
                        self?.session?.queue.async {
                            self?.handleStreamError(error)
                        }
                    }
                }
            }
        }
    }

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let session else {
            completion(HTTP3Error.streamClosed)
            return
        }
        let block: () -> Void = { [self] in
            guard state == .open, let sid = quicStreamID else {
                completion(state == .closed ? HTTP3Error.streamClosed : HTTP3Error.notReady)
                return
            }
            let frame = HTTP3Framer.dataFrame(payload: data)
            session.writeStream(sid, data: frame, completion: completion)
        }
        if session.isOnQueue {
            block()
        } else {
            session.queue.async(execute: block)
        }
    }

    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        guard let session else {
            completion(nil, HTTP3Error.streamClosed)
            return
        }
        // The callback chain (deliverData → NaiveProxyConnection → ProxyConnection
        // → startReceiving → receiveRaw → receiveData) runs on the session queue.
        // Dispatching via queue.async defers pendingReceive re-arm by one cycle,
        // causing the next packet to buffer instead of being delivered directly.
        // Execute synchronously when already on queue to avoid this.
        let block: () -> Void = { [self] in
            if let error = streamError {
                completion(nil, error)
                return
            }
            if !receiveQueue.isEmpty {
                // Hand out one chunk at a time and let the caller re-arm.
                // Merging multiple queued chunks into a single Data required
                // allocating + copying O(total) bytes on every slow-reader
                // drain; the upstream pipeline doesn't care about chunk
                // size, so this matches TCP socket semantics for free.
                let (data, quicBytes) = receiveQueue.removeFirst()
                ackQuicBytes(quicBytes)
                completion(data, nil)
                return
            }
            if endStreamReceived {
                closeAndShutdown()
                completion(nil, nil)
                return
            }
            if state == .closed {
                completion(nil, nil)
                return
            }
            pendingReceive = completion
        }

        if session.isOnQueue {
            block()
        } else {
            session.queue.async(execute: block)
        }
    }

    func close() {
        guard let session else { return }
        session.queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            session.removeStream(self)

            // Shut down the QUIC stream so the server can reclaim the stream
            // slot and grant new ones via MAX_STREAMS. A caller-initiated
            // close before completion is signalled as H3_REQUEST_CANCELLED.
            if let sid = quicStreamID {
                let code: HTTP3ErrorCode = headersReceived ? .noError : .requestCancelled
                session.shutdownStream(sid, code: code)
            }

            if let cb = connectCompletion {
                connectCompletion = nil
                cb(HTTP3Error.streamClosed)
            }
            if let pending = pendingReceive {
                pendingReceive = nil
                pending(nil, HTTP3Error.streamClosed)
            }
        }
    }

    // MARK: - Session Callbacks (called on session.queue)

    /// Handles raw QUIC stream data delivered by the session.
    func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            frameBuffer.append(data)
            processFrameBuffer()
        }

        if fin {
            endStreamReceived = true
            if let pending = pendingReceive, receiveQueue.isEmpty {
                pendingReceive = nil
                closeAndShutdown()
                pending(nil, nil) // EOF
            } else if receiveQueue.isEmpty {
                closeAndShutdown()
            }
        }
    }

    func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    // MARK: - HTTP/3 Frame Processing

    private func processFrameBuffer() {
        // Non-DATA frames (HEADERS, SETTINGS, GOAWAY) are consumed internally
        // and never reach the app. Ack their QUIC bytes as a batch at the end
        // of this parse pass — one flow-control extension per delivery rather
        // than one per parsed frame.
        var controlBytes = 0
        while frameBufferOffset < frameBuffer.count {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(
                from: frameBuffer, offset: frameBufferOffset
            ) else {
                break // Incomplete frame, wait for more data
            }
            frameBufferOffset += consumed

            if !headersReceived {
                processResponseHeaders(frame)
                controlBytes += consumed
            } else if frame.type == HTTP3FrameType.data.rawValue {
                deliverData(frame.payload, quicBytes: consumed)
            } else {
                // SETTINGS/GOAWAY/etc. — internally consumed.
                controlBytes += consumed
            }
        }
        if controlBytes > 0 {
            ackQuicBytes(controlBytes)
        }

        // Compact only when fully drained or after a generous threshold — avoids
        // the O(n²) "copy remaining bytes every frame" cost on bulk streams.
        // Reassign instead of mutating in place: `Data.removeFirst` / `removeAll`
        // leave `startIndex` shifted, but HTTP3Framer.decodeVarInt assumes
        // `data[0]` is the first byte.  `Data(...)` copies into fresh storage
        // with startIndex 0.
        if frameBufferOffset >= frameBuffer.count {
            frameBuffer = Data()
            frameBufferOffset = 0
        } else if frameBufferOffset > 64 * 1024 {
            frameBuffer = Data(frameBuffer[(frameBuffer.startIndex + frameBufferOffset)...])
            frameBufferOffset = 0
        }
    }

    private func processResponseHeaders(_ frame: HTTP3Framer.Frame) {
        guard frame.type == HTTP3FrameType.headers.rawValue else {
            handleStreamError(HTTP3Error.connectionFailed("Expected HEADERS, got type \(frame.type)"))
            return
        }

        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
            handleStreamError(HTTP3Error.connectionFailed("Malformed QPACK header block"))
            return
        }
        let statusHeader = headers.first(where: { $0.name == ":status" })

        guard let status = statusHeader?.value, status == "200" else {
            let code = statusHeader?.value ?? "unknown"
            if code == "407" {
                handleStreamError(HTTP3Error.authenticationRequired)
            } else {
                handleStreamError(HTTP3Error.tunnelFailed(statusCode: code))
            }
            return
        }

        let paddingTuples = headers.map { (name: $0.name, value: $0.value) }
        negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers: paddingTuples)

        // Cache negotiated padding type for fast open on subsequent connections
        NaivePaddingNegotiator.cachePaddingType(
            negotiatedPaddingType,
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )

        headersReceived = true
        state = .open

        let cb = connectCompletion
        connectCompletion = nil
        cb?(nil)
    }

    private func deliverData(_ data: Data, quicBytes: Int) {
        guard !data.isEmpty else {
            // Empty DATA frame — still consumed QUIC bytes (frame header).
            if quicBytes > 0 { ackQuicBytes(quicBytes) }
            return
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            ackQuicBytes(quicBytes)
            pending(data, nil)
        } else {
            receiveQueue.append((data, quicBytes))
        }
    }

    /// Extends the QUIC flow control window by the given byte count,
    /// signaling the server that we've consumed the data and can accept more.
    private func ackQuicBytes(_ count: Int) {
        guard count > 0, let sid = quicStreamID else { return }
        session?.extendStreamOffset(sid, count: count)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        streamError = error
        // Map the error to an HTTP/3 error code for RESET_STREAM/STOP_SENDING.
        let code: HTTP3ErrorCode
        if let h3 = error as? HTTP3Error, case .tunnelFailed = h3 {
            code = .connectError
        } else if error is HTTP3Error {
            code = .requestCancelled
        } else {
            code = .internalError
        }
        closeAndShutdown(code: code)

        if let cb = connectCompletion {
            connectCompletion = nil
            cb(error)
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            pending(nil, error)
        }
    }

    /// Closes the stream and sends RESET_STREAM/STOP_SENDING so the server
    /// can reclaim the stream slot and grant new stream IDs via MAX_STREAMS.
    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        guard state != .closed else { return }
        state = .closed
        session?.removeStream(self)
        if let sid = quicStreamID {
            session?.shutdownStream(sid, code: code)
        }
    }
}
