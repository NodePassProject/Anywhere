//
//  HTTP3RequestStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation

/// A general-purpose HTTP/3 request/response stream multiplexed over an
/// ``HTTP3Session``.
///
/// Unlike ``HTTP3Stream`` (specialised for Naive's CONNECT tunnels), this
/// issues an arbitrary request — GET or POST with a caller-supplied QPACK
/// header block — and exposes the response status plus a streamed response
/// body. XHTTP-over-HTTP/3 builds its download (GET) and upload (POST) streams
/// on top of it, mapping each "HTTP request" of a split-HTTP mode onto one
/// bidirectional QUIC stream.
///
/// Received DATA is queued one chunk at a time and the QUIC stream window is
/// extended only as the app drains it, so a slow reader exerts backpressure on
/// the server rather than letting it flood memory.
///
/// Threading: every public method hops to the session queue (shared with the
/// `QUICConnection`), so all mutable state is touched on a single serial queue.
nonisolated final class HTTP3RequestStream: HTTP3StreamHandler {

    // MARK: - State

    enum State { case idle, requestSent, open, closed }

    private weak var session: HTTP3Session?
    private(set) var quicStreamID: Int64?
    private var state: State = .idle

    // MARK: - Response

    private var headersReceived = false
    private(set) var responseStatus: Int?

    /// Fired once when the response HEADERS frame is parsed (status known), or
    /// with an error if the stream fails first. Callers that gate on the
    /// response (e.g. the XHTTP download GET) set this; fire-and-forget upload
    /// streams leave it nil.
    private var onResponse: ((Result<Int, Error>) -> Void)?

    // MARK: - Receive buffering

    // Each queued element carries its QUIC byte count (frame header + payload)
    // so the flow-control window is extended as the chunk leaves the buffer,
    // not in one up-front grant — a slow consumer then throttles the sender
    // instead of letting received data pile up unbounded.
    private var receiveQueue: [(chunk: Data, quicBytes: Int)] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var endStreamReceived = false
    private var streamError: Error?

    // Partial HTTP/3 frame buffer (frames may span multiple QUIC deliveries).
    // Parsing advances `frameBufferOffset` in place; the buffer is compacted
    // lazily to keep parse-per-frame amortized O(1).
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    // MARK: - Init

    init(session: HTTP3Session) {
        self.session = session
    }

    // MARK: - Request

    /// Opens a bidirectional QUIC stream and writes the request HEADERS frame.
    ///
    /// - Parameters:
    ///   - headerBlock: QPACK-encoded request header block (see ``QPACKEncoder``).
    ///   - endStream: send FIN with the HEADERS frame (true for a body-less GET).
    ///   - onResponse: optional callback fired when the response HEADERS arrive,
    ///     carrying the parsed `:status`.
    ///   - completion: fired once the request HEADERS frame is on the wire (or
    ///     with an error if the stream could not be opened/written).
    func sendRequest(headerBlock: Data,
                     endStream: Bool,
                     onResponse: ((Result<Int, Error>) -> Void)? = nil,
                     completion: @escaping (Error?) -> Void) {
        guard let session else { completion(HTTP3Error.streamClosed); return }
        session.queue.async { [self] in
            session.ensureReady { [weak self] error in
                guard let self, let session = self.session else {
                    completion(HTTP3Error.streamClosed)
                    return
                }
                if let error {
                    self.state = .closed
                    completion(error)
                    return
                }

                guard let sid = session.openBidiStream() else {
                    self.state = .closed
                    session.markStreamBlocked()
                    completion(HTTP3Error.streamIdBlocked)
                    return
                }
                self.quicStreamID = sid
                // Set before the write hops queues so a fast response can't race
                // ahead of the callback (response handling is serialised on this
                // same queue, so registering + storing the callback first is safe).
                self.onResponse = onResponse
                session.registerStream(self, streamID: sid)
                self.state = .requestSent

                let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
                session.writeStream(sid, data: frame, fin: endStream) { [weak self] error in
                    if let error {
                        self?.session?.queue.async { self?.handleStreamError(error) }
                    }
                    completion(error)
                }
            }
        }
    }

    /// Sends a chunk of request body as an HTTP/3 DATA frame, optionally closing
    /// the request stream (FIN) afterwards.
    func sendBody(_ data: Data, fin: Bool, completion: @escaping (Error?) -> Void) {
        guard let session else { completion(HTTP3Error.streamClosed); return }
        let block: () -> Void = { [self] in
            guard state != .closed, let sid = quicStreamID else {
                completion(HTTP3Error.streamClosed)
                return
            }
            if data.isEmpty && !fin {
                completion(nil)
                return
            }
            // An empty payload with fin==true is a bare half-close (FIN, no DATA frame).
            let frame = data.isEmpty ? Data() : HTTP3Framer.dataFrame(payload: data)
            session.writeStream(sid, data: frame, fin: fin, completion: completion)
        }
        if session.isOnQueue { block() } else { session.queue.async(execute: block) }
    }

    /// Returns the next chunk of response body, `nil` on EOF, or an error.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard let session else { completion(nil, HTTP3Error.streamClosed); return }
        let block: () -> Void = { [self] in
            if let error = streamError {
                completion(nil, error)
                return
            }
            if !receiveQueue.isEmpty {
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
        if session.isOnQueue { block() } else { session.queue.async(execute: block) }
    }

    /// Reads and discards the entire response, then lets the stream close
    /// cleanly on EOF. Used for fire-and-forget upload requests (packet-up)
    /// whose response is irrelevant — avoids RESET_STREAM after we've already
    /// sent FIN, which some servers treat as the POST being aborted.
    func drainResponse() {
        receive { [weak self] data, error in
            guard let self else { return }
            // EOF (nil data) or error → the stream has closed itself; stop.
            guard data != nil, error == nil else { return }
            self.drainResponse()
        }
    }

    func close() {
        guard let session else { return }
        session.queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            session.removeStream(self)
            // A caller-initiated close before completion is H3_REQUEST_CANCELLED;
            // after a clean response it's H3_NO_ERROR.
            if let sid = quicStreamID {
                let code: HTTP3ErrorCode = headersReceived ? .noError : .requestCancelled
                session.shutdownStream(sid, code: code)
            }
            if let cb = onResponse {
                onResponse = nil
                cb(.failure(HTTP3Error.streamClosed))
            }
            if let pending = pendingReceive {
                pendingReceive = nil
                pending(nil, HTTP3Error.streamClosed)
            }
        }
    }

    // MARK: - HTTP3StreamHandler (called on session queue)

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

    // MARK: - Frame processing

    private func processFrameBuffer() {
        // HEADERS/SETTINGS/trailers are consumed internally; only DATA reaches
        // the app. Ack control-frame QUIC bytes as a batch per parse pass.
        var controlBytes = 0
        while frameBufferOffset < frameBuffer.count {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(
                from: frameBuffer, offset: frameBufferOffset
            ) else {
                break // Incomplete frame, wait for more data.
            }
            frameBufferOffset += consumed

            if !headersReceived {
                processResponseHeaders(frame)
                controlBytes += consumed
            } else if frame.type == HTTP3FrameType.data.rawValue {
                deliverData(frame.payload, quicBytes: consumed)
            } else {
                // Trailers / unknown frames after the response headers.
                controlBytes += consumed
            }
        }
        if controlBytes > 0 {
            ackQuicBytes(controlBytes)
        }

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

        let statusValue = headers.first(where: { $0.name == ":status" })?.value
        let status = statusValue.flatMap { Int($0) }
        responseStatus = status
        headersReceived = true
        state = .open

        if let cb = onResponse {
            onResponse = nil
            if let status {
                cb(.success(status))
            } else {
                cb(.failure(HTTP3Error.connectionFailed("Response missing :status")))
            }
        }
    }

    private func deliverData(_ data: Data, quicBytes: Int) {
        guard !data.isEmpty else {
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

    /// Extends the QUIC stream flow-control window once the app has consumed data.
    private func ackQuicBytes(_ count: Int) {
        guard count > 0, let sid = quicStreamID else { return }
        session?.extendStreamOffset(sid, count: count)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        streamError = error
        closeAndShutdown(code: .internalError)
        if let cb = onResponse {
            onResponse = nil
            cb(.failure(error))
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            pending(nil, error)
        }
    }

    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        guard state != .closed else { return }
        state = .closed
        session?.removeStream(self)
        if let sid = quicStreamID {
            session?.shutdownStream(sid, code: code)
        }
    }
}
