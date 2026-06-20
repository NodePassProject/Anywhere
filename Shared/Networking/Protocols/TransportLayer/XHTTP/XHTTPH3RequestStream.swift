//
//  XHTTPH3RequestStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation

/// The QUIC stream window is extended only as the app drains received DATA, so a
/// slow reader backpressures the server. Every public method hops to the multiplexer
/// queue, so all mutable state is touched on one serial queue.
nonisolated final class XHTTPH3RequestStream: HTTP3StreamHandler {

    // MARK: - State

    enum State { case idle, requestSent, open, closed }

    private weak var multiplexer: HTTP3Multiplexer?
    private(set) var quicStreamID: Int64?
    private var state: State = .idle

    // MARK: - Response

    private var headersReceived = false
    private(set) var responseStatus: Int?

    /// Fired once with the response status when HEADERS arrive, or with an error
    /// if the stream fails first; fire-and-forget callers leave it nil.
    private var onResponse: ((Result<Int, Error>) -> Void)?

    // MARK: - Receive buffering

    // Each element carries its QUIC byte count so the flow-control window is
    // extended as chunks are consumed, not up-front.
    private var receiveQueue: [(chunk: Data, quicBytes: Int)] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var endStreamReceived = false
    private var streamError: Error?

    // Frames may span QUIC deliveries; offset-based parsing with lazy compaction
    // keeps cost amortized O(1).
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer) {
        self.multiplexer = multiplexer
    }

    // MARK: - Request

    /// Opens a bidirectional QUIC stream and writes the request HEADERS frame;
    /// `completion` fires once the HEADERS are written (or the stream fails),
    /// `onResponse` when the response `:status` arrives.
    func sendRequest(headerBlock: Data,
                     endStream: Bool,
                     onResponse: ((Result<Int, Error>) -> Void)? = nil,
                     completion: @escaping (Error?) -> Void) {
        guard let multiplexer else { completion(HTTP3Error.streamClosed); return }
        multiplexer.queue.async { [self] in
            multiplexer.ensureReady { [weak self] error in
                guard let self, let multiplexer = self.multiplexer else {
                    completion(HTTP3Error.streamClosed)
                    return
                }
                if let error {
                    self.state = .closed
                    completion(error)
                    return
                }

                guard let streamID = multiplexer.openBidiStream() else {
                    self.state = .closed
                    multiplexer.markStreamBlocked()
                    completion(HTTP3Error.streamIdBlocked)
                    return
                }
                self.quicStreamID = streamID
                // Register before the write so a fast response can't race ahead of the callback.
                self.onResponse = onResponse
                multiplexer.registerStream(self, streamID: streamID)
                self.state = .requestSent

                let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
                multiplexer.writeStream(streamID, data: frame, fin: endStream) { [weak self] error in
                    if let error {
                        self?.multiplexer?.queue.async { self?.handleStreamError(error) }
                    }
                    completion(error)
                }
            }
        }
    }

    func sendBody(_ data: Data, fin: Bool, completion: @escaping (Error?) -> Void) {
        guard let multiplexer else { completion(HTTP3Error.streamClosed); return }
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
            multiplexer.writeStream(sid, data: frame, fin: fin, completion: completion)
        }
        if multiplexer.isOnQueue { block() } else { multiplexer.queue.async(execute: block) }
    }

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard let multiplexer else { completion(nil, HTTP3Error.streamClosed); return }
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
        if multiplexer.isOnQueue { block() } else { multiplexer.queue.async(execute: block) }
    }

    /// Reads and discards the entire response so the stream closes cleanly on EOF —
    /// avoids RESET_STREAM after FIN, which some servers treat as aborting the POST.
    func drainResponse() {
        receive { [weak self] data, error in
            guard let self else { return }
            guard data != nil, error == nil else { return }
            self.drainResponse()
        }
    }

    func close() {
        guard let multiplexer else { return }
        multiplexer.queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            multiplexer.removeStream(self)
            // A caller-initiated close before completion is H3_REQUEST_CANCELLED;
            // after a clean response it's H3_NO_ERROR.
            if let sid = quicStreamID {
                let code: HTTP3ErrorCode = headersReceived ? .noError : .requestCancelled
                multiplexer.shutdownStream(sid, code: code)
            }
            if let callback = onResponse {
                onResponse = nil
                callback(.failure(HTTP3Error.streamClosed))
            }
            if let pending = pendingReceive {
                pendingReceive = nil
                pending(nil, HTTP3Error.streamClosed)
            }
        }
    }

    // MARK: - HTTP3StreamHandler (called on multiplexer queue)

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
                pending(nil, nil)
            } else if receiveQueue.isEmpty {
                closeAndShutdown()
            }
        }
    }

    func handleSessionError(_ error: Error) {
        // A benign QUIC connection close (NO_ERROR / H3_NO_ERROR) is a graceful end of the
        // response — surface EOF rather than a reset.
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            endStreamReceived = true
            if let pending = pendingReceive, receiveQueue.isEmpty {
                pendingReceive = nil
                pending(nil, nil)
            }
            return
        }
        handleStreamError(error)
    }

    // MARK: - Frame processing

    private func processFrameBuffer() {
        // Only DATA frames reach the app; control frames are acked in batch.
        var controlBytes = 0
        while frameBufferOffset < frameBuffer.count {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(
                from: frameBuffer, offset: frameBufferOffset
            ) else {
                break
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

        if let callback = onResponse {
            onResponse = nil
            if let status {
                callback(.success(status))
            } else {
                callback(.failure(HTTP3Error.connectionFailed("Response missing :status")))
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
        multiplexer?.extendStreamOffset(sid, count: count)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        streamError = error
        closeAndShutdown(code: .internalError)
        if let callback = onResponse {
            onResponse = nil
            callback(.failure(error))
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            pending(nil, error)
        }
    }

    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        guard state != .closed else { return }
        state = .closed
        multiplexer?.removeStream(self)
        if let sid = quicStreamID {
            multiplexer?.shutdownStream(sid, code: code)
        }
    }
}
