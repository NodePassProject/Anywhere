//
//  XHTTPH3RequestStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation
import Synchronization

nonisolated final class XHTTPH3RequestStream: HTTP3StreamHandler {

    // MARK: - State

    enum State { case idle, requestSent, open, closed }

    private weak var multiplexer: HTTP3Multiplexer?
    private(set) var quicStreamID: Int64?
    private var state: State = .idle

    // MARK: - Response

    private var headersReceived = false
    private(set) var responseStatus: Int?

    /// One-shot response-status signal; the awaiter is `responseTask.value`. Yields the HTTP
    /// status then finishes on success, or finishes-throwing on failure.
    private let responseSignal: AsyncThrowingStream<Int, Error>.Continuation
    private let responseTask: Task<Int, Error>

    // MARK: - Receive buffering

    /// Inbound DATA payloads / EOF / error from the multiplexer's demux loop. QUIC flow control
    /// counts every stream byte (HTTP/3 frame header + payload), so the per-chunk `quicBytes`
    /// accounting is split: `deliverData` credits the frame-header octets on the multiplexer queue
    /// as chunks arrive, and ``receive()`` credits the payload octets only once the app takes them —
    /// total credit stays exact, backpressure preserved. Producer side (`inbox`) is `Sendable` and
    /// driven on the multiplexer queue; the single consumer pulls `inboxIterator` from ``receive()``.
    /// The `Mutex` guards the iterator *value* (this stream is a queue-confined class, not an actor).
    private let inbox: AsyncThrowingStream<Data, Error>.Continuation
    private let inboxIterator: Mutex<AsyncThrowingStream<Data, Error>.AsyncIterator>

    // Frames may span QUIC deliveries; offset-based parsing with lazy compaction
    // keeps cost amortized O(1).
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer) {
        self.multiplexer = multiplexer
        let (responseStream, responseSignal) = AsyncThrowingStream.makeStream(of: Int.self)
        self.responseSignal = responseSignal
        self.responseTask = Task {
            for try await status in responseStream { return status }
            throw HTTP3Error.streamClosed
        }
        let (inboxStream, inbox) = AsyncThrowingStream.makeStream(of: Data.self)
        self.inbox = inbox
        self.inboxIterator = Mutex(inboxStream.makeAsyncIterator())
    }

    /// Single-consumer pull over `inbox`: takes the stored iterator, awaits one element, stores it
    /// back. Serial by ``receive()``'s single-consumer contract.
    private func nextInboxChunk() async throws -> Data? {
        var iterator = inboxIterator.withLock { $0 }
        let next = try await iterator.next()
        inboxIterator.withLock { $0 = iterator }
        return next
    }

    // MARK: - Request

    /// Opens a bidirectional QUIC stream and writes the request HEADERS frame; returns once the
    /// HEADERS are written (or throws if the stream fails). Await ``awaitResponseStatus()`` for
    /// the response `:status`.
    func sendRequest(headerBlock: Data, endStream: Bool) async throws {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        try await multiplexer.ensureReady()
        let streamID: Int64 = try await multiplexer.run { [self] () -> Result<Int64, Error> in
            guard let multiplexer = self.multiplexer else {
                return .failure(HTTP3Error.streamClosed)
            }
            guard let sid = multiplexer.openBidiStream() else {
                self.state = .closed
                multiplexer.markStreamBlocked()
                return .failure(HTTP3Error.streamIdBlocked)
            }
            self.quicStreamID = sid
            // Register before the write so a fast response is recorded, then surfaced by
            // `awaitResponseStatus()` (via `responseTask`) — never lost.
            multiplexer.registerStream(self, streamID: sid)
            self.state = .requestSent
            return .success(sid)
        }

        let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
        do {
            try await multiplexer.writeStream(streamID, data: frame, fin: endStream)
        } catch {
            multiplexer.queue.async { [weak self] in self?.handleStreamError(error) }
            throw error
        }
    }

    /// Suspends until the response `:status` arrives (or the stream fails). If the HEADERS were
    /// already parsed, the promise is resolved and returns immediately.
    func awaitResponseStatus() async throws -> Int {
        guard multiplexer != nil else { throw HTTP3Error.streamClosed }
        return try await responseTask.value
    }

    func sendBody(_ data: Data, fin: Bool) async throws {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        let sid: Int64 = try await multiplexer.run { [self] () -> Result<Int64, Error> in
            guard state != .closed, let sid = quicStreamID else {
                return .failure(HTTP3Error.streamClosed)
            }
            return .success(sid)
        }
        if data.isEmpty && !fin { return }
        // An empty payload with fin==true is a bare half-close (FIN, no DATA frame).
        let frame = data.isEmpty ? Data() : HTTP3Framer.dataFrame(payload: data)
        try await multiplexer.writeStream(sid, data: frame, fin: fin)
    }

    func receive() async throws -> Data? {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        let data = try await nextInboxChunk()
        guard let data else {
            // Clean EOF: reclaim the mux slot + STOP_SENDING once the consumer has drained.
            multiplexer.queue.async { [weak self] in self?.closeAndShutdown() }
            return nil
        }
        // Credit the payload octets now the app has consumed them (backpressure preserved). The
        // frame-header octets were already credited on the queue in `deliverData`.
        multiplexer.queue.async { [weak self] in self?.ackQuicBytes(data.count) }
        return data
    }

    /// Reads and discards the entire response so the stream closes cleanly on EOF —
    /// avoids RESET_STREAM after FIN, which some servers treat as aborting the POST.
    func drainResponse() {
        Task { [weak self] in
            while let self {
                let data: Data?
                do { data = try await self.receive() } catch { return }
                guard data != nil else { return }
            }
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
            responseSignal.finish(throwing: HTTP3Error.streamClosed)
            inbox.finish()
        }
    }

    // MARK: - HTTP3StreamHandler (called on multiplexer queue)

    func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            frameBuffer.append(data)
            processFrameBuffer()
        }
        if fin {
            // EOF ordered after every chunk already yielded to the inbox; the shutdown fires
            // from `receive` once the consumer drains.
            inbox.finish()
        }
    }

    func handleSessionError(_ error: Error) {
        // A benign QUIC connection close (NO_ERROR / H3_NO_ERROR) is a graceful end of the
        // response — surface EOF rather than a reset.
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            responseSignal.finish(throwing: HTTP3Error.streamClosed)
            inbox.finish()
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

        if let status {
            responseSignal.yield(status)
            responseSignal.finish()
        } else {
            responseSignal.finish(throwing: HTTP3Error.connectionFailed("Response missing :status"))
        }
    }

    private func deliverData(_ data: Data, quicBytes: Int) {
        guard !data.isEmpty else {
            if quicBytes > 0 { ackQuicBytes(quicBytes) }
            return
        }
        // Credit the frame-header overhead now; the payload octets are credited in `receive`
        // once the consumer drains them (backpressure preserved).
        let headerBytes = quicBytes - data.count
        if headerBytes > 0 { ackQuicBytes(headerBytes) }
        inbox.yield(Data(data))
    }

    /// Extends the QUIC stream flow-control window once the app has consumed data.
    private func ackQuicBytes(_ count: Int) {
        guard count > 0, let sid = quicStreamID else { return }
        multiplexer?.extendStreamOffset(sid, count: count)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        closeAndShutdown(code: .internalError)
        responseSignal.finish(throwing: error)
        inbox.finish(throwing: error)
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
