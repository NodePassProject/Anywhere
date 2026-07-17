//
//  XHTTPH3RequestStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation

actor XHTTPH3RequestStream {

    // MARK: - State

    enum State { case idle, requestSent, open, closed }

    /// The ngtcp2 boundary whose executor this stream adopts; held strongly so the
    /// executor outlives the stream even after the multiplexer is torn down.
    private nonisolated let bridge: NGTCP2ConcurrencyBridge
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

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

    /// Inbound DATA payloads / EOF / error from the multiplexer's demux events. QUIC flow
    /// control counts every stream byte (HTTP/3 frame header + payload), so the per-chunk
    /// `quicBytes` accounting is split: `deliverData` credits the frame-header octets as
    /// chunks arrive, and ``receive()`` credits the payload octets only once the app takes
    /// them — total credit stays exact, backpressure preserved. The single consumer pulls
    /// `inboxIterator` from ``receive()`` as plain isolated state.
    private let inbox: AsyncThrowingStream<Data, Error>.Continuation
    private var inboxIterator: AsyncThrowingStream<Data, Error>.AsyncIterator

    // Frames may span QUIC deliveries; offset-based parsing with lazy compaction
    // keeps cost amortized O(1).
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer) {
        self.bridge = multiplexer.sharedBridge
        self.multiplexer = multiplexer
        let (responseStream, responseSignal) = AsyncThrowingStream.makeStream(of: Int.self)
        self.responseSignal = responseSignal
        self.responseTask = Task {
            for try await status in responseStream { return status }
            throw HTTP3Error.streamClosed
        }
        let (inboxStream, inbox) = AsyncThrowingStream.makeStream(of: Data.self)
        self.inbox = inbox
        self.inboxIterator = inboxStream.makeAsyncIterator()
    }

    // MARK: - Request

    /// Opens a bidirectional QUIC stream and writes the request HEADERS frame; returns once the
    /// HEADERS are written (or throws if the stream fails). Await ``awaitResponseStatus()`` for
    /// the response `:status`.
    func sendRequest(headerBlock: Data, endStream: Bool) async throws {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        try await multiplexer.ensureReady()

        // Demux event sinks; they fire on the shared executor and enter this actor's
        // isolation synchronously (verified against the executor at runtime).
        let events = HTTP3Multiplexer.StreamEvents(
            data: { [weak self] data, fin in
                self?.assumeIsolated { $0.handleStreamData(data, fin: fin) }
            },
            error: { [weak self] error in
                self?.assumeIsolated { $0.handleSessionError(error) }
            }
        )

        // The open and the sink registration are one isolated step on the multiplexer, so a
        // fast response is recorded before we even return here, then surfaced by
        // `awaitResponseStatus()` (via `responseTask`) — never lost.
        guard let sid = await multiplexer.openStream(events: events) else {
            state = .closed
            throw HTTP3Error.streamIdBlocked
        }
        quicStreamID = sid
        state = .requestSent

        let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
        do {
            try await multiplexer.writeStream(sid, data: frame, fin: endStream)
        } catch {
            handleStreamError(error)
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
        guard state != .closed, let sid = quicStreamID else {
            throw HTTP3Error.streamClosed
        }
        if data.isEmpty && !fin { return }
        // An empty payload with fin==true is a bare half-close (FIN, no DATA frame).
        let frame = data.isEmpty ? Data() : HTTP3Framer.dataFrame(payload: data)
        try await multiplexer.writeStream(sid, data: frame, fin: fin)
    }

    func receive() async throws -> Data? {
        guard multiplexer != nil else { throw HTTP3Error.streamClosed }
        let data = try await nextInboxChunk()
        guard let data else {
            // Clean EOF: reclaim the mux slot + STOP_SENDING once the consumer has drained.
            closeAndShutdown()
            return nil
        }
        // Credit the payload octets now the app has consumed them (backpressure preserved). The
        // frame-header octets were already credited by the demux path in `deliverData`.
        ackQuicBytes(data.count)
        return data
    }

    /// Reads and discards the entire response so the stream closes cleanly on EOF —
    /// avoids RESET_STREAM after FIN, which some servers treat as aborting the POST.
    nonisolated func drainResponse() {
        Task {
            while true {
                let data: Data?
                do { data = try await self.receive() } catch { return }
                guard data != nil else { return }
            }
        }
    }

    nonisolated func close() {
        Task { await self.performClose() }
    }

    /// Single-consumer pull over `inbox`. Takes a local copy of the iterator for the mutating
    /// async `next()` (both share the stream's backing storage) and stores it back. Serial by
    /// ``receive()``'s single-consumer contract.
    private func nextInboxChunk() async throws -> Data? {
        var iterator = inboxIterator
        let next = try await iterator.next()
        inboxIterator = iterator
        return next
    }

    private func performClose() {
        guard state != .closed else { return }
        state = .closed
        // A caller-initiated close before completion is H3_REQUEST_CANCELLED;
        // after a clean response it's H3_NO_ERROR.
        detachFromMultiplexer(code: headersReceived ? .noError : .requestCancelled)
        responseSignal.finish(throwing: HTTP3Error.streamClosed)
        inbox.finish()
    }

    // MARK: - Demux events (delivered on the shared executor)

    private func handleStreamData(_ data: Data, fin: Bool) {
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

    private func handleSessionError(_ error: Error) {
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
        state = .closed
        detachFromMultiplexer(code: .internalError)
        responseSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        guard state != .closed else { return }
        state = .closed
        detachFromMultiplexer(code: code)
    }

    /// Releases the mux registration + slot and shuts the QUIC stream down. The multiplexer
    /// shares this actor's executor, so its isolation is entered synchronously here.
    private func detachFromMultiplexer(code: HTTP3ErrorCode) {
        guard let multiplexer, let sid = quicStreamID else { return }
        multiplexer.assumeIsolated { $0.removeStream(sid) }
        multiplexer.shutdownStream(sid, code: code)
    }
}
