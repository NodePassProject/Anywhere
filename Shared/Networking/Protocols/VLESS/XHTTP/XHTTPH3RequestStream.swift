//
//  XHTTPH3RequestStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation
import Synchronization

nonisolated final class XHTTPH3RequestStream: Sendable {

    // MARK: - State

    enum Phase { case idle, requestSent, open, closed }

    /// Weak back-reference to the owning multiplexer, boxed so the stream stays `Sendable`;
    /// set once at init.
    private struct WeakMultiplexer { weak var value: HTTP3Multiplexer? }
    private let multiplexerBox: Mutex<WeakMultiplexer>

    /// Request/response state, guarded by `lock`. Never held across a call into the
    /// multiplexer, an inbox yield, or a continuation resume; effects are computed under
    /// the lock and performed after it is released.
    private struct State {
        var phase: Phase = .idle
        var quicStreamID: Int64?
        var headersReceived = false
        var responseStatus: Int?

        // Frames may span QUIC deliveries; offset-based parsing with lazy compaction
        // keeps cost amortized O(1).
        var frameBuffer = Data()
        var frameBufferOffset = 0
    }
    private let lock = Mutex(State())

    var quicStreamID: Int64? { lock.withLock { $0.quicStreamID } }
    var responseStatus: Int? { lock.withLock { $0.responseStatus } }

    // MARK: - Response

    /// One-shot response-status signal; the awaiter is `responseTask.value`. Yields the HTTP
    /// status then finishes on success, or finishes-throwing on failure.
    private let responseSignal: AsyncThrowingStream<Int, Error>.Continuation
    private let responseTask: Task<Int, Error>

    // MARK: - Receive buffering

    /// Inbound DATA payloads / EOF / error from the multiplexer's demux events. QUIC flow
    /// control counts every stream byte (HTTP/3 frame header + payload), so the per-chunk
    /// `quicBytes` accounting is split: the demux path credits the frame-header octets as
    /// chunks arrive, and ``receive()`` credits the payload octets only once the app takes
    /// them — total credit stays exact, backpressure preserved. The single consumer pulls via
    /// ``receive()``.
    private let inbox = AsyncInbox<Data>()

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer) {
        self.multiplexerBox = Mutex(WeakMultiplexer(value: multiplexer))
        let (responseStream, responseSignal) = AsyncThrowingStream.makeStream(of: Int.self)
        self.responseSignal = responseSignal
        self.responseTask = Task {
            for try await status in responseStream { return status }
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
    }

    // MARK: - Request

    /// Opens a bidirectional QUIC stream and writes the request HEADERS frame; returns once the
    /// HEADERS are written (or throws if the stream fails). Await ``awaitResponseStatus()`` for
    /// the response `:status`.
    func sendRequest(headerBlock: Data, endStream: Bool) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
        try await multiplexer.ensureReady()

        // Demux event sinks; they fire synchronously on the ngtcp2 queue and route into
        // this stream's Mutex-guarded state machine (compute under the lock, effects after).
        let events = HTTP3Multiplexer.StreamEvents(
            data: { [weak self] data, fin in
                self?.handleStreamData(data, fin: fin)
            },
            error: { [weak self] error in
                self?.handleSessionError(error)
            }
        )

        // The open and the sink registration are one on-queue step on the multiplexer, so a
        // fast response is recorded before we even return here, then surfaced by
        // `awaitResponseStatus()` (via `responseTask`) — never lost.
        guard let sid = await multiplexer.openStream(events: events) else {
            lock.withLock { $0.phase = .closed }
            throw AnywhereError.proxy(.http3, .streamIDsExhausted)
        }
        lock.withLock { state in
            state.quicStreamID = sid
            state.phase = .requestSent
        }

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
        guard multiplexerBox.withLock({ $0.value }) != nil else { throw AnywhereError.proxy(.http3, .streamClosed) }
        return try await responseTask.value
    }

    func sendBody(_ data: Data, fin: Bool) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
        let sid: Int64? = lock.withLock { state in
            state.phase == .closed ? nil : state.quicStreamID
        }
        guard let sid else { throw AnywhereError.proxy(.http3, .streamClosed) }
        if data.isEmpty && !fin { return }
        // An empty payload with fin==true is a bare half-close (FIN, no DATA frame).
        let frame = data.isEmpty ? Data() : HTTP3Framer.dataFrame(payload: data)
        try await multiplexer.writeStream(sid, data: frame, fin: fin)
    }

    func receive() async throws -> Data? {
        guard multiplexerBox.withLock({ $0.value }) != nil else { throw AnywhereError.proxy(.http3, .streamClosed) }
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
    func drainResponse() {
        Task {
            while true {
                let data: Data?
                do { data = try await self.receive() } catch { return }
                guard data != nil else { return }
            }
        }
    }

    func close() {
        let detach: (sid: Int64?, code: HTTP3ErrorCode)? = lock.withLock { state in
            guard state.phase != .closed else { return nil }
            // A caller-initiated close before completion is H3_REQUEST_CANCELLED;
            // after a clean response it's H3_NO_ERROR.
            let code: HTTP3ErrorCode = state.headersReceived ? .noError : .requestCancelled
            state.phase = .closed
            return (state.quicStreamID, code)
        }
        guard let detach else { return }
        detachFromMultiplexer(sid: detach.sid, code: detach.code)
        responseSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
        inbox.finish()
    }

    private func nextInboxChunk() async throws -> Data? {
        try await inbox.next()
    }

    // MARK: - Demux events (delivered synchronously on the ngtcp2 queue)

    private func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            processInbound(data)
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
        if case AnywhereError.quic(.closed(graceful: true)) = error {
            responseSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
            inbox.finish()
            return
        }
        handleStreamError(error)
    }

    // MARK: - Frame processing

    /// Outcome of the response-HEADERS frame in a parse pass, decided under `lock`.
    private enum HeadersOutcome {
        case none
        case status(Int)
        case missingStatus
        case failed(Error)
    }

    /// Appends `data` (a zero-copy ngtcp2 view — copied here) and drains every complete frame.
    /// Frame parsing and state transitions run under `lock`; inbox yields, flow-control acks,
    /// and the response resolution are performed after it is released.
    private func processInbound(_ data: Data) {
        // Only DATA frames reach the app; control frames are acked in batch.
        var controlBytes = 0
        var deliveries: [Data] = []
        var outcome: HeadersOutcome = .none

        lock.withLock { state in
            state.frameBuffer.append(data)
            while state.frameBufferOffset < state.frameBuffer.count {
                guard let (frame, consumed) = HTTP3Framer.parseFrame(
                    from: state.frameBuffer, offset: state.frameBufferOffset
                ) else {
                    break
                }
                state.frameBufferOffset += consumed

                if !state.headersReceived {
                    outcome = Self.processResponseHeaders(frame, state: &state)
                    controlBytes += consumed
                    // A rejected response closes the stream; nothing after it is deliverable.
                    if case .failed = outcome { break }
                    if case .missingStatus = outcome { break }
                } else if frame.type == HTTP3FrameType.data.rawValue {
                    if frame.payload.isEmpty {
                        controlBytes += consumed
                    } else {
                        // Credit the frame-header overhead now; the payload octets are credited
                        // in `receive` once the consumer drains them (backpressure preserved).
                        controlBytes += consumed - frame.payload.count
                        deliveries.append(Data(frame.payload))
                    }
                } else {
                    // Trailers / unknown frames after the response headers.
                    controlBytes += consumed
                }
            }

            if state.frameBufferOffset >= state.frameBuffer.count {
                state.frameBuffer = Data()
                state.frameBufferOffset = 0
            } else if state.frameBufferOffset > 64 * 1024 {
                state.frameBuffer = Data(state.frameBuffer[(state.frameBuffer.startIndex + state.frameBufferOffset)...])
                state.frameBufferOffset = 0
            }
        }

        switch outcome {
        case .none:
            break
        case .status(let status):
            responseSignal.yield(status)
            responseSignal.finish()
        case .missingStatus:
            responseSignal.finish(throwing: AnywhereError.proxy(.http3, .connectionClosed(detail: "Response missing :status")))
        case .failed(let error):
            handleStreamError(error)
        }

        for payload in deliveries {
            inbox.yield(payload)
        }
        if controlBytes > 0 {
            ackQuicBytes(controlBytes)
        }
    }

    /// Parses the response HEADERS. Must be called with `lock` held; on a decoded status the
    /// phase flips to `.open` in place, and the off-lock effects (response resolution or
    /// teardown) are carried in the returned outcome.
    private static func processResponseHeaders(_ frame: HTTP3Framer.Frame, state: inout State) -> HeadersOutcome {
        guard frame.type == HTTP3FrameType.headers.rawValue else {
            return .failed(AnywhereError.proxy(.http3, .connectionClosed(detail: "Expected HEADERS, got type \(frame.type)")))
        }
        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
            return .failed(AnywhereError.proxy(.http3, .connectionClosed(detail: "Malformed QPACK header block")))
        }

        let statusValue = headers.first(where: { $0.name == ":status" })?.value
        let status = statusValue.flatMap { Int($0) }
        state.responseStatus = status
        state.headersReceived = true
        state.phase = .open

        if let status {
            return .status(status)
        } else {
            return .missingStatus
        }
    }

    /// Extends the QUIC stream flow-control window once the app has consumed data.
    private func ackQuicBytes(_ count: Int) {
        guard count > 0 else { return }
        guard let sid = lock.withLock({ $0.quicStreamID }) else { return }
        multiplexerBox.withLock { $0.value }?.extendStreamOffset(sid, count: count)
    }

    private func handleStreamError(_ error: Error) {
        let sid: Int64?? = lock.withLock { state in
            guard state.phase != .closed else { return nil }
            state.phase = .closed
            return .some(state.quicStreamID)
        }
        guard let sid else { return }
        detachFromMultiplexer(sid: sid, code: .internalError)
        responseSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        let sid: Int64?? = lock.withLock { state in
            guard state.phase != .closed else { return nil }
            state.phase = .closed
            return .some(state.quicStreamID)
        }
        guard let sid else { return }
        detachFromMultiplexer(sid: sid, code: code)
    }

    /// Releases the mux registration + slot and shuts the QUIC stream down. Called with
    /// `lock` released — both multiplexer calls take the multiplexer's own locks.
    private func detachFromMultiplexer(sid: Int64?, code: HTTP3ErrorCode) {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }), let sid else { return }
        multiplexer.removeStream(sid)
        multiplexer.shutdownStream(sid, code: code)
    }
}
