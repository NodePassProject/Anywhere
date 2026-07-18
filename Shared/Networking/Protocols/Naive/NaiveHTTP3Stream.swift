//
//  NaiveHTTP3Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated final class NaiveHTTP3Stream: NaiveTunnel, Sendable {

    // MARK: - Phase

    enum Phase {
        case idle, connectSent, open, closed
    }

    // MARK: - Properties

    let destination: String

    /// Weak back-reference to the pooled multiplexer, boxed so the stream stays `Sendable`;
    /// set once at init.
    private struct WeakMultiplexer { weak var value: HTTP3Multiplexer? }
    private let multiplexerBox: Mutex<WeakMultiplexer>

    private let configuration: NaiveConfiguration

    /// Receive/response state, guarded by `lock`. Never held across a call into the
    /// multiplexer, an inbox yield, or a continuation resume; effects are computed under
    /// the lock and performed after it is released.
    private struct State {
        var phase: Phase = .idle
        var quicStreamID: Int64?
        var headersReceived = false

        /// Partial HTTP/3 frame buffer; frames may span QUIC deliveries. Offset-based
        /// parsing with lazy compaction keeps cost amortized O(1).
        var frameBuffer = Data()
        var frameBufferOffset = 0

        /// Handshake-produced value, exposed for the synchronous `NaiveTunnel` surface.
        var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none
    }
    private let lock = Mutex(State())

    /// Inbound DATA payloads / EOF / error from the multiplexer's demux events. The producer
    /// (`yield`/`finish`) runs synchronously on the ngtcp2 queue; the single consumer pulls via
    /// ``receiveData()``. QUIC flow control counts every stream byte (HTTP/3 frame header +
    /// payload), so the per-chunk `quicBytes` accounting is split: the demux path credits the
    /// frame-header octets as chunks arrive, and ``receiveData()`` credits the payload octets only
    /// once the app takes them — total credit stays exact, backpressure preserved.
    private let inbox = AsyncInbox<Data>()

    /// Resolves when the CONNECT response (200) arrives, or the stream fails first.
    /// One-shot connect signal, resolved by the demux path; the awaiter is `connectTask.value`.
    private let connectSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let connectTask: Task<Void, Error>

    var isConnected: Bool { lock.withLock { $0.phase == .open } }

    var quicStreamID: Int64? { lock.withLock { $0.quicStreamID } }

    var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType {
        lock.withLock { $0.negotiatedPaddingType }
    }

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer, configuration: NaiveConfiguration, destination: String) {
        self.multiplexerBox = Mutex(WeakMultiplexer(value: multiplexer))
        self.configuration = configuration
        self.destination = destination
        let (connectStream, connectSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.connectSignal = connectSignal
        self.connectTask = Task { for try await _ in connectStream {} }
    }

    // MARK: - NaiveTunnel

    func openTunnel() async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw HTTP3Error.connectionFailed("No multiplexer")
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

        // The open and the sink registration are one on-queue step on the multiplexer, so
        // no demuxed byte can race the registration.
        guard let streamID = await multiplexer.openStream(events: events) else {
            lock.withLock { $0.phase = .closed }
            connectSignal.finish(throwing: HTTP3Error.streamIdBlocked)
            try await connectTask.value
            return
        }
        lock.withLock { state in
            state.quicStreamID = streamID
            state.phase = .connectSent
        }

        var extraHeaders: [(name: String, value: String)] = []
        extraHeaders.append((name: "user-agent", value: "Chrome/128.0.0.0"))
        if let auth = configuration.basicAuth {
            extraHeaders.append((name: "proxy-authorization", value: "Basic \(auth)"))
        }
        let cachedType = NaivePaddingNegotiator.cachedPaddingType(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )
        extraHeaders.append(contentsOf: NaivePaddingNegotiator.requestHeaders(
            fastOpen: cachedType != nil
        ))

        var allHeaders = extraHeaders
        allHeaders.insert((name: ":method", value: "CONNECT"), at: 0)
        allHeaders.insert((name: ":authority", value: destination), at: 1)
        guard multiplexer.isWithinPeerFieldSectionLimit(allHeaders) else {
            // handleStreamError resolves connectSignal with the failure and tears the stream down.
            handleStreamError(HTTP3Error.connectionFailed("Request headers exceed peer MAX_FIELD_SECTION_SIZE"))
            try await connectTask.value
            return
        }

        let headerBlock = QPACKEncoder.encodeConnectHeaders(
            authority: destination, extraHeaders: extraHeaders
        )
        let headersFrame = HTTP3Framer.headersFrame(headerBlock: headerBlock)

        // Strong captures: the write task owns the stream until the HEADERS reach ngtcp2;
        // every outcome (response, send failure) flows through `connectSignal`.
        Task {
            do {
                try await multiplexer.writeStream(streamID, data: headersFrame)
            } catch {
                self.handleStreamError(error)
            }
        }
        try await connectTask.value
    }

    func sendData(_ data: Data) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw HTTP3Error.streamClosed
        }
        enum Gate { case ok(Int64); case closed; case notReady }
        let gate: Gate = lock.withLock { state in
            guard state.phase == .open, let sid = state.quicStreamID else {
                return state.phase == .closed ? .closed : .notReady
            }
            return .ok(sid)
        }
        switch gate {
        case .closed:
            throw HTTP3Error.streamClosed
        case .notReady:
            throw HTTP3Error.notReady
        case .ok(let sid):
            let frame = HTTP3Framer.dataFrame(payload: data)
            try await multiplexer.writeStream(sid, data: frame)
        }
    }

    func receiveData() async throws -> Data? {
        guard multiplexerBox.withLock({ $0.value }) != nil else { throw HTTP3Error.streamClosed }
        let data = try await nextInboxChunk()
        guard let data else {
            // Clean EOF: reclaim the mux slot + STOP_SENDING once the consumer has drained.
            closeAndShutdown()
            return nil
        }
        // Credit the payload bytes now the app has taken them (backpressure preserved). The
        // frame-header octets were already credited by the demux path in `deliverData`.
        ackQuicBytes(data.count)
        return data
    }

    func close() {
        let detach: (sid: Int64?, code: HTTP3ErrorCode)? = lock.withLock { state in
            guard state.phase != .closed else { return nil }
            let code: HTTP3ErrorCode = state.headersReceived ? .noError : .requestCancelled
            state.phase = .closed
            return (state.quicStreamID, code)
        }
        guard let detach else { return }
        detachFromMultiplexer(sid: detach.sid, code: detach.code)
        connectSignal.finish(throwing: HTTP3Error.streamClosed)
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
            // EOF is ordered after every chunk already yielded to the inbox; the shutdown
            // (STOP_SENDING + slot release) fires from `receiveData` once the consumer drains.
            inbox.finish()
        }
    }

    private func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    // MARK: - HTTP/3 Frame Processing

    /// Outcome of the response-HEADERS frame in a parse pass, decided under `lock`.
    private enum HeadersOutcome {
        case none
        case opened(padding: NaivePaddingNegotiator.PaddingType)
        case failed(Error)
    }

    /// Appends `data` (a zero-copy ngtcp2 view — copied here) and drains every complete frame.
    /// Frame parsing and state transitions run under `lock`; inbox yields, flow-control acks,
    /// and the connect resolution are performed after it is released.
    private func processInbound(_ data: Data) {
        // Non-DATA frames are consumed internally; ack their QUIC bytes as one
        // batch per parse pass instead of per frame.
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
                } else if frame.type == HTTP3FrameType.data.rawValue {
                    if frame.payload.isEmpty {
                        // Empty DATA frame — still consumed QUIC bytes (frame header).
                        controlBytes += consumed
                    } else {
                        // Credit the frame-header overhead now; the payload octets are credited
                        // in `receiveData` once the consumer drains them (backpressure preserved).
                        controlBytes += consumed - frame.payload.count
                        deliveries.append(Data(frame.payload))
                    }
                } else {
                    // SETTINGS/GOAWAY/etc. — internally consumed.
                    controlBytes += consumed
                }
            }

            // Compact lazily to avoid O(n²); use Data(...) reassignment, not in-place
            // removal, which leaves startIndex shifted while the parser assumes 0.
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
        case .opened(let padding):
            NaivePaddingNegotiator.cachePaddingType(
                padding,
                host: configuration.proxyHost,
                port: configuration.proxyPort,
                sni: configuration.effectiveSNI
            )
            connectSignal.finish()
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

    /// Parses the CONNECT response HEADERS. Must be called with `lock` held; on success the
    /// phase flips to `.open` in place, and the off-lock effects (padding cache, connect
    /// resolution or teardown) are carried in the returned outcome.
    private static func processResponseHeaders(_ frame: HTTP3Framer.Frame, state: inout State) -> HeadersOutcome {
        guard frame.type == HTTP3FrameType.headers.rawValue else {
            return .failed(HTTP3Error.connectionFailed("Expected HEADERS, got type \(frame.type)"))
        }

        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
            return .failed(HTTP3Error.connectionFailed("Malformed QPACK header block"))
        }
        let statusHeader = headers.first(where: { $0.name == ":status" })

        guard let status = statusHeader?.value, status == "200" else {
            let code = statusHeader?.value ?? "unknown"
            if code == "407" {
                return .failed(HTTP3Error.authenticationRequired)
            } else {
                return .failed(HTTP3Error.tunnelFailed(statusCode: code))
            }
        }

        let paddingTuples = headers.map { (name: $0.name, value: $0.value) }
        let negotiated = NaivePaddingNegotiator.parseResponse(headers: paddingTuples)
        state.negotiatedPaddingType = negotiated
        state.headersReceived = true
        state.phase = .open
        return .opened(padding: negotiated)
    }

    /// Extends the QUIC receive window to signal consumed bytes to the server.
    private func ackQuicBytes(_ count: Int) {
        guard count > 0 else { return }
        guard let streamID = lock.withLock({ $0.quicStreamID }) else { return }
        multiplexerBox.withLock { $0.value }?.extendStreamOffset(streamID, count: count)
    }

    private func handleStreamError(_ error: Error) {
        let detach: (sid: Int64?, code: HTTP3ErrorCode)? = lock.withLock { state in
            guard state.phase != .closed else { return nil }
            let code: HTTP3ErrorCode
            if let http3Error = error as? HTTP3Error, case .tunnelFailed = http3Error {
                code = .connectError
            } else if error is HTTP3Error {
                code = .requestCancelled
            } else {
                code = .internalError
            }
            state.phase = .closed
            return (state.quicStreamID, code)
        }
        guard let detach else { return }
        detachFromMultiplexer(sid: detach.sid, code: detach.code)

        connectSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    /// Closes the stream and sends RESET_STREAM/STOP_SENDING so the server can free the slot via MAX_STREAMS.
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
