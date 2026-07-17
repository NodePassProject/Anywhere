//
//  NaiveHTTP3Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP3Stream")

nonisolated class NaiveHTTP3Stream: NaiveTunnel, HTTP3StreamHandler {

    // MARK: - State

    enum StreamState {
        case idle, connectSent, open, closed
    }

    // MARK: - Properties

    let destination: String
    private(set) var quicStreamID: Int64?

    private weak var multiplexer: HTTP3Multiplexer?
    private let configuration: NaiveConfiguration

    private var state: StreamState = .idle
    private var headersReceived = false

    /// Inbound DATA payloads / EOF / error from the multiplexer's demux loop. Producer side (`inbox`)
    /// is `Sendable` and driven on the multiplexer queue; the single consumer pulls `inboxIterator`
    /// from ``receiveData()``. The `Mutex` guards the iterator *value* (this stream is a queue-confined
    /// class, not an actor). QUIC flow control counts every stream byte (HTTP/3 frame header +
    /// payload), so the per-chunk `quicBytes` accounting is split: `deliverData` credits the
    /// frame-header octets on the multiplexer queue as chunks arrive, and ``receiveData()`` credits
    /// the payload octets only once the app takes them — total credit stays exact, backpressure preserved.
    private let inbox: AsyncThrowingStream<Data, Error>.Continuation
    private let inboxIterator: Mutex<AsyncThrowingStream<Data, Error>.AsyncIterator>

    /// Partial HTTP/3 frame buffer; frames may span QUIC deliveries.
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    /// Resolves when the CONNECT response (200) arrives, or the stream fails first. The waiter
    /// continuation lives in the promise (async infra), bridging the multiplexer's demux loop.
    /// One-shot connect signal, resolved by the demux/callback path; the awaiter is `connectTask.value`.
    private let connectSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let connectTask: Task<Void, Error>

    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    var isConnected: Bool { state == .open }

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer, configuration: NaiveConfiguration, destination: String) {
        self.multiplexer = multiplexer
        self.configuration = configuration
        self.destination = destination
        let (connectStream, connectSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.connectSignal = connectSignal
        self.connectTask = Task { for try await _ in connectStream {} }
        let (inboxStream, inbox) = AsyncThrowingStream.makeStream(of: Data.self)
        self.inbox = inbox
        self.inboxIterator = Mutex(inboxStream.makeAsyncIterator())
    }

    /// Single-consumer pull over `inbox`: takes the stored iterator, awaits one element, stores it
    /// back. Serial by ``receiveData()``'s single-consumer contract.
    private func nextInboxChunk() async throws -> Data? {
        var iterator = inboxIterator.withLock { $0 }
        let next = try await iterator.next()
        inboxIterator.withLock { $0 = iterator }
        return next
    }

    // MARK: - NaiveTunnel

    // The HTTP/3 QUIC multiplexer pushes stream data on its own queue and resolves the parked
    // continuations there; the async surface awaits them (state machine preserved).

    func openTunnel() async throws {
        guard let multiplexer else { throw HTTP3Error.connectionFailed("No multiplexer") }
        try await multiplexer.ensureReady()

        // Claim the stream, register it, and fire the CONNECT HEADERS write on the multiplexer
        // queue; every outcome (early failure, or the eventual response / send failure) flows
        // through `connectSignal`, resolved here or later in `processResponseHeaders` (200) /
        // `handleStreamError`.
        await multiplexer.run { [self] in
            guard let multiplexer = self.multiplexer else {
                self.connectSignal.finish(throwing: HTTP3Error.streamClosed)
                return
            }
            guard let streamID = multiplexer.openBidiStream() else {
                self.state = .closed
                multiplexer.markStreamBlocked()
                self.connectSignal.finish(throwing: HTTP3Error.streamIdBlocked)
                return
            }
            self.quicStreamID = streamID
            multiplexer.registerStream(self, streamID: streamID)
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

            var allHeaders = extraHeaders
            allHeaders.insert((name: ":method", value: "CONNECT"), at: 0)
            allHeaders.insert((name: ":authority", value: self.destination), at: 1)
            guard multiplexer.isWithinPeerFieldSectionLimit(allHeaders) else {
                // handleStreamError resolves connectSignal with the failure and tears the stream down.
                self.handleStreamError(HTTP3Error.connectionFailed("Request headers exceed peer MAX_FIELD_SECTION_SIZE"))
                return
            }

            let headerBlock = QPACKEncoder.encodeConnectHeaders(
                authority: self.destination, extraHeaders: extraHeaders
            )
            let headersFrame = HTTP3Framer.headersFrame(headerBlock: headerBlock)

            Task { [weak self] in
                guard let self, let multiplexer = self.multiplexer else { return }
                do {
                    try await multiplexer.writeStream(streamID, data: headersFrame)
                } catch {
                    multiplexer.queue.async { self.handleStreamError(error) }
                }
            }
        }
        try await connectTask.value
    }

    func sendData(_ data: Data) async throws {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        // Guard `state == .open` and read the (once-set) stream ID on the multiplexer queue.
        let streamID: Int64 = try await multiplexer.run { [self] () -> Result<Int64, Error> in
            guard state == .open, let sid = quicStreamID else {
                return .failure(state == .closed ? HTTP3Error.streamClosed : HTTP3Error.notReady)
            }
            return .success(sid)
        }
        let frame = HTTP3Framer.dataFrame(payload: data)
        try await multiplexer.writeStream(streamID, data: frame)
    }

    func receiveData() async throws -> Data? {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        let data = try await nextInboxChunk()
        guard let data else {
            // Clean EOF: reclaim the mux slot + STOP_SENDING once the consumer has drained.
            multiplexer.queue.async { [weak self] in self?.closeAndShutdown() }
            return nil
        }
        // Credit the payload bytes now the app has taken them (backpressure preserved). The
        // frame-header octets were already credited on the queue in `deliverData`.
        multiplexer.queue.async { [weak self] in self?.ackQuicBytes(data.count) }
        return data
    }

    func close() {
        guard let multiplexer else { return }
        multiplexer.queue.async { [self] in
            guard state != .closed else { return }
            state = .closed
            multiplexer.removeStream(self)

            // Shutdown lets the server reclaim the slot via MAX_STREAMS; a
            // pre-completion close signals H3_REQUEST_CANCELLED.
            if let streamID = quicStreamID {
                let code: HTTP3ErrorCode = headersReceived ? .noError : .requestCancelled
                multiplexer.shutdownStream(streamID, code: code)
            }

            connectSignal.finish(throwing: HTTP3Error.streamClosed)
            inbox.finish()
        }
    }

    // MARK: - Session Callbacks (called on multiplexer.queue)

    func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            frameBuffer.append(data)
            processFrameBuffer()
        }

        if fin {
            // EOF is ordered after every chunk already yielded to the inbox; the shutdown
            // (STOP_SENDING + slot release) fires from `receiveData` once the consumer drains.
            inbox.finish()
        }
    }

    func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    // MARK: - HTTP/3 Frame Processing

    private func processFrameBuffer() {
        // Non-DATA frames are consumed internally; ack their QUIC bytes as one
        // batch per parse pass instead of per frame.
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
                // SETTINGS/GOAWAY/etc. — internally consumed.
                controlBytes += consumed
            }
        }
        if controlBytes > 0 {
            ackQuicBytes(controlBytes)
        }

        // Compact lazily to avoid O(n²); use Data(...) reassignment, not in-place
        // removal, which leaves startIndex shifted while the parser assumes 0.
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

        NaivePaddingNegotiator.cachePaddingType(
            negotiatedPaddingType,
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )

        headersReceived = true
        state = .open

        connectSignal.finish()
    }

    private func deliverData(_ data: Data, quicBytes: Int) {
        guard !data.isEmpty else {
            // Empty DATA frame — still consumed QUIC bytes (frame header).
            if quicBytes > 0 { ackQuicBytes(quicBytes) }
            return
        }
        // Credit the frame-header overhead now; the payload octets are credited in
        // `receiveData` once the consumer drains them (backpressure preserved).
        let headerBytes = quicBytes - data.count
        if headerBytes > 0 { ackQuicBytes(headerBytes) }
        inbox.yield(Data(data))
    }

    /// Extends the QUIC receive window to signal consumed bytes to the server.
    private func ackQuicBytes(_ count: Int) {
        guard count > 0, let streamID = quicStreamID else { return }
        multiplexer?.extendStreamOffset(streamID, count: count)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        let code: HTTP3ErrorCode
        if let http3Error = error as? HTTP3Error, case .tunnelFailed = http3Error {
            code = .connectError
        } else if error is HTTP3Error {
            code = .requestCancelled
        } else {
            code = .internalError
        }
        closeAndShutdown(code: code)

        connectSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    /// Closes the stream and sends RESET_STREAM/STOP_SENDING so the server can free the slot via MAX_STREAMS.
    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        guard state != .closed else { return }
        state = .closed
        multiplexer?.removeStream(self)
        if let streamID = quicStreamID {
            multiplexer?.shutdownStream(streamID, code: code)
        }
    }
}
