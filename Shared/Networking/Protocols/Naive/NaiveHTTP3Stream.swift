//
//  NaiveHTTP3Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

actor NaiveHTTP3Stream {

    // MARK: - State

    enum StreamState {
        case idle, connectSent, open, closed
    }

    // MARK: - Properties

    nonisolated let destination: String

    /// The ngtcp2 boundary whose executor this stream adopts; held strongly so the
    /// executor outlives the stream even after the pooled multiplexer is evicted.
    private nonisolated let bridge: NGTCP2ConcurrencyBridge
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    private(set) var quicStreamID: Int64?

    private weak var multiplexer: HTTP3Multiplexer?
    private let configuration: NaiveConfiguration

    private var state: StreamState = .idle
    private var headersReceived = false

    /// Mirrors `state == .open` for the synchronous `NaiveTunnel` surface.
    private nonisolated let _isConnected = Atomic<Bool>(false)
    nonisolated var isConnected: Bool { _isConnected.load(ordering: .relaxed) }

    /// Inbound DATA payloads / EOF / error from the multiplexer's demux events. The producer
    /// (`yield`/`finish`) runs on the shared executor; the single consumer pulls via
    /// ``receiveData()``. QUIC flow control counts every stream byte (HTTP/3 frame header +
    /// payload), so the per-chunk `quicBytes` accounting is split: the demux path credits the
    /// frame-header octets as chunks arrive, and ``receiveData()`` credits the payload octets only
    /// once the app takes them — total credit stays exact, backpressure preserved.
    private let inbox = AsyncInbox<Data>()

    /// Partial HTTP/3 frame buffer; frames may span QUIC deliveries.
    private var frameBuffer = Data()
    private var frameBufferOffset = 0

    /// Resolves when the CONNECT response (200) arrives, or the stream fails first.
    /// One-shot connect signal, resolved by the demux path; the awaiter is `connectTask.value`.
    private let connectSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let connectTask: Task<Void, Error>

    /// Handshake-produced value, mirrored for the synchronous `NaiveTunnel` surface.
    private nonisolated let _negotiatedPaddingType = Mutex(NaivePaddingNegotiator.PaddingType.none)
    nonisolated var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType {
        _negotiatedPaddingType.withLock { $0 }
    }

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer, configuration: NaiveConfiguration, destination: String) {
        self.bridge = multiplexer.sharedBridge
        self.multiplexer = multiplexer
        self.configuration = configuration
        self.destination = destination
        let (connectStream, connectSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.connectSignal = connectSignal
        self.connectTask = Task { for try await _ in connectStream {} }
    }

    // MARK: - NaiveTunnel

    func openTunnel() async throws {
        guard let multiplexer else { throw HTTP3Error.connectionFailed("No multiplexer") }
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

        // The open and the sink registration are one isolated step on the multiplexer, so
        // no demuxed byte can race the registration.
        guard let streamID = await multiplexer.openStream(events: events) else {
            state = .closed
            connectSignal.finish(throwing: HTTP3Error.streamIdBlocked)
            try await connectTask.value
            return
        }
        quicStreamID = streamID
        state = .connectSent

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
        guard await multiplexer.isWithinPeerFieldSectionLimit(allHeaders) else {
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
                handleStreamError(error)
            }
        }
        try await connectTask.value
    }

    func sendData(_ data: Data) async throws {
        guard let multiplexer else { throw HTTP3Error.streamClosed }
        guard state == .open, let sid = quicStreamID else {
            throw state == .closed ? HTTP3Error.streamClosed : HTTP3Error.notReady
        }
        let frame = HTTP3Framer.dataFrame(payload: data)
        try await multiplexer.writeStream(sid, data: frame)
    }

    func receiveData() async throws -> Data? {
        guard multiplexer != nil else { throw HTTP3Error.streamClosed }
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

    nonisolated func close() {
        Task { await self.performClose() }
    }
    
    private func nextInboxChunk() async throws -> Data? {
        try await inbox.next()
    }

    private func performClose() {
        guard state != .closed else { return }
        state = .closed
        _isConnected.store(false, ordering: .relaxed)
        detachFromMultiplexer(code: headersReceived ? .noError : .requestCancelled)
        connectSignal.finish(throwing: HTTP3Error.streamClosed)
        inbox.finish()
    }

    // MARK: - Demux events (delivered on the shared executor)

    private func handleStreamData(_ data: Data, fin: Bool) {
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

    private func handleSessionError(_ error: Error) {
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
        let negotiated = NaivePaddingNegotiator.parseResponse(headers: paddingTuples)
        _negotiatedPaddingType.withLock { $0 = negotiated }

        NaivePaddingNegotiator.cachePaddingType(
            negotiated,
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )

        headersReceived = true
        state = .open
        _isConnected.store(true, ordering: .relaxed)

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
        state = .closed
        _isConnected.store(false, ordering: .relaxed)
        detachFromMultiplexer(code: code)

        connectSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    /// Closes the stream and sends RESET_STREAM/STOP_SENDING so the server can free the slot via MAX_STREAMS.
    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        guard state != .closed else { return }
        state = .closed
        _isConnected.store(false, ordering: .relaxed)
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

extension NaiveHTTP3Stream: NaiveTunnel {}
