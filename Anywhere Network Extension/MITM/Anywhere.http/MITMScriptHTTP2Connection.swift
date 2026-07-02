//
//  MITMScriptHTTP2Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "MITMScriptHTTP2")

// MARK: - Errors

enum MITMScriptHTTP2Error: Error, LocalizedError {
    case notReady
    case protocolError(String)
    case connectionClosed(String)
    case goaway
    case streamReset(UInt32)
    case requestHeadersTooLarge
    /// Sentinel: the TLS ALPN came back non-`h2`; retry over HTTP/1.1.
    case needsHTTP1Fallback

    var errorDescription: String? {
        switch self {
        case .notReady: return "HTTP/2 connection not ready"
        case .protocolError(let message): return "HTTP/2 protocol error: \(message)"
        case .connectionClosed(let message): return "HTTP/2 connection closed: \(message)"
        case .goaway: return "HTTP/2 GOAWAY received"
        case .streamReset(let sid): return "HTTP/2 stream \(sid) reset"
        case .requestHeadersTooLarge: return "HTTP/2 request header block exceeds one frame"
        case .needsHTTP1Fallback: return "origin did not negotiate HTTP/2"
        }
    }
}

// MARK: - MITMScriptHTTP2Connection

/// One pooled, multiplexed HTTP/2 connection to a single origin, serving the MITM script `fetch` API.
/// All mutable state is confined to `queue`.
nonisolated final class MITMScriptHTTP2Connection: Multiplexer {

    // MARK: State

    enum State: Equatable {
        case idle
        case connecting
        /// Client preface + SETTINGS sent, awaiting the server's SETTINGS.
        case prefaceSent
        case ready
        /// GOAWAY received — existing streams finish, no new streams.
        case goingAway
        case closed
    }

    // MARK: Flow-control / SETTINGS profile

    /// Advertised per-stream receive window; also our SETTINGS_INITIAL_WINDOW_SIZE.
    private static let streamRecvWindow = 4 * 1024 * 1024
    /// Advertised connection receive window; sized to the client's 16 MiB global in-flight budget.
    private static let connectionRecvWindow = 16 * 1024 * 1024
    private static let maxFrameSize: UInt32 = 16_384
    private static let headerTableSize: UInt32 = 65_536
    /// Bounds a single decoded header list and the accumulated CONTINUATION block.
    private static let maxHeaderListSize = 262_144
    /// Keeps in-flight bodies bounded under the NE memory budget; beyond this the pool opens another connection.
    private static let ownMaxConcurrentStreams: UInt32 = 32

    private static let httpVersionDefaultWindow = 65_535
    private static let priorityFlag: UInt8 = 0x20
    private static let connectionPreface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    private static let maxReceiveBufferSize = 2 * 1024 * 1024

    // MARK: Origin

    let host: String
    let port: UInt16
    let insecure: Bool

    // MARK: Serial state (touched only on `queue`)

    /// Guards all mutable connection + stream state; `.userInitiated` to match the data-plane chain.
    let queue = DispatchQueue(label: "com.anywhere.ne.script-http2", qos: .userInitiated)

    private(set) var state: State = .idle

    private var dialed: OutboundConnector.Dialed?
    private var tlsClient: TLSClient?
    private var connection: ProxyConnection?

    private var streams: [UInt32: MITMScriptHTTP2Stream] = [:]
    private var nextStreamID: UInt32 = 1
    private var maxConcurrentStreams: UInt32 = ownMaxConcurrentStreams

    /// Connection-scoped HPACK decoder; the dynamic table is shared across all streams (RFC 7541 §2.2).
    private let hpackDecoder = HPACKDecoder()

    private var connectionSendWindow = httpVersionDefaultWindow
    private var connectionRecvConsumed = 0
    private(set) var peerInitialWindowSize = httpVersionDefaultWindow

    private var receiveBuffer = Data()

    /// In-progress header block: the initiating HEADERS' flags + accumulated fragment (RFC 7540 §6.10).
    private var pendingHeaders: (streamID: UInt32, flags: UInt8, block: Data)?

    private var readyCallbacks: [(Result<Void, Error>) -> Void] = []

    private(set) var negotiatedHTTP1 = false

    /// Called when the connection becomes permanently unusable, so the pool can evict it.
    var onClose: (() -> Void)?
    /// Called once when the origin is discovered to be HTTP/1.1-only, so the pool can cache it.
    var onNegotiatedHTTP1: (() -> Void)?

    // MARK: Pool-visible snapshot (guarded by `poolLock`, read off-queue by the pool)

    private let poolLock = UnfairLock()
    private var poolState: State = .idle
    /// `streams.count + poolReserved`, so a slot claimed by an in-flight `perform` isn't lost to `updatePoolSnapshot`.
    private var poolStreamCount = 0
    private var poolReserved = 0
    private var poolMaxConcurrent: UInt32 = ownMaxConcurrentStreams

    // MARK: Init

    init(host: String, port: UInt16, insecure: Bool) {
        self.host = host
        self.port = port
        self.insecure = insecure
    }

    // MARK: - Multiplexer

    var isClosed: Bool { poolLock.withLock { poolState == .closed } }
    var activeStreamCount: Int { poolLock.withLock { poolStreamCount } }
    var poolIsGoingAway: Bool { poolLock.withLock { poolState == .goingAway } }

    /// Atomically checks capacity and reserves a stream slot; accepts in-progress connections so a
    /// burst of requests coalesces behind one handshake. The caller MUST follow up with `perform`,
    /// which releases the reservation exactly once.
    func tryReserveStream() -> Bool {
        poolLock.withLock {
            switch poolState {
            case .idle, .connecting, .prefaceSent, .ready: break
            case .goingAway, .closed: return false
            }
            guard poolStreamCount < Int(poolMaxConcurrent) else { return false }
            poolReserved += 1
            poolStreamCount += 1
            return true
        }
    }

    private func releaseReservation() {
        poolLock.withLock { if poolReserved > 0 { poolReserved -= 1 } }
    }

    /// Must be called on `queue`.
    private func updatePoolSnapshot() {
        poolLock.withLock {
            poolState = state
            poolStreamCount = streams.count + poolReserved
            poolMaxConcurrent = maxConcurrentStreams
        }
    }

    // MARK: - Request entry point

    /// Runs one request/response on a new stream. A reservation must already have been made by the
    /// pool (see `tryReserveStream`); this releases it exactly once. `completion` fires once.
    func perform(
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<MITMScriptHTTPClient.Response, Error>) -> Void
    ) {
        queue.async { [self] in
            ensureReady { [weak self] result in
                guard let self else {
                    completion(.failure(MITMScriptHTTP2Error.notReady))
                    return
                }
                switch result {
                case .failure(let error):
                    self.releaseReservation()
                    self.updatePoolSnapshot()
                    completion(.failure(error))
                case .success:
                    let stream = MITMScriptHTTP2Stream(
                        streamID: self.allocateStreamID(),
                        connection: self,
                        request: request,
                        hostHeader: hostHeader,
                        maxBytes: maxBytes,
                        resourceTimeout: resourceTimeout,
                        completion: completion
                    )
                    self.streams[stream.streamID] = stream
                    self.releaseReservation()
                    self.updatePoolSnapshot()
                    stream.start()
                }
            }
        }
    }

    private func allocateStreamID() -> UInt32 {
        let id = nextStreamID
        nextStreamID &+= 2   // client streams are odd (RFC 7540 §5.1.1)
        return id
    }

    // MARK: - Setup

    /// Must be called on `queue`. Completion always fires on `queue`.
    private func ensureReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        switch state {
        case .ready:
            completion(.success(()))
        case .idle:
            readyCallbacks.append(completion)
            beginSetup()
        case .connecting, .prefaceSent:
            readyCallbacks.append(completion)
        case .goingAway, .closed:
            completion(.failure(negotiatedHTTP1 ? MITMScriptHTTP2Error.needsHTTP1Fallback
                                                : MITMScriptHTTP2Error.connectionClosed("connection closed")))
        }
    }

    private func beginSetup() {
        state = .connecting
        updatePoolSnapshot()
        // `OutboundConnector.dial` completes on the queue we pass.
        OutboundConnector.dial(host: host, port: port, queue: queue) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.failSetup(error)
            case .success(let dialed):
                self.dialed = dialed
                self.startTLS(dialed: dialed)
            }
        }
    }

    private func startTLS(dialed: OutboundConnector.Dialed) {
        let configuration = TLSConfiguration(serverName: host, alpn: ["h2", "http/1.1"], insecureSkipVerify: insecure)
        let client = TLSClient(configuration: configuration)
        tlsClient = client
        client.connect(overTunnel: dialed.connection) { [weak self] result in
            guard let self else { return }
            self.queue.async {
                guard self.state == .connecting else { return }
                switch result {
                case .failure(let error):
                    self.failSetup(error)
                case .success(let tlsConnection):
                    guard client.negotiatedALPN == "h2" else {
                        // HTTP/1.1-only origin: cache it and fail waiters over to the HTTP/1.1 path —
                        // one live connection can't serve N concurrent HTTP/1.1 exchanges.
                        self.negotiatedHTTP1 = true
                        self.onNegotiatedHTTP1?()
                        self.state = .closed
                        self.teardownTransport()
                        self.completeReadyCallbacks(.failure(MITMScriptHTTP2Error.needsHTTP1Fallback))
                        self.updatePoolSnapshot()
                        self.onClose?()
                        return
                    }
                    self.connection = TLSProxyConnection(tlsConnection: tlsConnection)
                    self.sendConnectionPreface()
                }
            }
        }
    }

    private func sendConnectionPreface() {
        guard let connection else { failSetup(MITMScriptHTTP2Error.notReady); return }
        var data = Data()
        data.append(Self.connectionPreface)
        data.append(NaiveHTTP2Framer.settingsFrame([
            (id: 0x1, value: Self.headerTableSize),
            (id: 0x2, value: 0),                                   // ENABLE_PUSH off
            (id: 0x3, value: Self.ownMaxConcurrentStreams),        // server-initiated streams (moot with push off)
            (id: 0x4, value: UInt32(Self.streamRecvWindow)),       // INITIAL_WINDOW_SIZE
            (id: 0x5, value: Self.maxFrameSize),
            (id: 0x6, value: UInt32(Self.maxHeaderListSize)),
        ]).serialized)
        let bump = UInt32(Self.connectionRecvWindow - Self.httpVersionDefaultWindow)
        data.append(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: bump).serialized)

        connection.send(data: data) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard self.state == .connecting else { return }
                if let error { self.failSetup(error); return }
                self.state = .prefaceSent
                self.updatePoolSnapshot()
                self.startReadLoop()
            }
        }
    }

    // MARK: - Read loop

    private func startReadLoop() {
        handleInbound()
        guard state != .closed else { return }
        readFromTransport { [weak self] error in
            guard let self else { return }
            if let error {
                self.handleSessionError(error)
                return
            }
            self.startReadLoop()
        }
    }

    /// Completion fires on `queue`.
    private func readFromTransport(_ completion: @escaping (Error?) -> Void) {
        guard let connection else { completion(MITMScriptHTTP2Error.notReady); return }
        connection.receive { [weak self] data, error in
            guard let self else { return }
            self.queue.async {
                if let error { completion(error); return }
                guard let data, !data.isEmpty else {
                    completion(MITMScriptHTTP2Error.connectionClosed("connection closed by peer"))
                    return
                }
                self.receiveBuffer.append(data)
                if self.receiveBuffer.count > Self.maxReceiveBufferSize {
                    // The loop drains fully each pass, so this only trips if a single frame is absurd.
                    completion(MITMScriptHTTP2Error.protocolError("receive buffer exceeded \(Self.maxReceiveBufferSize) bytes"))
                    return
                }
                completion(nil)
            }
        }
    }

    private func handleInbound() {
        while state != .closed, let frame = NaiveHTTP2Framer.deserialize(from: &receiveBuffer) {
            routeFrame(frame)
        }
        if receiveBuffer.isEmpty { receiveBuffer = Data() }   // release backing store
    }

    private func routeFrame(_ frame: NaiveHTTP2Frame) {
        // §6.10: an in-progress header block accepts only a CONTINUATION on the same stream.
        if let pending = pendingHeaders {
            guard frame.type == .continuation, frame.streamID == pending.streamID else {
                connectionError("expected CONTINUATION on stream \(pending.streamID)")
                return
            }
            appendContinuation(frame)
            return
        }

        switch frame.type {
        case .settings:
            handleSettings(frame)
        case .ping:
            if !frame.hasFlag(NaiveHTTP2FrameFlags.ack) {
                sendControlFrame(NaiveHTTP2Framer.pingAckFrame(opaqueData: frame.payload))
            }
        case .goaway:
            handleGoaway(frame)
        case .windowUpdate:
            handleWindowUpdate(frame)
        case .headers:
            beginHeaders(frame)
        case .data:
            handleData(frame)
        case .rstStream:
            if let stream = streams[frame.streamID] {
                streams.removeValue(forKey: stream.streamID)
                updatePoolSnapshot()
                let code = NaiveHTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                stream.handleReset(errorCode: code)
            }
        case .continuation:
            // CONTINUATION with no header block in progress is a connection error (§6.10).
            connectionError("unexpected CONTINUATION on stream \(frame.streamID)")
        }
    }

    // MARK: - HEADERS (connection-scoped decode)

    private func beginHeaders(_ frame: NaiveHTTP2Frame) {
        guard let fragment = strippedHeaderBlockFragment(frame) else {
            connectionError("malformed HEADERS framing")
            return
        }
        if frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
            completeHeaderBlock(streamID: frame.streamID, flags: frame.flags, block: fragment)
        } else {
            guard fragment.count <= Self.maxHeaderListSize else {
                connectionError("header block exceeds \(Self.maxHeaderListSize) bytes")
                return
            }
            pendingHeaders = (frame.streamID, frame.flags, fragment)
        }
    }

    private func appendContinuation(_ frame: NaiveHTTP2Frame) {
        guard var pending = pendingHeaders else { return }
        pending.block.append(frame.payload)
        guard pending.block.count <= Self.maxHeaderListSize else {
            connectionError("header block exceeds \(Self.maxHeaderListSize) bytes")
            return
        }
        if frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
            pendingHeaders = nil
            completeHeaderBlock(streamID: pending.streamID, flags: pending.flags, block: pending.block)
        } else {
            pendingHeaders = pending
        }
    }

    /// Decodes HPACK unconditionally, THEN routes the fields — never gate the decode on stream
    /// existence, or a finished/reset stream's HEADERS would desync the shared dynamic table.
    private func completeHeaderBlock(streamID: UInt32, flags: UInt8, block: Data) {
        guard let decoded = hpackDecoder.decodeHeaders(from: block) else {
            // A failed decode leaves the dynamic table in an unknown state — connection-fatal.
            connectionError("HPACK decode failed")
            return
        }
        let endStream = (flags & NaiveHTTP2FrameFlags.endStream) != 0
        streams[streamID]?.handleHeaders(fields: decoded.fields, endStream: endStream)
    }

    /// Removes leading pad-length + trailing padding (PADDED) and the 5 priority bytes (PRIORITY)
    /// so only the HPACK fragment reaches the decoder (RFC 7540 §6.2). Malformed framing → nil.
    private func strippedHeaderBlockFragment(_ frame: NaiveHTTP2Frame) -> Data? {
        var bytes = frame.payload[...]
        if frame.hasFlag(NaiveHTTP2FrameFlags.padded) {
            guard let padLength = bytes.first else { return nil }
            bytes = bytes.dropFirst()
            guard bytes.count >= Int(padLength) else { return nil }
            bytes = bytes.dropLast(Int(padLength))
        }
        if (frame.flags & Self.priorityFlag) != 0 {
            guard bytes.count >= 5 else { return nil }
            bytes = bytes.dropFirst(5)
        }
        return Data(bytes)
    }

    // MARK: - DATA (connection-scoped flow control)

    private func handleData(_ frame: NaiveHTTP2Frame) {
        // Credit the full payload (incl. padding) even for finished streams, or orphaned DATA
        // leaks connection flow-control credit until the whole connection stalls.
        creditConnectionRecvWindow(frame.payload.count)

        let endStream = frame.hasFlag(NaiveHTTP2FrameFlags.endStream)
        guard let stream = streams[frame.streamID] else { return }
        let body = Self.unpaddedDataPayload(frame)
        stream.handleData(body, fullPayloadCount: frame.payload.count, endStream: endStream)
    }

    private func creditConnectionRecvWindow(_ count: Int) {
        guard count > 0 else { return }
        connectionRecvConsumed += count
        if connectionRecvConsumed >= Self.connectionRecvWindow / 2 {
            let increment = UInt32(connectionRecvConsumed)
            connectionRecvConsumed = 0
            sendControlFrame(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment))
        }
    }

    /// Body payload with HTTP/2 DATA padding removed; flow control still counts the full payload.
    private static func unpaddedDataPayload(_ frame: NaiveHTTP2Frame) -> Data {
        guard frame.hasFlag(NaiveHTTP2FrameFlags.padded) else { return frame.payload }
        guard let padLength = frame.payload.first else { return Data() }
        let withoutPadByte = frame.payload.dropFirst()
        guard withoutPadByte.count >= Int(padLength) else { return Data(withoutPadByte) }
        return Data(withoutPadByte.dropLast(Int(padLength)))
    }

    // MARK: - Control-frame handlers

    private func handleSettings(_ frame: NaiveHTTP2Frame) {
        if frame.hasFlag(NaiveHTTP2FrameFlags.ack) { return }

        for (id, value) in NaiveHTTP2Framer.parseSettings(payload: frame.payload) {
            switch id {
            case 0x3: // MAX_CONCURRENT_STREAMS
                maxConcurrentStreams = min(Self.ownMaxConcurrentStreams, value)
            case 0x4: // INITIAL_WINDOW_SIZE
                let delta = Int(value) - peerInitialWindowSize
                peerInitialWindowSize = Int(value)
                for (_, stream) in streams { stream.adjustSendWindow(delta: delta) }
            default:
                break
            }
        }

        sendControlFrame(NaiveHTTP2Framer.settingsAckFrame())

        if state == .prefaceSent {
            state = .ready
            completeReadyCallbacks(.success(()))
        }
        updatePoolSnapshot()
    }

    private func handleGoaway(_ frame: NaiveHTTP2Frame) {
        let previous = state
        state = .goingAway
        updatePoolSnapshot()
        if let parsed = NaiveHTTP2Framer.parseGoaway(payload: frame.payload) {
            logger.warning("[MITMScriptHTTP2] GOAWAY lastStreamID=\(parsed.lastStreamID) errorCode=\(parsed.errorCode)")
            // Streams above lastStreamID were never processed by the peer — fail them.
            let doomed = streams.filter { $0.key > parsed.lastStreamID }
            for (id, stream) in doomed {
                streams.removeValue(forKey: id)
                stream.failFromSession(MITMScriptHTTP2Error.goaway)
            }
            updatePoolSnapshot()
        }
        if previous == .connecting || previous == .prefaceSent {
            completeReadyCallbacks(.failure(MITMScriptHTTP2Error.goaway))
        }
        if streams.isEmpty { close(error: MITMScriptHTTP2Error.goaway) }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload), increment > 0 else { return }
        if frame.streamID == 0 {
            let updated = connectionSendWindow + Int(increment)
            guard updated <= 0x7FFF_FFFF else { connectionError("connection send window overflow"); return }
            connectionSendWindow = updated
        } else if let stream = streams[frame.streamID] {
            stream.adjustSendWindow(delta: Int(increment))
        }
    }

    // MARK: - Sending (called by streams, on `queue`)

    /// The header block must fit one frame; we don't emit CONTINUATION on the send side.
    func sendHeaders(streamID: UInt32, headerBlock: Data, endStream: Bool, completion: @escaping (Error?) -> Void) {
        guard headerBlock.count <= Int(Self.maxFrameSize) else {
            completion(MITMScriptHTTP2Error.requestHeadersTooLarge)
            return
        }
        let frame = NaiveHTTP2Framer.headersFrame(streamID: streamID, headerBlock: headerBlock, endStream: endStream)
        sendRaw(frame.serialized, completion: completion)
    }

    /// Sends `data` as DATA frames, respecting connection + stream send windows and MAX_FRAME_SIZE.
    /// `completion` fires once when the whole body is sent or on error.
    func sendData(
        _ data: Data,
        on stream: MITMScriptHTTP2Stream,
        offset: Int = 0,
        endStream: Bool,
        completion: @escaping (Error?) -> Void
    ) {
        guard state == .ready || state == .goingAway else {
            completion(MITMScriptHTTP2Error.notReady); return
        }
        guard !stream.isFinished else {
            completion(MITMScriptHTTP2Error.streamReset(stream.streamID)); return
        }

        if offset >= data.count {
            if endStream {
                let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: Data(), endStream: true)
                sendRaw(frame.serialized, completion: completion)
            } else {
                completion(nil)
            }
            return
        }

        let maxByFlow = min(connectionSendWindow, stream.sendWindow)
        let chunkSize = min(data.count - offset, min(NaiveHTTP2Framer.maxDataPayload, maxByFlow))
        guard chunkSize > 0 else {
            // Window exhausted — wait for WINDOW_UPDATE and retry, bailing if the stream dies.
            queue.asyncAfter(deadline: .now() + .milliseconds(50)) { [weak self, weak stream] in
                guard let self, let stream, !stream.isFinished else {
                    completion(MITMScriptHTTP2Error.streamReset(stream?.streamID ?? 0)); return
                }
                self.sendData(data, on: stream, offset: offset, endStream: endStream, completion: completion)
            }
            return
        }

        connectionSendWindow -= chunkSize
        stream.consumeSendWindow(chunkSize)
        let start = data.startIndex + offset
        let chunk = data.subdata(in: start..<(start + chunkSize))
        let isLast = offset + chunkSize >= data.count
        let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk, endStream: endStream && isLast)
        sendRaw(frame.serialized) { [weak self, weak stream] error in
            guard let self else { return }
            self.queue.async {
                if let error { completion(error); return }
                guard let stream else { completion(MITMScriptHTTP2Error.notReady); return }
                if isLast { completion(nil) }
                else { self.sendData(data, on: stream, offset: offset + chunkSize, endStream: endStream, completion: completion) }
            }
        }
    }

    /// Fire-and-forget control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE, RST_STREAM).
    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        guard let connection else { return }
        connection.send(data: frame.serialized) { error in
            if let error { logger.debug("[MITMScriptHTTP2] control frame send failed: \(error.localizedDescription)") }
        }
    }

    private func sendRaw(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection else { completion(MITMScriptHTTP2Error.notReady); return }
        connection.send(data: data, completion: completion)
    }

    // MARK: - Stream teardown (called by streams on `queue`)

    /// Called by a stream as it finishes. Sends RST_STREAM(CANCEL) when the stream is abandoned
    /// before END_STREAM (timeout, cap, cancel) so the peer reclaims its slot; never on a clean end.
    func removeStream(_ stream: MITMScriptHTTP2Stream, sendRST: Bool) {
        guard streams.removeValue(forKey: stream.streamID) != nil else { return }
        if sendRST, state == .ready || state == .goingAway {
            sendControlFrame(NaiveHTTP2Framer.rstStreamFrame(streamID: stream.streamID, errorCode: 0x8 /* CANCEL */))
        }
        updatePoolSnapshot()
        if state == .goingAway, streams.isEmpty {
            close(error: MITMScriptHTTP2Error.goaway)
        }
    }

    // MARK: - Errors / teardown

    private func connectionError(_ message: String) {
        logger.warning("[MITMScriptHTTP2] \(message)")
        handleSessionError(MITMScriptHTTP2Error.protocolError(message))
    }

    private func handleSessionError(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        teardownTransport()
        completeReadyCallbacks(.failure(error))
        let victims = streams
        streams.removeAll()
        pendingHeaders = nil
        updatePoolSnapshot()
        for (_, stream) in victims { stream.failFromSession(error) }
        onClose?()
    }

    private func failSetup(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        teardownTransport()
        completeReadyCallbacks(.failure(error))
        updatePoolSnapshot()
        onClose?()
    }

    private func completeReadyCallbacks(_ result: Result<Void, Error>) {
        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for callback in callbacks { callback(result) }
    }

    /// The TLS wrapper, TLS client, and dialed proxy transport are separate objects —
    /// cancel all three or the pooled connection leaks a socket.
    private func teardownTransport() {
        if let connection {
            connection.cancel()
        } else {
            dialed?.connection.cancel()   // TLS never wrapped it (setup failed early)
        }
        tlsClient?.cancel()
        dialed?.proxyClient?.cancel()
        connection = nil
        tlsClient = nil
        dialed = nil
    }

    // MARK: - Multiplexer.close

    func close(error: Error?) {
        queue.async { [self] in
            guard state != .closed else { return }
            let reason = error ?? MITMScriptHTTP2Error.connectionClosed("connection closed")
            state = .closed
            teardownTransport()
            completeReadyCallbacks(.failure(reason))
            let victims = streams
            streams.removeAll()
            pendingHeaders = nil
            updatePoolSnapshot()
            for (_, stream) in victims { stream.failFromSession(reason) }
            onClose?()
        }
    }
}
