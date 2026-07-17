//
//  HTTP3Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HTTP3Multiplexer")

actor HTTP3Multiplexer {

    nonisolated var unownedExecutor: UnownedSerialExecutor { quic.unownedExecutor }

    // MARK: - State

    enum SessionState {
        case idle, connecting, ready, draining, closed
    }

    /// Per-stream event sinks, registered with ``openStream(events:)``. Invoked
    /// synchronously on the multiplexer's executor from the QUIC demux path; a stream
    /// actor on the same executor enters its isolation via `assumeIsolated` inside these.
    struct StreamEvents: Sendable {
        /// Raw HTTP/3 stream payload; `fin` marks the read-side EOF.
        let data: @Sendable (Data, Bool) -> Void
        /// Terminal stream/session failure.
        let error: @Sendable (Error) -> Void
    }

    // MARK: - Properties

    private let quic: QUICConnection

    /// The ngtcp2 boundary object whose executor this multiplexer (and its streams) adopt.
    /// Vended so per-request stream actors can join the same isolation domain.
    nonisolated var sharedBridge: NGTCP2ConcurrencyBridge { quic.bridge }

    private var state: SessionState = .idle

    private var streams: [Int64: StreamEvents] = [:]
    /// Readiness latch: the ready/teardown path finishes `readySignal` (throwing on failure);
    /// every awaiter gets that one outcome via `readyTask.value` (broadcast, cached once resolved).
    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    private var serverControlStreamID: Int64?
    private var serverControlBuffer = Data()
    /// Tracks server-initiated streams whose type byte hasn't been classified yet.
    private var pendingServerStreams: [Int64: Data] = [:]
    /// RFC 9114 §7.2.4: SETTINGS MUST be the first frame on the control stream.
    private var serverSettingsReceived = false

    /// Peer-advertised MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2). UInt64.max = unlimited.
    private(set) var peerMaxFieldSectionSize: UInt64 = UInt64.max

    /// RFC 9220: true when the peer allows extended CONNECT with a `:protocol` pseudo-header.
    private(set) var peerSupportsExtendedConnect = false

    /// RFC 9297: true when the peer enables H3_DATAGRAM (required for CONNECT-UDP).
    private(set) var peerSupportsH3Datagram = false

    // Pool-visible state, read under `_poolState` from arbitrary threads; must not
    // touch `streams` or other executor-protected state.
    private struct PoolState {
        var isClosed = false
        /// True when ngtcp2 signals STREAM_ID_BLOCKED; the pool creates a new multiplexer instead.
        var isStreamBlocked = false
        var streamCount = 0
        var reservedStreams = 0
        /// Pool eviction hook, fired exactly once on close.
        var onClose: (@Sendable () -> Void)?
    }
    private let _poolState = Mutex(PoolState())
    /// Must match `QUICTuning.naive.initialMaxStreamsBidi`; undersizing forces premature multiplexer churn.
    private let maxConcurrentStreams = 512

    nonisolated var isClosed: Bool {
        _poolState.withLock { $0.isClosed }
    }

    /// True when ngtcp2 signals STREAM_ID_BLOCKED; the pool creates a new multiplexer instead.
    nonisolated var poolIsStreamBlocked: Bool {
        _poolState.withLock { $0.isStreamBlocked }
    }

    nonisolated var hasActiveStreams: Bool {
        _poolState.withLock { $0.streamCount > 0 || $0.reservedStreams > 0 }
    }

    // MARK: - Init

    /// - Parameter transport: When set, QUIC rides the relay transport instead of the
    ///   direct UDP carrier; `host`/`port` identify the server logically, not a dial target.
    init(host: String, port: UInt16, serverName: String, tuning: QUICTuning = .naive,
         transport: QUICDatagramTransport? = nil) {
        self.quic = QUICConnection(host: host, port: port, serverName: serverName,
                                   alpn: ["h3"], tuning: tuning, transport: transport)
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
    }

    // MARK: - Pool Interface

    /// Installs the pool's eviction hook; fired exactly once when the session closes.
    nonisolated func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        _poolState.withLock { $0.onClose = hook }
    }

    nonisolated func tryReserveStream() -> Bool {
        _poolState.withLock { state in
            guard !state.isClosed && !state.isStreamBlocked else { return false }
            let count = state.streamCount + state.reservedStreams
            guard count < maxConcurrentStreams else { return false }
            state.reservedStreams += 1
            return true
        }
    }

    /// Reserves a slot bypassing `maxConcurrentStreams` when the pool is at its hard
    /// cap; ngtcp2's STREAM_ID_BLOCKED and the caller's retry path handle backpressure.
    nonisolated func forceReserveStream() -> Bool {
        _poolState.withLock { state in
            guard !state.isClosed && !state.isStreamBlocked else { return false }
            state.reservedStreams += 1
            return true
        }
    }

    nonisolated var activeStreamCount: Int {
        _poolState.withLock { $0.streamCount + $0.reservedStreams }
    }

    /// Converts a reserved slot into an active stream. Non-pooled callers skip this.
    nonisolated func noteStreamStarted() {
        _poolState.withLock { state in
            state.reservedStreams = max(0, state.reservedStreams - 1)
            state.streamCount += 1
        }
    }

    // MARK: - Stream Creation

    /// Opens a bidirectional QUIC stream and registers its event sinks in one isolated step,
    /// so no demuxed byte can fall between the open and the registration. Returns `nil` —
    /// after recording the STREAM_ID_BLOCKED pool signal — when ngtcp2 has no stream credit.
    func openStream(events: StreamEvents) -> Int64? {
        guard let sid = quic.openBidiStream() else {
            markStreamBlocked()
            return nil
        }
        streams[sid] = events
        return sid
    }

    func removeStream(_ streamID: Int64) {
        if streams.removeValue(forKey: streamID) != nil {
            _poolState.withLock { $0.streamCount = max(0, $0.streamCount - 1) }
        }

        if state == .draining && streams.isEmpty {
            close()
        }
    }

    /// Called when openBidiStream fails (STREAM_ID_BLOCKED).
    nonisolated func markStreamBlocked() {
        _poolState.withLock { state in
            state.isStreamBlocked = true
            state.streamCount = max(0, state.streamCount - 1)
        }
    }

    // MARK: - Connection Lifecycle

    /// Coalesces awaiters behind one connect; resolves at `.ready` or on fail/close.
    func ensureReady() async throws {
        switch state {
        case .ready:
            return
        case .draining:
            throw HTTP3Error.connectionFailed("Session draining (GOAWAY)")
        case .closed:
            throw HTTP3Error.connectionFailed("Session closed")
        case .connecting:
            break
        case .idle:
            state = .connecting
            startConnection()
        }
        // Resolves on `.ready` (success) or teardown (fail/close).
        try await readyTask.value
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        // Drain pool entries eagerly on close so no new streams go to a dead multiplexer.
        quic.handlers.withLock { handlers in
            handlers.connectionClosed = { [weak self] error in
                self?.assumeIsolated { $0.failSession(error) }
            }
        }

        // Strong `self`: the connect task owns the multiplexer until it resolves, so a
        // pooled instance can't deallocate mid-handshake and leak the ngtcp2 state. Explicit
        // `[self]` so the deliberately-weak capture in the stored QUIC handler below reads as intentional.
        Task { [self] in
            do {
                try await quic.connect()
            } catch {
                failSession(error)
                return
            }
            openControlStreams()

            quic.handlers.withLock { handlers in
                handlers.streamData = { [weak self] streamID, data, fin in
                    self?.assumeIsolated { $0.handleStreamData(streamID: streamID, data: data, fin: fin) }
                }
            }

            state = .ready
            readySignal.finish()
        }
    }

    private func openControlStreams() {
        // HTTP/3 control stream (type 0x00) + SETTINGS
        if let sid = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00)
            payload.append(HTTP3Framer.clientSettingsFrame())
            quic.writeStreamOnQueue(sid, data: payload)
        }
        // QPACK encoder (type 0x02) and decoder (type 0x03)
        if let sid = quic.openUniStream() {
            quic.writeStreamOnQueue(sid, data: Data([0x02]))
        }
        if let sid = quic.openUniStream() {
            quic.writeStreamOnQueue(sid, data: Data([0x03]))
        }
    }

    // MARK: - Stream Operations

    /// Async stream write, forwarding to the QUIC ngtcp2-boundary continuation.
    nonisolated func writeStream(_ streamID: Int64, data: Data, fin: Bool = false) async throws {
        try await quic.writeStream(streamID, data: data, fin: fin)
    }

    /// Extends flow control once the app consumes data; safe from any context (hops internally).
    nonisolated func extendStreamOffset(_ streamID: Int64, count: Int) {
        quic.extendStreamOffset(streamID, count: count)
    }

    /// Sends RESET_STREAM + STOP_SENDING; safe from any context (hops internally).
    nonisolated func shutdownStream(_ streamID: Int64, code: HTTP3ErrorCode = .noError) {
        quic.shutdownStream(streamID, appErrorCode: code.rawValue)
    }

    // MARK: - Stream Data Demux

    private func handleStreamData(streamID: Int64, data: Data, fin: Bool) {
        if let stream = streams[streamID] {
            stream.data(data, fin)
            return
        }

        // Server-initiated unidirectional streams (odd stream IDs with bit 1 set)
        let isServerUni = (streamID & 0x03) == 0x03
        guard isServerUni, !data.isEmpty else { return }

        // Server-initiated stream data is consumed immediately, so extend flow
        // control right away — otherwise connection-level credits leak permanently.
        quic.extendStreamOffset(streamID, count: data.count)

        if streamID == serverControlStreamID {
            serverControlBuffer.append(data)
            processServerControlFrames()
        } else {
            var buffer = pendingServerStreams.removeValue(forKey: streamID) ?? Data()
            buffer.append(data)
            guard !buffer.isEmpty else { return }
            let streamType = buffer[buffer.startIndex]
            switch streamType {
            case 0x00: // Control stream (RFC 9114 §6.2.1)
                guard serverControlStreamID == nil else {
                    // RFC 9114 §6.2.1: a second control stream is H3_STREAM_CREATION_ERROR.
                    failSession(HTTP3Error.connectionFailed("Duplicate server control stream"))
                    return
                }
                serverControlStreamID = streamID
                serverControlBuffer = Data(buffer.dropFirst())
                processServerControlFrames()
            case 0x01: // Push (RFC 9114 §6.2.2) — we never send MAX_PUSH_ID
                failSession(HTTP3Error.connectionFailed("Server opened push stream without MAX_PUSH_ID"))
            case 0x02, 0x03: // QPACK encoder / decoder (RFC 9204 §4.2)
                // We advertised QPACK_MAX_TABLE_CAPACITY=0; drain silently.
                break
            default:
                // RFC 9114 §6.2: tolerate reserved grease types (0x1f * N + 0x21);
                // abort anything else with STOP_SENDING.
                if !isReservedStreamType(streamType) {
                    quic.shutdownStream(streamID, appErrorCode: HTTP3ErrorCode.streamCreationError.rawValue)
                }
            }
        }
    }

    /// RFC 9114 §7.2.9 reserved stream type grease values.
    private func isReservedStreamType(_ streamType: UInt8) -> Bool {
        streamType >= 0x21 && (UInt64(streamType) - 0x21) % 0x1f == 0
    }

    /// Parses frames on the server's control stream. RFC 9114 §7.2.4: SETTINGS
    /// must be the first frame, else H3_MISSING_SETTINGS.
    private func processServerControlFrames() {
        while !serverControlBuffer.isEmpty {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: serverControlBuffer) else {
                break
            }
            serverControlBuffer = Data(serverControlBuffer.dropFirst(consumed))

            if !serverSettingsReceived {
                guard frame.type == HTTP3FrameType.settings.rawValue else {
                    failSession(HTTP3Error.connectionFailed("First control-stream frame was not SETTINGS"))
                    return
                }
                serverSettingsReceived = true
                if !parseServerSettings(frame.payload) {
                    failSession(HTTP3Error.connectionFailed("Malformed SETTINGS frame"))
                    return
                }
                continue
            }

            switch frame.type {
            case HTTP3FrameType.goaway.rawValue:
                handleGoaway(frame.payload)
            case HTTP3FrameType.settings.rawValue:
                // Only one SETTINGS frame is permitted (RFC 9114 §7.2.4).
                failSession(HTTP3Error.connectionFailed("Duplicate SETTINGS frame"))
                return
            case HTTP3FrameType.data.rawValue,
                 HTTP3FrameType.headers.rawValue,
                 HTTP3FrameType.pushPromise.rawValue:
                // Forbidden on the control stream (RFC 9114 §7.2.1/§7.2.2/§7.2.5): H3_FRAME_UNEXPECTED.
                failSession(HTTP3Error.connectionFailed("Forbidden frame type \(frame.type) on control stream"))
                return
            default:
                break
            }
        }
    }

    /// Parses the server's SETTINGS payload. Returns false if malformed.
    private func parseServerSettings(_ payload: Data) -> Bool {
        var offset = 0
        var seen = Set<UInt64>()
        while offset < payload.count {
            guard let (id, idLen) = QUICVarInt.decode(from: payload, offset: offset) else {
                return false
            }
            offset += idLen
            guard let (value, valLen) = QUICVarInt.decode(from: payload, offset: offset) else {
                return false
            }
            offset += valLen

            // RFC 9114 §7.2.4: the same identifier MUST NOT occur more than once.
            if !seen.insert(id).inserted { return false }

            switch id {
            case HTTP3SettingsID.maxFieldSectionSize.rawValue:
                peerMaxFieldSectionSize = value
            case HTTP3SettingsID.enableConnectProtocol.rawValue:
                // RFC 9220 §3: only 0 or 1 are valid.
                guard value == 0 || value == 1 else { return false }
                peerSupportsExtendedConnect = (value == 1)
            case HTTP3SettingsID.h3Datagram.rawValue:
                // RFC 9297 §2.1: only 0 or 1 are valid.
                guard value == 0 || value == 1 else { return false }
                peerSupportsH3Datagram = (value == 1)
            case HTTP3SettingsID.qpackMaxTableCapacity.rawValue,
                 HTTP3SettingsID.qpackBlockedStreams.rawValue:
                break // Dynamic table not used; no reaction needed.
            default:
                break
            }
        }
        return true
    }

    /// RFC 9114 §4.2.2: Σ(name + value + 32) octets over all fields must fit the peer's limit.
    func isWithinPeerFieldSectionLimit(_ headers: [(name: String, value: String)]) -> Bool {
        let limit = peerMaxFieldSectionSize
        if limit == UInt64.max { return true }
        var total: UInt64 = 0
        for header in headers {
            total = total &+ UInt64(header.name.utf8.count) &+ UInt64(header.value.utf8.count) &+ 32
            if total > limit { return false }
        }
        return true
    }

    private func handleGoaway(_ payload: Data) {
        guard state == .ready else { return }
        state = .draining

        _poolState.withLock { $0.isStreamBlocked = true }

        logger.debug("[HTTP3Multiplexer] Received GOAWAY, draining \(streams.count) active streams")

        if streams.isEmpty {
            close()
        }
        // Existing streams continue to completion; removeStream() closes when the last one finishes.
    }

    // MARK: - Close

    nonisolated func close(error: Error? = nil) {
        // Strong `self`: a weakly-captured pooled multiplexer could deallocate before
        // this runs, skipping `quic.close()` and leaking the socket + ngtcp2 state.
        // Synchronous on the executor so pool state updates before new streams are handed out.
        quic.enqueue { self.assumeIsolated { $0.failSession(error ?? HTTP3Error.connectionFailed("Session closed")) } }
    }

    private func failSession(_ error: Error) {
        guard state != .closed else { return }
        state = .closed

        let onClose = _poolState.withLock { state in
            state.isClosed = true
            state.streamCount = 0
            state.reservedStreams = 0
            let hook = state.onClose
            state.onClose = nil
            return hook
        }

        readySignal.finish(throwing: error)

        let activeStreams = Array(streams.values)
        streams.removeAll()
        for stream in activeStreams {
            stream.error(error)
        }

        quic.close()
        onClose?()
    }
}

extension HTTP3Multiplexer: Multiplexer {}
