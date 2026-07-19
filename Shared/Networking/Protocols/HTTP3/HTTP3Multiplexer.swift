//
//  HTTP3Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HTTP3Multiplexer")

nonisolated final class HTTP3Multiplexer: Multiplexer, Sendable {

    // MARK: - State

    enum SessionState {
        case idle, connecting, ready, draining, closed
    }

    /// Per-stream event sinks, registered with ``openStream(events:)``. Invoked
    /// synchronously on the ngtcp2 bridge queue from the QUIC demux path; `data` receives a
    /// zero-copy view into ngtcp2's buffer, so sinks must consume (copy) it before returning.
    struct StreamEvents: Sendable {
        /// Raw HTTP/3 stream payload; `fin` marks the read-side EOF.
        let data: @Sendable (Data, Bool) -> Void
        /// Terminal stream/session failure.
        let error: @Sendable (Error) -> Void
    }

    // MARK: - Properties

    private let quic: QUICConnection

    /// Session + demux state, guarded by `lock`. Never held across a call into a stream sink,
    /// a QUIC write, or a continuation resume; effects are computed under the lock and
    /// performed after it is released.
    private struct Session {
        var state: SessionState = .idle

        var streams: [Int64: StreamEvents] = [:]

        var serverControlStreamID: Int64?
        var serverControlBuffer = Data()
        /// Tracks server-initiated streams whose type byte hasn't been classified yet.
        var pendingServerStreams: [Int64: Data] = [:]
        /// RFC 9114 §7.2.4: SETTINGS MUST be the first frame on the control stream.
        var serverSettingsReceived = false

        /// Peer-advertised MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2). UInt64.max = unlimited.
        var peerMaxFieldSectionSize: UInt64 = UInt64.max

        /// RFC 9220: true when the peer allows extended CONNECT with a `:protocol` pseudo-header.
        var peerSupportsExtendedConnect = false

        /// RFC 9297: true when the peer enables H3_DATAGRAM (required for CONNECT-UDP).
        var peerSupportsH3Datagram = false
    }
    private let lock = Mutex(Session())

    /// Readiness latch: the ready/teardown path finishes `readySignal` (throwing on failure);
    /// every awaiter gets that one outcome via `readyTask.value` (broadcast, cached once resolved).
    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    /// Peer-advertised MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2). UInt64.max = unlimited.
    var peerMaxFieldSectionSize: UInt64 { lock.withLock { $0.peerMaxFieldSectionSize } }

    /// RFC 9220: true when the peer allows extended CONNECT with a `:protocol` pseudo-header.
    var peerSupportsExtendedConnect: Bool { lock.withLock { $0.peerSupportsExtendedConnect } }

    /// RFC 9297: true when the peer enables H3_DATAGRAM (required for CONNECT-UDP).
    var peerSupportsH3Datagram: Bool { lock.withLock { $0.peerSupportsH3Datagram } }

    // Pool-visible state behind its own mutex, read by the pool from arbitrary threads.
    // Only ever taken sequentially with `lock` (never nested), so the two can't deadlock.
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

    var isClosed: Bool {
        _poolState.withLock { $0.isClosed }
    }

    /// True when ngtcp2 signals STREAM_ID_BLOCKED; the pool creates a new multiplexer instead.
    var poolIsStreamBlocked: Bool {
        _poolState.withLock { $0.isStreamBlocked }
    }

    var hasActiveStreams: Bool {
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
    func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        _poolState.withLock { $0.onClose = hook }
    }

    func tryReserveStream() -> Bool {
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
    func forceReserveStream() -> Bool {
        _poolState.withLock { state in
            guard !state.isClosed && !state.isStreamBlocked else { return false }
            state.reservedStreams += 1
            return true
        }
    }

    var activeStreamCount: Int {
        _poolState.withLock { $0.streamCount + $0.reservedStreams }
    }

    /// Converts a reserved slot into an active stream. Non-pooled callers skip this.
    func noteStreamStarted() {
        _poolState.withLock { state in
            state.reservedStreams = max(0, state.reservedStreams - 1)
            state.streamCount += 1
        }
    }

    // MARK: - Stream Creation

    /// Opens a bidirectional QUIC stream and registers its event sinks in one hop on the ngtcp2
    /// queue — the demux runs on that same queue, so no demuxed byte can fall between the open
    /// and the registration. Returns `nil` — after recording the STREAM_ID_BLOCKED pool
    /// signal — when ngtcp2 has no stream credit.
    func openStream(events: StreamEvents) async -> Int64? {
        await quic.run { () -> Int64? in
            guard let sid = self.quic.openBidiStream() else {
                self.markStreamBlocked()
                return nil
            }
            self.lock.withLock { $0.streams[sid] = events }
            return sid
        }
    }

    func removeStream(_ streamID: Int64) {
        let (removed, shouldClose): (Bool, Bool) = lock.withLock { session in
            let removed = session.streams.removeValue(forKey: streamID) != nil
            let shouldClose = session.state == .draining && session.streams.isEmpty
            return (removed, shouldClose)
        }
        if removed {
            _poolState.withLock { $0.streamCount = max(0, $0.streamCount - 1) }
        }
        if shouldClose {
            close()
        }
    }

    /// Called when openBidiStream fails (STREAM_ID_BLOCKED).
    func markStreamBlocked() {
        _poolState.withLock { state in
            state.isStreamBlocked = true
            state.streamCount = max(0, state.streamCount - 1)
        }
    }

    // MARK: - Connection Lifecycle

    /// Coalesces awaiters behind one connect; resolves at `.ready` or on fail/close.
    func ensureReady() async throws {
        enum Action { case ready; case park; case beginAndPark; case drainingFail; case closedFail }
        let action: Action = lock.withLock { session in
            switch session.state {
            case .ready:
                return .ready
            case .draining:
                return .drainingFail
            case .closed:
                return .closedFail
            case .connecting:
                return .park
            case .idle:
                session.state = .connecting
                return .beginAndPark
            }
        }
        switch action {
        case .ready:
            return
        case .drainingFail:
            throw AnywhereError.proxy(.http3, .connectionClosed(detail: "Session draining (GOAWAY)"))
        case .closedFail:
            throw AnywhereError.proxy(.http3, .connectionClosed(detail: "Session closed"))
        case .beginAndPark:
            startConnection()
            // Resolves on `.ready` (success) or teardown (fail/close).
            try await readyTask.value
        case .park:
            try await readyTask.value
        }
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        // Both handlers fire on the bridge queue and route into the Mutex-guarded paths.
        // Installed before the connect so no demuxed byte (and no eager close) can beat them;
        // `connectionClosed` drains pool entries eagerly so no new streams go to a dead multiplexer.
        quic.handlers.withLock { handlers in
            handlers.connectionClosed = { [weak self] error in
                self?.failSession(error)
            }
            handlers.streamData = { [weak self] streamID, data, fin in
                self?.handleStreamData(streamID: streamID, data: data, fin: fin)
            }
        }

        // Strong `self`: the connect task owns the multiplexer until it resolves, so a
        // pooled instance can't deallocate mid-handshake and leak the ngtcp2 state.
        Task { [self] in
            do {
                try await quic.connect()
            } catch {
                failSession(error)
                return
            }
            // Control/QPACK stream opens assert on-queue; one hop for the whole batch.
            await quic.run { self.openControlStreams() }

            let becameReady: Bool = lock.withLock { session in
                guard session.state == .connecting else { return false }
                session.state = .ready
                return true
            }
            if becameReady {
                readySignal.finish()
            }
        }
    }

    /// Must run on the ngtcp2 queue (the stream opens and writes assert it).
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
    func writeStream(_ streamID: Int64, data: Data, fin: Bool = false) async throws {
        try await quic.writeStream(streamID, data: data, fin: fin)
    }

    /// Extends flow control once the app consumes data; safe from any context (hops internally).
    func extendStreamOffset(_ streamID: Int64, count: Int) {
        quic.extendStreamOffset(streamID, count: count)
    }

    /// Sends RESET_STREAM + STOP_SENDING; safe from any context (hops internally).
    func shutdownStream(_ streamID: Int64, code: HTTP3ErrorCode = .noError) {
        quic.shutdownStream(streamID, appErrorCode: code.rawValue)
    }

    // MARK: - Stream Data Demux

    /// One deferred effect of a demux pass, computed under `lock` and performed after it
    /// is released (`failSession`/`close`/stream shutdown all re-take locks).
    private enum DemuxEffect {
        case fail(Error)
        case goaway(activeStreams: Int, shouldClose: Bool)
        case abortStream(Int64, HTTP3ErrorCode)
    }

    /// Runs synchronously on the bridge queue from the QUIC demux path; `data` is a zero-copy
    /// view into ngtcp2's buffer, consumed (copied/appended) before this returns.
    private func handleStreamData(streamID: Int64, data: Data, fin: Bool) {
        // Registered stream: snapshot the sink under the lock, dispatch outside it.
        if let sink = lock.withLock({ $0.streams[streamID] }) {
            sink.data(data, fin)
            return
        }

        // Server-initiated unidirectional streams (odd stream IDs with bit 1 set)
        let isServerUni = (streamID & 0x03) == 0x03
        guard isServerUni, !data.isEmpty else { return }

        // Server-initiated stream data is consumed immediately, so extend flow
        // control right away — otherwise connection-level credits leak permanently.
        quic.extendStreamOffset(streamID, count: data.count)

        let effects: [DemuxEffect] = lock.withLock { session in
            if streamID == session.serverControlStreamID {
                session.serverControlBuffer.append(data)
                return Self.processServerControlFrames(&session)
            }

            var buffer = session.pendingServerStreams.removeValue(forKey: streamID) ?? Data()
            buffer.append(data)
            guard !buffer.isEmpty else { return [] }
            let streamType = buffer[buffer.startIndex]
            switch streamType {
            case 0x00: // Control stream (RFC 9114 §6.2.1)
                guard session.serverControlStreamID == nil else {
                    // RFC 9114 §6.2.1: a second control stream is H3_STREAM_CREATION_ERROR.
                    return [.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Duplicate server control stream")))]
                }
                session.serverControlStreamID = streamID
                session.serverControlBuffer = Data(buffer.dropFirst())
                return Self.processServerControlFrames(&session)
            case 0x01: // Push (RFC 9114 §6.2.2) — we never send MAX_PUSH_ID
                return [.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Server opened push stream without MAX_PUSH_ID")))]
            case 0x02, 0x03: // QPACK encoder / decoder (RFC 9204 §4.2)
                // We advertised QPACK_MAX_TABLE_CAPACITY=0; drain silently.
                return []
            default:
                // RFC 9114 §6.2: tolerate reserved grease types (0x1f * N + 0x21);
                // abort anything else with STOP_SENDING.
                if !Self.isReservedStreamType(streamType) {
                    return [.abortStream(streamID, .streamCreationError)]
                }
                return []
            }
        }

        perform(effects)
    }

    private func perform(_ effects: [DemuxEffect]) {
        for effect in effects {
            switch effect {
            case .fail(let error):
                failSession(error)
            case .goaway(let activeStreams, let shouldClose):
                _poolState.withLock { $0.isStreamBlocked = true }
                logger.debug("[HTTP3Multiplexer] Received GOAWAY, draining \(activeStreams) active streams")
                if shouldClose {
                    close()
                }
                // Existing streams continue to completion; removeStream() closes when the last one finishes.
            case .abortStream(let streamID, let code):
                quic.shutdownStream(streamID, appErrorCode: code.rawValue)
            }
        }
    }

    /// RFC 9114 §7.2.9 reserved stream type grease values.
    private static func isReservedStreamType(_ streamType: UInt8) -> Bool {
        streamType >= 0x21 && (UInt64(streamType) - 0x21) % 0x1f == 0
    }

    /// Parses frames on the server's control stream. RFC 9114 §7.2.4: SETTINGS
    /// must be the first frame, else H3_MISSING_SETTINGS. Must be called with `lock`
    /// held; a `.fail` outcome ends the pass (the session is torn down off-lock).
    private static func processServerControlFrames(_ session: inout Session) -> [DemuxEffect] {
        var effects: [DemuxEffect] = []
        while !session.serverControlBuffer.isEmpty {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: session.serverControlBuffer) else {
                break
            }
            session.serverControlBuffer = Data(session.serverControlBuffer.dropFirst(consumed))

            if !session.serverSettingsReceived {
                guard frame.type == HTTP3FrameType.settings.rawValue else {
                    effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "First control-stream frame was not SETTINGS"))))
                    return effects
                }
                session.serverSettingsReceived = true
                if !parseServerSettings(frame.payload, into: &session) {
                    effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Malformed SETTINGS frame"))))
                    return effects
                }
                continue
            }

            switch frame.type {
            case HTTP3FrameType.goaway.rawValue:
                // Second GOAWAY while already draining is ignored (state guard).
                if session.state == .ready {
                    session.state = .draining
                    effects.append(.goaway(activeStreams: session.streams.count,
                                           shouldClose: session.streams.isEmpty))
                }
            case HTTP3FrameType.settings.rawValue:
                // Only one SETTINGS frame is permitted (RFC 9114 §7.2.4).
                effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Duplicate SETTINGS frame"))))
                return effects
            case HTTP3FrameType.data.rawValue,
                 HTTP3FrameType.headers.rawValue,
                 HTTP3FrameType.pushPromise.rawValue:
                // Forbidden on the control stream (RFC 9114 §7.2.1/§7.2.2/§7.2.5): H3_FRAME_UNEXPECTED.
                effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Forbidden frame type \(frame.type) on control stream"))))
                return effects
            default:
                break
            }
        }
        return effects
    }

    /// Parses the server's SETTINGS payload into `session`. Returns false if malformed.
    private static func parseServerSettings(_ payload: Data, into session: inout Session) -> Bool {
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
                session.peerMaxFieldSectionSize = value
            case HTTP3SettingsID.enableConnectProtocol.rawValue:
                // RFC 9220 §3: only 0 or 1 are valid.
                guard value == 0 || value == 1 else { return false }
                session.peerSupportsExtendedConnect = (value == 1)
            case HTTP3SettingsID.h3Datagram.rawValue:
                // RFC 9297 §2.1: only 0 or 1 are valid.
                guard value == 0 || value == 1 else { return false }
                session.peerSupportsH3Datagram = (value == 1)
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

    // MARK: - Close

    /// Idempotent; the pool-visible `isClosed` flips before this returns, so no new
    /// streams are handed out afterwards.
    func close(error: Error? = nil) {
        failSession(error ?? AnywhereError.proxy(.http3, .connectionClosed(detail: "Session closed")))
    }

    /// Central teardown: flips to `.closed`, fails every waiter and live stream, and
    /// closes the QUIC connection. Idempotent.
    private func failSession(_ error: Error) {
        let victims: [StreamEvents]? = lock.withLock { session in
            guard session.state != .closed else { return nil }
            session.state = .closed
            let victims = Array(session.streams.values)
            session.streams.removeAll()
            return victims
        }
        guard let victims else { return }

        let onClose = _poolState.withLock { state in
            state.isClosed = true
            state.streamCount = 0
            state.reservedStreams = 0
            let hook = state.onClose
            state.onClose = nil
            return hook
        }

        readySignal.finish(throwing: error)

        for sink in victims {
            sink.error(error)
        }

        quic.close()
        onClose?()
    }
}
