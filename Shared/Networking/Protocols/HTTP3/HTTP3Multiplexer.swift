//
//  HTTP3Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP3Multiplexer")

// MARK: - HTTP3StreamHandler

/// Per-stream handler to which the multiplexer demuxes QUIC stream data and
/// connection-level errors.
protocol HTTP3StreamHandler: AnyObject {
    // Requirements are nonisolated: handlers run on the QUICConnection's serial
    // queue, never the main actor (the project default isolation).

    /// The assigned QUIC stream ID, or nil before one has been opened.
    nonisolated var quicStreamID: Int64? { get }
    /// Delivers raw QUIC stream payload (HTTP/3 frames). Called on the multiplexer queue.
    nonisolated func handleStreamData(_ data: Data, fin: Bool)
    /// Signals that the multiplexer failed or closed. Called on the multiplexer queue.
    nonisolated func handleSessionError(_ error: Error)
}

nonisolated class HTTP3Multiplexer: Multiplexer {

    // MARK: - State

    enum SessionState {
        case idle, connecting, ready, draining, closed
    }

    // MARK: - Properties

    private let quic: QUICConnection
    /// Shares the QUICConnection's serial queue to avoid cross-queue dispatch on the hot receive path.
    var queue: DispatchQueue { quic.queue }

    var isOnQueue: Bool { quic.isOnQueue }

    private var state: SessionState = .idle

    private var streams: [Int64: any HTTP3StreamHandler] = [:]
    private var readyCallbacks: [(Error?) -> Void] = []
    var onClose: (() -> Void)?

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

    // Pool-visible state, accessed under _poolLock from arbitrary threads; must not
    // touch `streams` or other queue-protected state.
    private let _poolLock = UnfairLock()
    private(set) var isClosed = false
    /// True when ngtcp2 signals STREAM_ID_BLOCKED; the pool creates a new multiplexer instead.
    private(set) var poolIsStreamBlocked = false
    private var _poolStreamCount = 0
    private var _reservedStreams = 0
    /// Must match `QUICTuning.naive.initialMaxStreamsBidi`; undersizing forces premature multiplexer churn.
    private let maxConcurrentStreams = 512

    var hasActiveStreams: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolStreamCount > 0 || _reservedStreams > 0
    }

    // MARK: - Init

    /// - Parameter transport: When set, QUIC rides the relay transport instead of a
    ///   kernel socket; `host`/`port` identify the server logically, not a dial target.
    init(host: String, port: UInt16, serverName: String, tuning: QUICTuning = .naive,
         transport: QUICDatagramTransport? = nil) {
        self.quic = QUICConnection(host: host, port: port, serverName: serverName,
                                   alpn: ["h3"], tuning: tuning, transport: transport)
    }

    // MARK: - Pool Interface

    func tryReserveStream() -> Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        guard !isClosed && !poolIsStreamBlocked else { return false }
        let count = _poolStreamCount + _reservedStreams
        guard count < maxConcurrentStreams else { return false }
        _reservedStreams += 1
        return true
    }

    /// Reserves a slot bypassing `maxConcurrentStreams` when the pool is at its hard
    /// cap; ngtcp2's STREAM_ID_BLOCKED and the caller's retry path handle backpressure.
    func forceReserveStream() -> Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        guard !isClosed && !poolIsStreamBlocked else { return false }
        _reservedStreams += 1
        return true
    }

    var activeStreamCount: Int {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolStreamCount + _reservedStreams
    }

    // MARK: - Stream Creation

    /// Converts a reserved slot into an active stream. Non-pooled callers skip this.
    func noteStreamStarted() {
        // Called on queue
        _poolLock.lock()
        _reservedStreams = max(0, _reservedStreams - 1)
        _poolStreamCount += 1
        _poolLock.unlock()
    }

    func registerStream(_ stream: any HTTP3StreamHandler, streamID: Int64) {
        streams[streamID] = stream
    }

    func removeStream(_ stream: any HTTP3StreamHandler) {
        if let sid = stream.quicStreamID {
            if streams.removeValue(forKey: sid) != nil {
                _poolLock.lock()
                _poolStreamCount = max(0, _poolStreamCount - 1)
                _poolLock.unlock()
            }
        }

        if state == .draining && streams.isEmpty {
            close()
        }
    }

    /// Called when openBidiStream fails (STREAM_ID_BLOCKED).
    func markStreamBlocked() {
        _poolLock.lock()
        poolIsStreamBlocked = true
        _poolStreamCount = max(0, _poolStreamCount - 1)
        _poolLock.unlock()
    }

    // MARK: - Connection Lifecycle

    func ensureReady(completion: @escaping (Error?) -> Void) {
        // Called on queue
        switch state {
        case .ready:
            completion(nil)
        case .draining:
            completion(HTTP3Error.connectionFailed("Session draining (GOAWAY)"))
        case .closed:
            completion(HTTP3Error.connectionFailed("Session closed"))
        case .connecting:
            readyCallbacks.append(completion)
        case .idle:
            state = .connecting
            readyCallbacks.append(completion)
            startConnection()
        }
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        // Drain pool entries eagerly on close so no new streams go to a dead multiplexer.
        quic.connectionClosedHandler = { [weak self] error in
            guard let self else { return }
            self.failSession(error)
        }

        quic.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.failSession(error)
                    return
                }

                self.openControlStreams()

                // Called on quic.queue (= our queue), so no re-dispatch needed (~1-2μs saved/packet).
                self.quic.streamDataHandler = { [weak self] streamID, data, fin in
                    self?.handleStreamData(streamID: streamID, data: data, fin: fin)
                }

                self.state = .ready
                let callbacks = self.readyCallbacks
                self.readyCallbacks.removeAll()
                for cb in callbacks { cb(nil) }
            }
        }
    }

    private func openControlStreams() {
        // HTTP/3 control stream (type 0x00) + SETTINGS
        if let sid = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00)
            payload.append(HTTP3Framer.clientSettingsFrame())
            quic.writeStream(sid, data: payload) { _ in }
        }
        // QPACK encoder (type 0x02) and decoder (type 0x03)
        if let sid = quic.openUniStream() {
            quic.writeStream(sid, data: Data([0x02])) { _ in }
        }
        if let sid = quic.openUniStream() {
            quic.writeStream(sid, data: Data([0x03])) { _ in }
        }
    }

    // MARK: - Stream Operations (called on queue)

    func openBidiStream() -> Int64? {
        quic.openBidiStream()
    }

    func writeStream(_ streamID: Int64, data: Data, fin: Bool = false, completion: @escaping (Error?) -> Void) {
        quic.writeStream(streamID, data: data, fin: fin, completion: completion)
    }

    func extendStreamOffset(_ streamID: Int64, count: Int) {
        quic.extendStreamOffset(streamID, count: count)
    }

    func shutdownStream(_ streamID: Int64, code: HTTP3ErrorCode = .noError) {
        quic.shutdownStream(streamID, appErrorCode: code.rawValue)
    }

    // MARK: - Stream Data Demux

    private func handleStreamData(streamID: Int64, data: Data, fin: Bool) {
        if let stream = streams[streamID] {
            stream.handleStreamData(data, fin: fin)
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
            var buf = pendingServerStreams.removeValue(forKey: streamID) ?? Data()
            buf.append(data)
            guard !buf.isEmpty else { return }
            let streamType = buf[buf.startIndex]
            switch streamType {
            case 0x00: // Control stream (RFC 9114 §6.2.1)
                guard serverControlStreamID == nil else {
                    // RFC 9114 §6.2.1: a second control stream is H3_STREAM_CREATION_ERROR.
                    failSession(HTTP3Error.connectionFailed("Duplicate server control stream"))
                    return
                }
                serverControlStreamID = streamID
                serverControlBuffer = Data(buf.dropFirst())
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
    private func isReservedStreamType(_ t: UInt8) -> Bool {
        t >= 0x21 && (UInt64(t) - 0x21) % 0x1f == 0
    }

    /// Parses frames on the server's control stream. RFC 9114 §7.2.4: SETTINGS
    /// must be the first frame, else H3_MISSING_SETTINGS.
    private func processServerControlFrames() {
        while !serverControlBuffer.isEmpty {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: serverControlBuffer) else {
                break // Incomplete frame
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
        for h in headers {
            total = total &+ UInt64(h.name.utf8.count) &+ UInt64(h.value.utf8.count) &+ 32
            if total > limit { return false }
        }
        return true
    }

    private func handleGoaway(_ payload: Data) {
        guard state == .ready else { return }
        state = .draining

        _poolLock.lock()
        poolIsStreamBlocked = true
        _poolLock.unlock()

        logger.debug("[HTTP3Multiplexer] Received GOAWAY, draining \(streams.count) active streams")

        if streams.isEmpty {
            close()
        }
        // Existing streams continue to completion; removeStream() closes when the last one finishes.
    }

    // MARK: - Close

    func close(error: Error? = nil) {
        // Strong `self`: a weakly-captured pooled multiplexer could deallocate before
        // this runs, skipping `quic.close()` and leaking the socket + ngtcp2 state.
        queue.async {
            guard self.state != .closed else { return }
            self.state = .closed

            self._poolLock.lock()
            self.isClosed = true
            self._poolStreamCount = 0
            self._reservedStreams = 0
            self._poolLock.unlock()

            let activeStreams = Array(self.streams.values)
            self.streams.removeAll()
            for stream in activeStreams {
                stream.handleSessionError(HTTP3Error.connectionFailed("Session closed"))
            }

            self.quic.close()
            self.onClose?()
        }
    }

    private func failSession(_ error: Error) {
        guard state != .closed else { return }
        state = .closed

        _poolLock.lock()
        isClosed = true
        _poolStreamCount = 0
        _reservedStreams = 0
        _poolLock.unlock()

        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for cb in callbacks { cb(error) }

        let activeStreams = Array(streams.values)
        streams.removeAll()
        for stream in activeStreams {
            stream.handleSessionError(error)
        }

        onClose?()
    }
}
