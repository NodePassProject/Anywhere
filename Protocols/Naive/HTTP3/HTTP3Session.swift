//
//  HTTP3Session.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP3Session")

class HTTP3Session {

    // MARK: - State

    enum SessionState {
        case idle, connecting, ready, draining, closed
    }

    // MARK: - Properties

    private let quic: QUICConnection
    private let configuration: NaiveConfiguration
    /// Shares the QUICConnection's serial queue to avoid cross-queue dispatch
    /// on the hot receive path (recv_stream_data → session → stream).
    var queue: DispatchQueue { quic.queue }

    /// Whether the caller is already on the session/QUIC queue.
    var isOnQueue: Bool { quic.isOnQueue }

    private var state: SessionState = .idle

    /// Active streams keyed by QUIC stream ID.
    private var streams: [Int64: HTTP3Stream] = [:]

    /// Pending ready callbacks (batched while connecting).
    private var readyCallbacks: [(Error?) -> Void] = []

    /// Pool eviction callback.
    var onClose: (() -> Void)?

    /// Server-initiated control stream ID and frame buffer.
    private var serverControlStreamID: Int64?
    private var serverControlBuffer = Data()
    /// Tracks server-initiated streams whose type byte hasn't been read yet.
    private var pendingServerStreams: [Int64: Data] = [:]
    /// True once we've parsed the server's SETTINGS frame on its control stream.
    /// RFC 9114 §7.2.4: SETTINGS MUST be the first frame on the control stream.
    private var serverSettingsReceived = false

    /// Peer-advertised MAX_FIELD_SECTION_SIZE from SETTINGS. RFC 9114 §4.2.2.
    /// Defaults to unlimited until SETTINGS arrives.
    private(set) var peerMaxFieldSectionSize: UInt64 = UInt64.max

    // Pool-visible state — accessed from the pool's lock context (arbitrary thread).
    // Must NOT touch `streams` or other queue-protected state.
    private let _poolLock = UnfairLock()
    private(set) var poolIsClosed = false
    /// True when ngtcp2 can't open more streams (STREAM_ID_BLOCKED).
    /// The pool will create a new session instead of reusing this one.
    private(set) var poolIsStreamBlocked = false
    private var _poolStreamCount = 0
    private var _reservedStreams = 0
    private let maxConcurrentStreams = 100

    /// Whether the session has active or reserved streams. Thread-safe.
    /// Used by the pool to avoid evicting sessions that are still in use.
    var hasActiveStreams: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolStreamCount > 0 || _reservedStreams > 0
    }

    // MARK: - Init

    init(host: String, port: UInt16, serverName: String, configuration: NaiveConfiguration) {
        self.configuration = configuration
        self.quic = QUICConnection(host: host, port: port, serverName: serverName, alpn: ["h3"])
    }

    // MARK: - Pool Interface

    /// Atomically reserves a stream slot. Thread-safe (called from pool lock).
    func tryReserveStream() -> Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        guard !poolIsClosed && !poolIsStreamBlocked else { return false }
        let count = _poolStreamCount + _reservedStreams
        guard count < maxConcurrentStreams else { return false }
        _reservedStreams += 1
        return true
    }

    // MARK: - Stream Creation

    func createStream(destination: String) -> HTTP3Stream {
        // Called on queue
        _poolLock.lock()
        _reservedStreams = max(0, _reservedStreams - 1)
        _poolStreamCount += 1
        _poolLock.unlock()
        let stream = HTTP3Stream(session: self, configuration: configuration,
                                 destination: destination)
        return stream
    }

    /// Registers a stream after its QUIC stream ID is assigned.
    func registerStream(_ stream: HTTP3Stream, streamID: Int64) {
        streams[streamID] = stream
    }

    func removeStream(_ stream: HTTP3Stream) {
        if let sid = stream.quicStreamID {
            if streams.removeValue(forKey: sid) != nil {
                _poolLock.lock()
                _poolStreamCount = max(0, _poolStreamCount - 1)
                _poolLock.unlock()
            }
        }

        // When draining and no streams remain, close the session
        if state == .draining && streams.isEmpty {
            close()
        }
    }

    /// Called when openBidiStream fails (STREAM_ID_BLOCKED).
    /// Marks session as blocked so the pool creates a new one.
    func markStreamBlocked() {
        _poolLock.lock()
        poolIsStreamBlocked = true
        // Release the reservation that createStream made
        _poolStreamCount = max(0, _poolStreamCount - 1)
        _poolLock.unlock()
    }

    // MARK: - Connection Lifecycle

    /// Ensures the QUIC connection and HTTP/3 control streams are ready.
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

        // React immediately when the QUIC connection closes (draining, error, etc.)
        // so the pool stops handing out streams on this dead session.
        quic.connectionClosedHandler = { [weak self] error in
            guard let self else { return }
            logger.error("[HTTP3Session] QUIC connection closed: \(error.localizedDescription)")
            self.failSession(error)
        }

        quic.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    logger.error("[HTTP3Session] QUIC connect failed: \(error.localizedDescription)")
                    self.failSession(error)
                    return
                }

                // Open HTTP/3 control stream
                self.openControlStreams()

                // Stream data handler — called on quic.queue which IS our queue,
                // so no dispatch needed (avoids ~1-2μs per packet).
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

    func writeStream(_ streamID: Int64, data: Data, completion: @escaping (Error?) -> Void) {
        quic.writeStream(streamID, data: data, completion: completion)
    }

    func extendStreamOffset(_ streamID: Int64, count: Int) {
        quic.extendStreamOffset(streamID, count: count)
    }

    func shutdownStream(_ streamID: Int64) {
        quic.shutdownStream(streamID)
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

        // Server-initiated stream data is consumed immediately (SETTINGS, QPACK,
        // GOAWAY, etc.) — extend flow control right away so connection-level
        // credits aren't permanently leaked.
        quic.extendStreamOffset(streamID, count: data.count)

        if streamID == serverControlStreamID {
            // Data on the established control stream — parse for SETTINGS/GOAWAY
            serverControlBuffer.append(data)
            processServerControlFrames()
        } else {
            // Any server-initiated unidirectional stream other than the control
            // stream needs its type byte read and classified. If the stream is
            // already known to be non-control (e.g. QPACK) we keep discarding.
            var buf = pendingServerStreams.removeValue(forKey: streamID) ?? Data()
            buf.append(data)
            guard !buf.isEmpty else { return }
            let streamType = buf[buf.startIndex]
            switch streamType {
            case 0x00: // Control stream (RFC 9114 §6.2.1)
                guard serverControlStreamID == nil else {
                    // RFC 9114 §6.2.1: more than one control stream is a
                    // connection error of type H3_STREAM_CREATION_ERROR.
                    failSession(HTTP3Error.connectionFailed("Duplicate server control stream"))
                    return
                }
                serverControlStreamID = streamID
                serverControlBuffer = Data(buf.dropFirst())
                processServerControlFrames()
            case 0x01: // Push (RFC 9114 §6.2.2) — we never send MAX_PUSH_ID
                failSession(HTTP3Error.connectionFailed("Server opened push stream without MAX_PUSH_ID"))
            case 0x02, 0x03: // QPACK encoder / decoder (RFC 9204 §4.2)
                // We advertised QPACK_MAX_TABLE_CAPACITY=0 so there's nothing
                // meaningful on these streams; drain silently.
                break
            default:
                // RFC 9114 §6.2: unknown or reserved stream types. Reserved
                // types follow `0x1f * N + 0x21`; for everything else we
                // abort reading via STOP_SENDING rather than trust the bytes.
                if !isReservedStreamType(streamType) {
                    quic.shutdownStream(streamID)
                }
            }
        }
    }

    /// RFC 9114 §7.2.9 reserved stream type grease values.
    private func isReservedStreamType(_ t: UInt8) -> Bool {
        t >= 0x21 && (UInt64(t) - 0x21) % 0x1f == 0
    }

    /// Parses HTTP/3 frames on the server's control stream.
    /// RFC 9114 §7.2.4: SETTINGS MUST be the first frame; anything else before
    /// SETTINGS is a connection error (H3_MISSING_SETTINGS).
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
                // These frames are forbidden on the control stream
                // (RFC 9114 §7.2.1/§7.2.2/§7.2.5): H3_FRAME_UNEXPECTED.
                failSession(HTTP3Error.connectionFailed("Forbidden frame type \(frame.type) on control stream"))
                return
            default:
                break // Unknown/grease types are ignored.
            }
        }
    }

    /// Parses the server's SETTINGS payload into peer limits we care about.
    /// Returns false if the payload is malformed.
    private func parseServerSettings(_ payload: Data) -> Bool {
        var offset = 0
        var seen = Set<UInt64>()
        while offset < payload.count {
            guard let (id, idLen) = HTTP3Framer.decodeVarInt(from: payload, offset: offset) else {
                return false
            }
            offset += idLen
            guard let (value, valLen) = HTTP3Framer.decodeVarInt(from: payload, offset: offset) else {
                return false
            }
            offset += valLen

            // RFC 9114 §7.2.4: the same identifier MUST NOT occur more than once.
            if !seen.insert(id).inserted { return false }

            switch id {
            case HTTP3SettingsID.maxFieldSectionSize.rawValue:
                peerMaxFieldSectionSize = value
            case HTTP3SettingsID.qpackMaxTableCapacity.rawValue,
                 HTTP3SettingsID.qpackBlockedStreams.rawValue:
                // We don't use the dynamic table, so we don't need to react.
                break
            default:
                break // Unknown / reserved identifiers are ignored.
            }
        }
        return true
    }

    /// RFC 9114 §4.2.2 — Sum of (name.utf8.count + value.utf8.count + 32)
    /// over all fields. Returns true if the list fits under the peer's limit.
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

    /// Handles a GOAWAY frame: stops accepting new streams and drains existing ones.
    private func handleGoaway(_ payload: Data) {
        guard state == .ready else { return }
        state = .draining

        // Mark session as stream-blocked so the pool creates a new session
        _poolLock.lock()
        poolIsStreamBlocked = true
        _poolLock.unlock()

        logger.info("[HTTP3Session] Received GOAWAY, draining \(streams.count) active streams")

        // If no active streams remain, close immediately
        if streams.isEmpty {
            close()
        }
        // Otherwise, existing streams continue until they complete naturally.
        // When the last stream is removed via removeStream(), check for drain completion.
    }

    // MARK: - Close

    func close() {
        queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed

            self._poolLock.lock()
            self.poolIsClosed = true
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
        poolIsClosed = true
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
