//
//  HysteriaSession.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HysteriaSession")

// MARK: - Errors

enum HysteriaError: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case authRejected(statusCode: Int)
    case tunnelFailed(message: String)
    case streamClosed
    case udpNotSupported

    var errorDescription: String? {
        switch self {
        case .notReady: return "Hysteria session not ready"
        case .connectionFailed(let m): return "Hysteria connection failed: \(m)"
        case .authRejected(let c): return "Hysteria auth rejected (status \(c))"
        case .tunnelFailed(let m): return "Hysteria tunnel failed: \(m)"
        case .streamClosed: return "Hysteria stream closed"
        case .udpNotSupported: return "Hysteria server does not support UDP"
        }
    }
}

// MARK: - HysteriaSession

final class HysteriaSession {

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: HysteriaConfiguration

    var queue: DispatchQueue { quic.queue }
    var isOnQueue: Bool { quic.isOnQueue }

    private var state: State = .idle

    /// Bidi stream used for the one-shot auth POST. All other bidi streams
    /// opened after `ready` are raw Hysteria TCP streams.
    private var authStreamID: Int64 = -1
    private var authBuffer = Data()
    private var authHeadersReceived = false

    /// Pending readiness callbacks (auth not yet complete).
    private var readyCallbacks: [(Error?) -> Void] = []

    /// Fired when the session transitions to `.closed` (graceful close or
    /// `failSession`). ``HysteriaClient`` uses this to clear its cached
    /// slot so the next call reconnects.
    var onClose: (() -> Void)?

    /// Raw post-auth TCP stream handlers keyed by QUIC stream ID.
    private var tcpStreams: [Int64: HysteriaConnection] = [:]

    /// Active UDP connections keyed by session ID.
    private var udpSessions: [UInt32: HysteriaUDPConnection] = [:]
    private var nextUDPSessionID: UInt32 = 1

    /// Server-advertised UDP support.
    private(set) var udpSupported = false
    /// Server-advertised RX budget (bytes/sec). 0 = unlimited.
    private(set) var serverRxBytesPerSec: UInt64 = 0

    // MARK: Pool-visible state (accessed without the queue)

    private let _poolLock = UnfairLock()
    private(set) var poolIsClosed = false
    private var _poolTCPCount = 0
    private var _poolUDPCount = 0

    var hasActiveConnections: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolTCPCount > 0 || _poolUDPCount > 0
    }

    // MARK: - Init

    init(configuration: HysteriaConfiguration) {
        self.configuration = configuration
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.sni,
            alpn: ["h3"],
            datagramsEnabled: true,
            tuning: .hysteria(uploadMbps: configuration.uploadMbps)
        )
    }

    // MARK: - Lifecycle

    /// Brings the session to `ready`: QUIC connect → HTTP/3 SETTINGS →
    /// POST /auth → 233 response. Callbacks are invoked once, in order.
    func ensureReady(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            switch self.state {
            case .ready:
                completion(nil)
            case .closed:
                completion(HysteriaError.connectionFailed("Session closed"))
            case .connecting, .authenticating:
                self.readyCallbacks.append(completion)
            case .idle:
                self.state = .connecting
                self.readyCallbacks.append(completion)
                self.startConnection()
            }
        }
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.connectionClosedHandler = { [weak self] error in
            self?.failSession(error)
        }

        quic.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    logger.error("[Hysteria] QUIC connect failed: \(error.localizedDescription)")
                    self.failSession(error)
                    return
                }

                self.quic.streamDataHandler = { [weak self] sid, data, fin in
                    // Runs synchronously on quic.queue (== session.queue)
                    // from inside ngtcp2's read_pkt call. Processing inline
                    // lets the MAX_STREAM_DATA ACK ride read_pkt's tail-flush
                    // and keeps the hot RX loop free of per-packet queue hops.
                    // `data` is a zero-copy view into ngtcp2's receive buffer;
                    // handleStreamData is responsible for detaching it before
                    // the view is invalidated on return.
                    self?.handleStreamData(sid: sid, data: data, fin: fin)
                }
                self.quic.streamTerminationHandler = { [weak self] sid, error in
                    // Runs synchronously on quic.queue. Fired for RESET_STREAM
                    // from the peer and for the terminal stream_close event.
                    // Must be idempotent — both may fire for the same stream.
                    self?.handleStreamTermination(sid: sid, error: error)
                }
                self.quic.datagramHandler = { [weak self] data in
                    // Runs synchronously on quic.queue. QUICConnection already
                    // hands datagramHandler a standalone Data, so we can
                    // process inline without an intermediate copy.
                    self?.handleDatagram(data)
                }

                self.openHTTP3Control()
                self.sendAuthRequest()
                self.state = .authenticating
            }
        }
    }

    private func openHTTP3Control() {
        // RFC 9114 §6.2: we must open an HTTP/3 control stream with a SETTINGS
        // frame even though Hysteria doesn't send further HTTP/3 frames after
        // /auth. Without it a strict HTTP/3 server would close the connection.
        if let sid = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00) // stream type = control
            payload.append(Self.clientSettingsFrame())
            quic.writeStream(sid, data: payload) { _ in }
        }
        // QPACK encoder (0x02) / decoder (0x03) uni streams. We advertise
        // dynamic-table capacity 0, so these only carry the type byte.
        if let enc = quic.openUniStream() {
            quic.writeStream(enc, data: Data([0x02])) { _ in }
        }
        if let dec = quic.openUniStream() {
            quic.writeStream(dec, data: Data([0x03])) { _ in }
        }
    }

    /// Parses a single HTTP/3 frame off the front of `buffer`. Returns
    /// (type, payload-slice, totalConsumedBytes), or `nil` if the frame
    /// isn't fully buffered yet. The returned payload is a zero-copy slice
    /// of `buffer`; `HysteriaHTTP3Codec.decodeHeaderBlock` is slice-safe.
    private func parseNextHTTP3Frame(_ buffer: Data) -> (type: UInt64, payload: Data, consumed: Int)? {
        guard let (frameType, typeLen) = Self.decodeQUICVarInt(buffer, offset: 0) else { return nil }
        guard let (payloadLen, lenBytes) = Self.decodeQUICVarInt(buffer, offset: typeLen) else { return nil }
        let headerLen = typeLen + lenBytes
        let total = headerLen + Int(payloadLen)
        guard buffer.count >= total else { return nil }
        let base = buffer.startIndex
        let payload = buffer[(base + headerLen)..<(base + total)]
        return (frameType, payload, total)
    }

    /// Slice-safe QUIC varint decoder (RFC 9000 §16).
    private static func decodeQUICVarInt(_ data: Data, offset: Int) -> (UInt64, Int)? {
        guard offset < data.count else { return nil }
        let base = data.startIndex
        let first = data[base + offset]
        let prefix = first >> 6
        let len = 1 << Int(prefix)
        guard offset + len <= data.count else { return nil }
        var value = UInt64(first & 0x3F)
        for i in 1..<len {
            value = (value << 8) | UInt64(data[base + offset + i])
        }
        return (value, len)
    }

    /// HTTP/3 SETTINGS frame with QPACK dynamic table disabled.
    /// Layout: varint(type=0x04) | varint(len) | pairs of varint(id, value).
    private static func clientSettingsFrame() -> Data {
        // id=0x01 (QPACK_MAX_TABLE_CAPACITY) val=0,
        // id=0x07 (QPACK_BLOCKED_STREAMS) val=0.
        let payload = Data([0x01, 0x00, 0x07, 0x00])
        var frame = Data()
        frame.append(0x04)                  // type = SETTINGS (1-byte varint)
        frame.append(UInt8(payload.count))  // len   (1-byte varint)
        frame.append(payload)
        return frame
    }

    private func sendAuthRequest() {
        guard let sid = quic.openBidiStream() else {
            failSession(HysteriaError.connectionFailed("Failed to open auth stream"))
            return
        }
        authStreamID = sid

        let extraHeaders: [(name: String, value: String)] = [
            ("hysteria-auth", configuration.password),
            ("hysteria-cc-rx", String(configuration.clientRxBytesPerSec)),
            ("hysteria-padding", HysteriaProtocol.randomPaddingString()),
            ("content-length", "0"),
        ]
        let frame = HysteriaHTTP3Codec.encodeAuthRequestFrame(
            authority: "hysteria", path: "/auth", extraHeaders: extraHeaders
        )

        quic.writeStream(sid, data: frame) { [weak self] error in
            guard let self else { return }
            if let error {
                self.queue.async { self.failSession(error) }
            }
        }
    }

    // MARK: - Stream dispatch

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        if sid == authStreamID {
            handleAuthStreamData(data, fin: fin)
            return
        }

        if let conn = tcpStreams[sid] {
            conn.handleStreamData(data, fin: fin)
            return
        }

        // Server-initiated unidirectional streams (bits 0x03). Drain to
        // avoid leaking connection-level flow control; Hysteria v2 doesn't
        // use them meaningfully after auth.
        if (sid & 0x03) == 0x03, !data.isEmpty {
            quic.extendStreamOffset(sid, count: data.count)
        }
    }

    private func handleAuthStreamData(_ data: Data, fin: Bool) {
        authBuffer.append(data)
        quic.extendStreamOffset(authStreamID, count: data.count)

        guard !authHeadersReceived else { return }

        // Parse HTTP/3 HEADERS frame: varint(type=0x01) | varint(len) | block
        guard let (frameType, payload, consumed) = parseNextHTTP3Frame(authBuffer) else {
            return // incomplete
        }
        authBuffer = Data(authBuffer.dropFirst(consumed))

        guard frameType == 0x01 else {
            failSession(HysteriaError.connectionFailed("Auth response wasn't HEADERS"))
            return
        }
        guard let headers = HysteriaHTTP3Codec.decodeHeaderBlock(payload) else {
            failSession(HysteriaError.connectionFailed("Malformed auth QPACK block"))
            return
        }

        authHeadersReceived = true

        let status = headers.first(where: { $0.name == ":status" })?.value
        guard let statusStr = status, let code = Int(statusStr) else {
            failSession(HysteriaError.connectionFailed("Missing :status on auth response"))
            return
        }
        if code != HysteriaProtocol.authSuccessStatus {
            failSession(HysteriaError.authRejected(statusCode: code))
            return
        }

        udpSupported = (headers.first(where: { $0.name == "hysteria-udp" })?.value).map {
            $0.lowercased() == "true"
        } ?? false
        let ccRxValue = headers.first(where: { $0.name == "hysteria-cc-rx" })?.value ?? ""
        // Server may respond with "auto" — treat that, and any unparseable
        // value, as 0 ("unlimited / use whatever").
        serverRxBytesPerSec = UInt64(ccRxValue) ?? 0

        // Brutal tx rate = min(server_rx, client_max_tx), treating a
        // server-side 0 as "no server cap". The client cap is always set
        // (validated 1…100 Mbit/s at construction time) so we always
        // have something to install.
        let clientTxBps = configuration.uploadBytesPerSec
        let effectiveTxBps: UInt64 = serverRxBytesPerSec == 0
            ? clientTxBps
            : min(serverRxBytesPerSec, clientTxBps)
        quic.setBrutalBandwidth(effectiveTxBps)

        // Tear down the auth stream — we don't need it anymore.
        quic.shutdownStream(authStreamID, appErrorCode: HysteriaProtocol.closeErrCodeOK)

        state = .ready
        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for cb in callbacks { cb(nil) }

        _ = fin // ignore; stream shutdown handled above
    }

    private func handleStreamTermination(sid: Int64, error: Error?) {
        // On quic.queue == session.queue. Called from both the peer-reset
        // and final-close ngtcp2 hooks; idempotent because `tcpStreams` is
        // removed the first time through.
        if sid == authStreamID { return }
        guard let conn = tcpStreams.removeValue(forKey: sid) else { return }
        _poolLock.lock()
        _poolTCPCount = max(0, _poolTCPCount - 1)
        _poolLock.unlock()
        conn.handleStreamTermination(error: error)
    }

    // MARK: - Datagram dispatch (UDP)

    private func handleDatagram(_ data: Data) {
        guard let msg = HysteriaProtocol.decodeUDPMessage(data) else { return }
        if let conn = udpSessions[msg.sessionID] {
            conn.handleIncomingDatagram(msg)
        }
        // Unknown sessions are dropped silently — matches the reference
        // server/client behavior (no explicit session teardown).
    }

    // MARK: - TCP stream API (called by HysteriaConnection)

    func openTCPStream(for conn: HysteriaConnection, completion: @escaping (Int64?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(nil, HysteriaError.streamClosed); return }
            guard self.state == .ready else {
                completion(nil, HysteriaError.notReady)
                return
            }
            guard let sid = self.quic.openBidiStream() else {
                completion(nil, HysteriaError.connectionFailed("Failed to open TCP stream"))
                return
            }
            self.tcpStreams[sid] = conn
            self._poolLock.lock()
            self._poolTCPCount += 1
            self._poolLock.unlock()
            completion(sid, nil)
        }
    }

    func writeStream(_ sid: Int64, data: Data, completion: @escaping (Error?) -> Void) {
        quic.writeStream(sid, data: data, completion: completion)
    }

    func extendStreamOffset(_ sid: Int64, count: Int) {
        quic.extendStreamOffset(sid, count: count)
    }

    func shutdownStream(_ sid: Int64, appErrorCode: UInt64 = HysteriaProtocol.closeErrCodeOK) {
        quic.shutdownStream(sid, appErrorCode: appErrorCode)
    }

    func releaseTCPStream(_ sid: Int64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.tcpStreams.removeValue(forKey: sid) != nil {
                self._poolLock.lock()
                self._poolTCPCount = max(0, self._poolTCPCount - 1)
                self._poolLock.unlock()
            }
        }
    }

    // MARK: - UDP session API (called by HysteriaUDPConnection)

    /// Registers a new UDP session. Invokes `completion` with the assigned
    /// session ID, or nil if the server didn't advertise UDP support.
    /// Completion runs on the session queue.
    func registerUDPSession(_ conn: HysteriaUDPConnection, completion: @escaping (UInt32?) -> Void) {
        let body = { [weak self] in
            guard let self else { completion(nil); return }
            guard self.state == .ready, self.udpSupported else {
                completion(nil); return
            }
            let sid = self.nextUDPSessionID
            self.nextUDPSessionID = self.nextUDPSessionID == UInt32.max ? 1 : self.nextUDPSessionID + 1
            self.udpSessions[sid] = conn
            self._poolLock.lock()
            self._poolUDPCount += 1
            self._poolLock.unlock()
            completion(sid)
        }
        if isOnQueue { body() } else { queue.async(execute: body) }
    }

    func releaseUDPSession(_ sessionID: UInt32) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.udpSessions.removeValue(forKey: sessionID) != nil {
                self._poolLock.lock()
                self._poolUDPCount = max(0, self._poolUDPCount - 1)
                self._poolLock.unlock()
            }
        }
    }

    func writeDatagrams(_ datagrams: [Data], completion: @escaping (Error?) -> Void) {
        quic.writeDatagrams(datagrams, completion: completion)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    // MARK: - Close

    func close() {
        queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed

            self._poolLock.lock()
            self.poolIsClosed = true
            self._poolLock.unlock()

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(HysteriaError.connectionFailed("Session closed")) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(HysteriaError.connectionFailed("Session closed")) }

            self.quic.close()
            self.onClose?()
        }
    }

    private func failSession(_ error: Error) {
        queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed

            self._poolLock.lock()
            self.poolIsClosed = true
            self._poolLock.unlock()

            let callbacks = self.readyCallbacks
            self.readyCallbacks.removeAll()
            for cb in callbacks { cb(error) }

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(error) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(error) }

            self.quic.close()
            self.onClose?()
        }
    }
}
