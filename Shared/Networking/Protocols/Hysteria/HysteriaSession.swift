//
//  HysteriaSession.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
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
    /// The flow's destination address cannot be sent over the current
    /// QUIC DATAGRAM ceiling — the Hysteria UDP header (fixed sessID/
    /// pktID/fragIDs + varint(addrLen) + addr bytes) alone meets or
    /// exceeds the peer's `max_datagram_frame_size` minus QUIC overhead.
    /// Permanent for this flow's destination: the address is fixed,
    /// so every subsequent send produces the same outcome. Distinct
    /// from `connectionFailed`'s transient cases (fragmentation refusals,
    /// queue overflow) so the LWIP layer tears the flow down instead of
    /// logging-and-continuing forever.
    case destinationTooLargeForDatagram(maxFrame: Int, headerSize: Int)

    var errorDescription: String? {
        switch self {
        case .notReady: return "Hysteria session not ready"
        case .connectionFailed(let m): return "Hysteria connection failed: \(m)"
        case .authRejected(let c): return "Hysteria auth rejected (status \(c))"
        case .tunnelFailed(let m): return "Hysteria tunnel failed: \(m)"
        case .streamClosed: return "Hysteria stream closed"
        case .udpNotSupported: return "Hysteria server does not support UDP"
        case .destinationTooLargeForDatagram(let frame, let header):
            return "Hysteria destination too large for DATAGRAM (peer max \(frame) ≤ header \(header))"
        }
    }
}

// MARK: - HysteriaSession

nonisolated final class HysteriaSession {

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: HysteriaConfiguration

    var queue: DispatchQueue { quic.queue }
    var isOnQueue: Bool { quic.isOnQueue }

    private var state: State = .idle

    /// Once-only gate shared by `close()` and `failSession` so terminal
    /// teardown (incl. `quic.close()`) runs exactly once regardless of which
    /// path fires first. Acquired from inside their on-queue blocks to keep
    /// the existing FIFO "first wins" ordering.
    private let closeLatch = CloseOnce()

    /// Bidi stream used for the one-shot auth POST. All other bidi streams
    /// opened after `ready` are raw Hysteria TCP streams.
    private var authStreamID: Int64 = -1
    private var authBuffer = Data()
    private var authHeadersReceived = false
    /// Ceiling on `authBuffer` growth. A well-behaved Hysteria server's
    /// auth response is one HTTP/3 HEADERS frame (a few hundred bytes of
    /// QPACK plus padding capped at `maxPaddingLength = 4096`). Anything
    /// approaching this bound is a misbehaving / malicious server trying
    /// to grow our buffer before delivering parseable headers; tear the
    /// session down rather than OOM. Generous (3× the worst legitimate
    /// case) so a server that happens to add unusually large padding
    /// still authenticates.
    private static let authBufferMaxBytes = 16 * 1024

    /// Pending readiness callbacks (auth not yet complete).
    private var readyCallbacks: [(Error?) -> Void] = []

    /// Fired when the session transitions to `.closed` (graceful close or
    /// `failSession`). ``HysteriaClient`` uses this to clear its cached
    /// slot so the next call reconnects.
    var onClose: (() -> Void)?

    /// Raw post-auth TCP stream handlers keyed by QUIC stream ID.
    private var tcpStreams: [Int64: HysteriaConnection] = [:]

    /// Server-initiated streams we've issued STOP_SENDING / RESET_STREAM
    /// for. Tracked so a server that keeps streaming data after we've
    /// already rejected the stream doesn't trigger a fresh `shutdownStream`
    /// call (and queued ngtcp2 frame) on every chunk before its own
    /// RESET_STREAM lands. Cleared in `handleStreamTermination` when the
    /// peer's reset arrives.
    private var rejectedServerStreams: Set<Int64> = []

    /// Active UDP connections keyed by session ID.
    private var udpSessions: [UInt32: HysteriaUDPConnection] = [:]
    private var nextUDPSessionID: UInt32 = 1

    /// Scheduled close fired when the session has held zero TCP streams and
    /// zero UDP sessions for `idleCloseDelay`. Without this, the QUIC
    /// connection (UDP socket, ngtcp2 state, 4 MiB kernel buffers, 10 s
    /// keep-alive PING) stays resident forever after the last consumer goes
    /// away. Accessed only on `queue`.
    private var idleCloseWorkItem: DispatchWorkItem?
    /// How long the session waits idle (no active streams, no active UDP
    /// sessions) before closing itself. 60 s is short enough to free
    /// resources promptly on burst-y workloads, long enough that the
    /// session survives back-to-back UDP queries that close their flows
    /// before the next opens.
    private static let idleCloseDelay: DispatchTimeInterval = .seconds(60)

    /// Server-advertised UDP support.
    private(set) var udpSupported = false
    /// Server-advertised RX budget (bytes/sec). 0 = unlimited.
    private(set) var serverRxBytesPerSec: UInt64 = 0

    // MARK: Pool-visible state (accessed without the queue)

    private let _poolLock = UnfairLock()
    /// Backing storage for ``poolIsClosed``. Mutated only under
    /// `_poolLock` in `close()` / `failSession`; read via the public
    /// accessor below (also under `_poolLock`) so the read is properly
    /// synchronised with the write. Swift's memory model doesn't
    /// guarantee that a plain `Bool` write under a lock is visible to a
    /// lock-free reader, so the previous `private(set) var poolIsClosed`
    /// was a data race even though it worked in practice on aarch64.
    private var _poolIsClosed = false
    private var _poolTCPCount = 0
    private var _poolUDPCount = 0

    var poolIsClosed: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolIsClosed
    }

    var hasActiveConnections: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolTCPCount > 0 || _poolUDPCount > 0
    }

    // MARK: - Init

    /// - Parameter transport: Optional UDP-relay transport for chained
    ///   Hysteria; when set, QUIC rides it instead of a kernel socket.
    init(configuration: HysteriaConfiguration, transport: QUICDatagramTransport? = nil) {
        self.configuration = configuration
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.sni,
            alpn: ["h3"],
            datagramsEnabled: true,
            tuning: .hysteria(congestionControl: configuration.congestionControl, uploadMbps: configuration.uploadMbps),
            transport: transport
        )
    }

#if DEBUG
    /// Leak tripwire: a session must reach terminal teardown (`close()` or
    /// `failSession`, both via `closeLatch`) before being freed — otherwise its
    /// `QUICConnection` (socket + ngtcp2 state) was never closed. DEBUG-only.
    deinit {
        assert(closeLatch.isClosed, "HysteriaSession leaked: freed without close()/failSession")
    }
#endif

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
                // Distinguishable from a connect failure so the
                // `HysteriaClient` retry shim can reconnect when the idle
                // timer closed the session between acquire and use.
                completion(HysteriaError.streamClosed)
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
        guard let (frameType, typeLen) = HysteriaProtocol.decodeVarInt(from: buffer, offset: 0) else { return nil }
        guard let (payloadLen, lenBytes) = HysteriaProtocol.decodeVarInt(from: buffer, offset: typeLen) else { return nil }
        let headerLen = typeLen + lenBytes
        let total = headerLen + Int(payloadLen)
        guard buffer.count >= total else { return nil }
        let base = buffer.startIndex
        let payload = buffer[(base + headerLen)..<(base + total)]
        return (frameType, payload, total)
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

        // Server-initiated streams — both unidirectional (sid & 0x03 == 0x03)
        // and bidirectional (sid & 0x03 == 0x01). Drain to credit
        // connection-level flow control; Hysteria v2 doesn't open server
        // streams meaningfully after auth, but failing to credit either
        // class would let a misbehaving peer pin our window to zero and
        // wedge every other stream on the connection.
        //
        // Crediting alone isn't enough: a hostile peer would happily keep
        // streaming garbage forever, costing AEAD CPU + bandwidth on a
        // session that should be carrying the user's traffic. After
        // crediting the in-flight chunk, send STOP_SENDING (and, for
        // bidi, RESET_STREAM) once so the peer stops. Tracking in
        // `rejectedServerStreams` keeps us from re-shutting down on
        // every subsequent chunk that arrives before the peer's
        // RESET_STREAM lands.
        if (sid & 0x01) == 0x01, !data.isEmpty {
            quic.extendStreamOffset(sid, count: data.count)
            if rejectedServerStreams.insert(sid).inserted {
                quic.shutdownStream(sid, appErrorCode: HysteriaProtocol.closeErrCodeProtocolError)
            }
        }
    }

    private func handleAuthStreamData(_ data: Data, fin: Bool) {
        // Always credit flow control. Done up front so the post-success
        // drain (below) doesn't need to remember to do it.
        quic.extendStreamOffset(authStreamID, count: data.count)

        // Post-auth drain: bytes arriving on the auth stream after we've
        // parsed HEADERS are leftover in-flight data from before our
        // `shutdownStream(authStreamID)` STOP_SENDING reached the peer
        // (or a misbehaving server / middlebox). Don't append — letting
        // `authBuffer` grow past `authBufferMaxBytes` would `failSession`
        // an otherwise-healthy connection.
        if authHeadersReceived { return }

        authBuffer.append(data)

        if authBuffer.count > Self.authBufferMaxBytes {
            failSession(HysteriaError.connectionFailed(
                "Auth response exceeded \(Self.authBufferMaxBytes)-byte buffer cap"
            ))
            return
        }

        // Parse HTTP/3 HEADERS frame: varint(type=0x01) | varint(len) | block
        guard let (frameType, payload, consumed) = parseNextHTTP3Frame(authBuffer) else {
            // Server FIN'd the stream before sending a parseable HEADERS
            // frame — fail fast instead of waiting for the QUIC keep-alive
            // PING / idle timeout to surface the dead session seconds later.
            if fin {
                failSession(HysteriaError.connectionFailed(
                    "Auth stream ended before HEADERS frame"
                ))
            }
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
        // The server's CC-RX only matters under Brutal, where it caps our send
        // rate. Under BBR the connection paces itself, so there is nothing to
        // adjust from the response.
        if configuration.congestionControl == .brutal {
            let ccRxValue = headers.first(where: { $0.name == "hysteria-cc-rx" })?.value ?? ""
            // `auto` is the server asking the CLIENT to defer pacing to its own
            // estimator. ngtcp2 in this tree doesn't ship BBR-with-pacing, so
            // the closest match is its native CUBIC: uninstall Brutal and let
            // CUBIC's loss-based control drive. Any other value (including
            // unparseable / missing) is treated as 0 = "no cap".
            let serverRxAuto = ccRxValue.lowercased() == "auto"
            serverRxBytesPerSec = serverRxAuto ? 0 : (UInt64(ccRxValue) ?? 0)

            if serverRxAuto {
                quic.uninstallBrutalCC()
            } else {
                // Brutal tx rate = min(server_rx, client_max_tx), treating a
                // server-side 0 as "no server cap". A client cap of 0 leaves
                // Brutal idle so ngtcp2's CUBIC drives instead.
                let clientTxBps = configuration.uploadBytesPerSec
                let effectiveTxBps: UInt64 = serverRxBytesPerSec == 0
                    ? clientTxBps
                    : min(serverRxBytesPerSec, clientTxBps)
                quic.setBrutalBandwidth(effectiveTxBps)
            }
        }

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
        if sid == authStreamID {
            // Pre-ready, this is a server-side abort of the auth flow
            // (RESET_STREAM, or a clean stream_close that arrived before
            // `handleAuthStreamData` saw a parseable HEADERS frame). Fail
            // the session immediately rather than letting `ensureReady`
            // wait out the QUIC keep-alive PING (~10 s) or idle timeout.
            //
            // Post-ready, this is our own `shutdownStream(authStreamID, …)`
            // landing after a successful 233 — silently absorb.
            if state != .ready {
                failSession(error ?? HysteriaError.connectionFailed(
                    "Auth stream closed before completion"
                ))
            }
            return
        }
        // Server stream we previously rejected — peer's RESET_STREAM (or
        // our own shutdown landing back as stream_close) finally arrived.
        // Drop the tracking entry and absorb; there's no app-layer state
        // to clean up.
        if rejectedServerStreams.remove(sid) != nil { return }
        guard let conn = tcpStreams.removeValue(forKey: sid) else { return }
        _poolLock.lock()
        _poolTCPCount = max(0, _poolTCPCount - 1)
        _poolLock.unlock()
        updateIdleCloseTimer()
        conn.handleStreamTermination(error: error)
    }

    // MARK: - Datagram dispatch (UDP)

    private func handleDatagram(_ data: Data) {
        guard let msg = HysteriaProtocol.decodeUDPMessage(data) else { return }
        if let conn = udpSessions[msg.sessionID] {
            conn.handleIncomingDatagram(msg)
        }
        // Unknown sessions are dropped silently; Hysteria has no explicit
        // UDP session teardown handshake.
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
            self.updateIdleCloseTimer()
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
                self.updateIdleCloseTimer()
            }
        }
    }

    // MARK: - UDP session API (called by HysteriaUDPConnection)

    /// Registers a new UDP session. Completion runs on the session queue
    /// and carries a distinct error per failure mode so the caller (and
    /// the `HysteriaClient` retry shim) can tell `udpNotSupported` apart
    /// from a transient `notReady`.
    func registerUDPSession(_ conn: HysteriaUDPConnection, completion: @escaping (Result<UInt32, Error>) -> Void) {
        let body = { [weak self] in
            guard let self else {
                completion(.failure(HysteriaError.streamClosed)); return
            }
            guard self.state == .ready else {
                completion(.failure(HysteriaError.notReady)); return
            }
            guard self.udpSupported else {
                completion(.failure(HysteriaError.udpNotSupported)); return
            }
            // Step past occupied slots after UInt32.max rollover; guard the
            // impossible-but-defensive full-table case explicitly.
            guard self.udpSessions.count < Int(UInt32.max) else {
                completion(.failure(HysteriaError.connectionFailed("UDP session pool exhausted")))
                return
            }
            var sid = self.nextUDPSessionID
            while self.udpSessions[sid] != nil {
                sid = sid == UInt32.max ? 1 : sid + 1
            }
            self.nextUDPSessionID = sid == UInt32.max ? 1 : sid + 1
            self.udpSessions[sid] = conn
            self._poolLock.lock()
            self._poolUDPCount += 1
            self._poolLock.unlock()
            self.updateIdleCloseTimer()
            completion(.success(sid))
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
                self.updateIdleCloseTimer()
            }
        }
    }

    /// Arms or cancels the idle-close timer based on current pool counts.
    /// Must be called on `queue`. Cancels any prior pending close; when the
    /// session currently holds no streams or UDP sessions and is still in
    /// `ready` state, schedules a delayed close that re-checks counts at
    /// fire time so a flurry of "release then open" doesn't tear down the
    /// QUIC connection.
    private func updateIdleCloseTimer() {
        idleCloseWorkItem?.cancel()
        idleCloseWorkItem = nil

        guard state == .ready else { return }
        _poolLock.lock()
        let total = _poolTCPCount + _poolUDPCount
        _poolLock.unlock()
        guard total == 0 else { return }

        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self._poolLock.lock()
            let liveCount = self._poolTCPCount + self._poolUDPCount
            self._poolLock.unlock()
            guard liveCount == 0, self.state == .ready else { return }
            self.close()
        }
        idleCloseWorkItem = work
        queue.asyncAfter(deadline: .now() + Self.idleCloseDelay, execute: work)
    }

    func writeDatagrams(_ datagrams: [Data], completion: @escaping (Error?) -> Void) {
        quic.writeDatagrams(datagrams, completion: completion)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    // MARK: - Close

    func close() {
        // `closeLatch.begin()` gives once-only teardown; the strong `self`
        // capture (not `[weak self]`) keeps the session alive until it runs —
        // an idle session torn down off-queue (interface-change `closeAll`)
        // could otherwise be the last reference and deallocate first, skipping
        // `quic.close()` and leaking the socket + ngtcp2 state.
        let work = {
            guard self.closeLatch.begin() else { return }
            self.state = .closed

            self.idleCloseWorkItem?.cancel()
            self.idleCloseWorkItem = nil

            // Zero counters under the same lock that flips `_poolIsClosed`.
            // The dictionaries are drained below, so the counters were about
            // to be stale otherwise — and any caller that reads
            // `hasActiveConnections` without also checking `poolIsClosed`
            // would see a phantom live count for an already-dead session.
            self._poolLock.lock()
            self._poolIsClosed = true
            self._poolTCPCount = 0
            self._poolUDPCount = 0
            self._poolLock.unlock()

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(HysteriaError.connectionFailed("Session closed")) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(HysteriaError.connectionFailed("Session closed")) }

            self.rejectedServerStreams.removeAll()

            self.quic.close()
            self.onClose?()
        }
        if isOnQueue {
            work()
        } else {
            queue.async(execute: work)
        }
    }

    private func failSession(_ error: Error) {
        // Shares `closeLatch` with `close()` so whichever runs first wins
        // (FIFO on `queue`); strong `self` keeps the session alive through
        // teardown — see `close()`.
        queue.async {
            guard self.closeLatch.begin() else { return }
            self.state = .closed

            self.idleCloseWorkItem?.cancel()
            self.idleCloseWorkItem = nil

            // See `close()` for why the counters are zeroed here too.
            self._poolLock.lock()
            self._poolIsClosed = true
            self._poolTCPCount = 0
            self._poolUDPCount = 0
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

            self.rejectedServerStreams.removeAll()

            self.quic.close()
            self.onClose?()
        }
    }
}
