//
//  QUICConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation
import Network
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "QUIC")

// MARK: - QUICConnection

class QUICConnection {

    enum State {
        case idle, connecting, handshaking, connected, closing, closed
    }

    enum QUICError: Error, LocalizedError {
        case connectionFailed(String)
        case handshakeFailed(String)
        case streamError(String)
        case timeout
        case closed

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let m): return "QUIC: \(m)"
            case .handshakeFailed(let m): return "QUIC TLS: \(m)"
            case .streamError(let m): return "QUIC stream: \(m)"
            case .timeout: return "QUIC timeout"
            case .closed: return "QUIC closed"
            }
        }
    }

    // MARK: Properties

    private let host: String
    private let port: UInt16
    private let serverName: String
    private let alpn: [String]
    private let tuning: QUICTuning

    fileprivate var state: State = .idle
    let queue: DispatchQueue
    private static let queueKey = DispatchSpecificKey<Bool>()

    fileprivate var conn: OpaquePointer?
    private var connRefStorage = ngtcp2_crypto_conn_ref()

    /// True while `handleReceivedPacket` is inside `ngtcp2_swift_conn_read_pkt`.
    /// Callbacks fired by ngtcp2 during read (e.g. recv_stream_data → app →
    /// `extendStreamOffset`) must not trigger a reentrant write — the
    /// tail-flush at the end of `handleReceivedPacket` covers it.
    private var inReadPkt = false

    /// Set when an operation (e.g. `extendStreamOffset`) has queued a
    /// MAX_STREAM_DATA/MAX_DATA update that needs to go out but we don't
    /// want to flush synchronously on the hot path.  Drained at the end
    /// of the current queue cycle via a single coalesced `writeToUDP`.
    private var flushScheduled = false

    private var udpConnection: NWConnection?
    private var localAddr = sockaddr_storage()
    private var remoteAddr = sockaddr_storage()
    /// Actual sockaddr size (either `sockaddr_in` or `sockaddr_in6`).
    private var addrLen: Int = MemoryLayout<sockaddr_in>.size

    fileprivate var tlsHandshaker: QUICTLSHandler?

    private var retransmitTimer: DispatchSourceTimer?

    private var dcid = ngtcp2_cid()
    private var scid = ngtcp2_cid()

    fileprivate var connectCompletion: ((Error?) -> Void)?
    /// Stream data delivery. The `Data` is a zero-copy view into ngtcp2's
    /// receive buffer and is only valid for the duration of this synchronous
    /// call — the handler MUST consume or copy it before returning. Dispatching
    /// the view to another queue without copying is a use-after-free.
    var streamDataHandler: ((Int64, Data, Bool) -> Void)?
    /// Called when a QUIC DATAGRAM frame is received.
    var datagramHandler: ((Data) -> Void)?
    /// Called when the QUIC connection is closed (draining, error, etc.).
    /// Allows the session to react immediately rather than discovering it on the next operation.
    var connectionClosedHandler: ((Error) -> Void)?

    /// When true, advertises DATAGRAM frame support in transport params.
    private let datagramsEnabled: Bool
    /// Maximum DATAGRAM frame size advertised to the peer (what we can receive).
    static let maxDatagramFrameSize: UInt64 = 65535

    /// Pending writes that were blocked by stream flow control.
    /// Flushed when incoming packets extend the window (MAX_STREAM_DATA).
    private var pendingWrites: [PendingWrite] = []

    private struct PendingWrite {
        let streamId: Int64
        var data: Data
        let fin: Bool
        let completion: (Error?) -> Void
    }

    /// Pending datagrams waiting to be sent. Drained in `writeToUDP()` where
    /// they get first priority for congestion window space.
    private var pendingDatagrams: [Data] = []

    static let maxUDPPayload = 1452

    /// Reusable send buffer. writeToUDP() and writeStreamSync() are called
    /// thousands of times per second under bulk transfer; allocating a fresh
    /// 1452-byte `[UInt8]` on each call was a measurable CPU hit. Both run
    /// on `queue` so sharing is safe.
    private var sendBuf = [UInt8](repeating: 0, count: QUICConnection.maxUDPPayload)

    /// Payload sizes PMTUD probes. Must be in (1200, max_tx_udp_payload_size]
    /// — ngtcp2 silently skips probes above `hard_max_udp_payload_size =
    /// min(remote_max_udp_payload_size, settings.max_tx_udp_payload_size)`.
    /// Ascending so each success advances to the next size.
    /// Values copied internally by ngtcp2 at conn-new time.
    private static let pmtudProbes: [UInt16] = [1350, 1400, 1452]

    // MARK: Init

    /// Returns true if the caller is already executing on this connection's queue.
    var isOnQueue: Bool { DispatchQueue.getSpecific(key: Self.queueKey) == true }

    init(host: String, port: UInt16, serverName: String? = nil, alpn: [String] = ["h3"],
         datagramsEnabled: Bool = false, tuning: QUICTuning) {
        self.host = host
        self.port = port
        self.serverName = serverName ?? host
        self.alpn = alpn
        self.datagramsEnabled = datagramsEnabled
        self.tuning = tuning
        self.queue = DispatchQueue(label: "com.argsment.Anywhere.quic")
        queue.setSpecific(key: Self.queueKey, value: true)
    }

    deinit { close() }

    // MARK: Connect

    func connect(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.state == .idle else {
                completion(QUICError.connectionFailed("Invalid state"))
                return
            }
            QUICCrypto.registerCallbacks()
            self.state = .connecting
            self.connectCompletion = completion
            self.setupUDP(completion: completion)
        }
    }

    // MARK: Streams

    func openBidiStream() -> Int64? {
        guard state == .connected, let conn else { return nil }
        var streamId: Int64 = -1
        let streamData: UnsafeMutableRawPointer? = nil
        let rv = ngtcp2_conn_open_bidi_stream(conn, &streamId, streamData)
        if rv != 0 {
            logger.error("[QUIC] Failed to open bidi stream: \(rv)")
            return nil
        }
        return streamId
    }

    func openUniStream() -> Int64? {
        guard state == .connected, let conn else { return nil }
        var streamId: Int64 = -1
        let streamData: UnsafeMutableRawPointer? = nil
        let rv = ngtcp2_conn_open_uni_stream(conn, &streamId, streamData)
        if rv != 0 {
            logger.error("[QUIC] Failed to open uni stream: \(rv)")
            return nil
        }
        return streamId
    }

    /// Extends both the stream-level and connection-level flow control windows.
    /// Called when the application has consumed `count` bytes from a stream,
    /// allowing the server to send more data.
    func extendStreamOffset(_ streamId: Int64, count: Int) {
        guard count > 0 else { return }
        // All ngtcp2_conn_* calls and `flushScheduled`/`inReadPkt` mutation
        // must happen on the QUIC queue.  Off-queue callers bounce through
        // an async; the same async coalesces with any pending flush.
        if isOnQueue {
            extendStreamOffsetOnQueue(streamId, count: count)
        } else {
            queue.async { [weak self] in
                self?.extendStreamOffsetOnQueue(streamId, count: count)
            }
        }
    }

    private func extendStreamOffsetOnQueue(_ streamId: Int64, count: Int) {
        guard let conn else { return }
        ngtcp2_conn_extend_max_stream_offset(conn, streamId, UInt64(count))
        ngtcp2_conn_extend_max_offset(conn, UInt64(count))
        // Coalesce MAX_STREAM_DATA/MAX_DATA flushes: on bulk receive the
        // reader drains one ~1300-byte chunk at a time, each triggering an
        // ack.  Flushing a full writeToUDP cycle per ack burnt CPU on the
        // hot path.  ngtcp2 queues the frame internally; schedule one
        // coalesced flush per queue cycle and let the next organic write
        // (or this async bounce) carry it out.
        //
        // Inside read_pkt: skip entirely — handleReceivedPacket's tail-flush
        // already drains pending updates.  Outside read_pkt: schedule once
        // via queue.async so a run of acks merges into one writeToUDP.
        if inReadPkt { return }
        if flushScheduled { return }
        flushScheduled = true
        queue.async { [weak self] in
            guard let self else { return }
            self.flushScheduled = false
            self.writeToUDP()
        }
    }

    /// Shuts down a stream (sends RESET_STREAM + STOP_SENDING).
    /// This frees the stream ID slot so the server grants new ones via MAX_STREAMS.
    /// - Parameter appErrorCode: Application-layer error code (e.g. an HTTP/3
    ///   error code per RFC 9114 §8.1). Defaults to `H3_NO_ERROR` (0x100).
    func shutdownStream(_ streamId: Int64, appErrorCode: UInt64 = 0x0100) {
        queue.async { [weak self] in
            guard let self, let conn = self.conn else { return }
            ngtcp2_conn_shutdown_stream(conn, 0, streamId, appErrorCode)
            self.writeToUDP()
        }
    }

    func writeStream(_ streamId: Int64, data: Data, fin: Bool = false,
                     completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, let conn = self.conn, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.writeStreamImpl(conn: conn, streamId: streamId,
                                 data: data, fin: fin, completion: completion)
        }
    }

    // MARK: Datagrams

    /// Queues a QUIC DATAGRAM frame for sending.
    ///
    /// The datagram is sent on the next `writeToUDP()` cycle, where it gets
    /// first priority for congestion window space (coalesced with ACKs and
    /// control frames).  QUIC datagrams are unreliable — if the congestion
    /// window is still exhausted after retries, the datagram is silently
    /// dropped (same as UDP packet loss).
    ///
    /// Only returns an error for fatal issues (connection closed, payload
    /// exceeds the remote's max_datagram_frame_size).
    func writeDatagram(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.conn != nil, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.pendingDatagrams.append(data)
            self.writeToUDP()
            completion(nil)
        }
    }

    /// Queues multiple QUIC DATAGRAM frames for sending atomically.
    ///
    /// All datagrams are appended to the pending queue before a single
    /// `writeToUDP()` cycle, preventing interleaving with datagrams from
    /// other concurrent callers.
    func writeDatagrams(_ datagrams: [Data], completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.conn != nil, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.pendingDatagrams.append(contentsOf: datagrams)
            self.writeToUDP()
            completion(nil)
        }
    }

    /// Maximum datagram payload size the remote endpoint can receive.
    /// Returns 0 if datagrams are not supported or the connection isn't ready.
    /// This accounts for the DATAGRAM frame overhead (up to 9 bytes).
    var maxDatagramPayloadSize: Int {
        guard let conn else { return 0 }
        guard let params = ngtcp2_swift_conn_get_remote_transport_params(conn) else { return 0 }
        let maxFrame = Int(params.pointee.max_datagram_frame_size)
        guard maxFrame > 0 else { return 0 }
        // NGTCP2_DATAGRAM_OVERHEAD = 1 (type) + 8 (length varint max) = 9
        return max(0, maxFrame - 9)
    }

    /// Writes stream data, queuing any remainder that can't be sent due to
    /// flow control. Queued data is flushed when incoming packets extend the
    /// window (MAX_STREAM_DATA).
    private func writeStreamImpl(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool,
                                  completion: @escaping (Error?) -> Void) {
        let sent = writeStreamSync(conn: conn, streamId: streamId,
                                    data: data, fin: fin)

        if sent >= data.count {
            completion(nil)
        } else {
            // Stream flow control blocked — queue remainder for later
            let remaining = Data(data[sent...])
            pendingWrites.append(PendingWrite(
                streamId: streamId, data: remaining,
                fin: fin, completion: completion
            ))
        }
    }

    /// Writes as much stream data as possible synchronously.
    /// Returns the number of bytes accepted by ngtcp2.
    private func writeStreamSync(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool) -> Int {
        let ts = currentTimestamp()
        var offset = 0

        while offset < data.count {
            var pi = ngtcp2_pkt_info()
            var pdatalen: ngtcp2_ssize = 0

            let remaining = data.count - offset
            let chunk = data[offset..<data.count]
            let isLast = (offset + remaining >= data.count)
            let flags: UInt32 = {
                var f: UInt32 = 0
                if fin && isLast { f |= UInt32(NGTCP2_WRITE_STREAM_FLAG_FIN) }
                if !isLast { f |= UInt32(NGTCP2_WRITE_STREAM_FLAG_MORE) }
                return f
            }()

            let nwrite: ngtcp2_ssize = chunk.withUnsafeBytes { rawBuf in
                let ptr = rawBuf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                var vec = ngtcp2_vec(base: UnsafeMutablePointer(mutating: ptr),
                                    len: remaining)
                return ngtcp2_swift_conn_writev_stream(
                    conn, nil, &pi, &sendBuf, sendBuf.count,
                    &pdatalen, flags,
                    streamId, &vec, 1, ts
                )
            }

            if nwrite == 0 { break }

            if nwrite < 0 {
                let code = Int32(nwrite)
                if code == NGTCP2_ERR_WRITE_MORE {
                    if pdatalen > 0 { offset += Int(pdatalen) }
                    continue
                }
                if code == NGTCP2_ERR_STREAM_DATA_BLOCKED {
                    if pdatalen > 0 { offset += Int(pdatalen) }
                    break
                }
                if code == NGTCP2_ERR_STREAM_NOT_FOUND || code == NGTCP2_ERR_STREAM_SHUT_WR {
                    break
                }
                break
            }

            sendUDPPacket(Data(sendBuf.prefix(Int(nwrite))))
            if pdatalen > 0 { offset += Int(pdatalen) }
            if pdatalen == 0 { break }
        }

        writeToUDP()
        return offset
    }

    /// Retries pending writes that were blocked by stream flow control.
    /// Called after processing incoming packets which may contain MAX_STREAM_DATA.
    private func flushPendingWrites() {
        guard !pendingWrites.isEmpty, let conn else { return }
        guard state == .connected else {
            let writes = pendingWrites
            pendingWrites.removeAll()
            for pw in writes { pw.completion(QUICError.closed) }
            return
        }

        var remaining: [PendingWrite] = []
        for pw in pendingWrites {
            let sent = writeStreamSync(conn: conn, streamId: pw.streamId,
                                        data: pw.data, fin: pw.fin)
            if sent >= pw.data.count {
                pw.completion(nil)
            } else {
                remaining.append(PendingWrite(
                    streamId: pw.streamId,
                    data: Data(pw.data[sent...]),
                    fin: pw.fin,
                    completion: pw.completion
                ))
            }
        }
        pendingWrites = remaining
    }

    // MARK: Close

    func close(error: Error? = nil) {
        let work = { [weak self] in
            guard let self else { return }
            guard self.state != .closed else { return }
            // Any close that happens before we reached `.connected` means the
            // TLS handshake didn't complete — invalidate any cached session
            // ticket for this (SNI, ALPN) so the next attempt does a full
            // handshake instead of replaying a ticket whose keys the server
            // may have rotated. Without this, one bad ticket produces a
            // permanent HANDSHAKE_TIMEOUT loop across every future session.
            if self.state != .connected {
                invalidateCachedSessionTicket(serverName: self.serverName, alpn: self.alpn)
            }
            self.retransmitTimer?.cancel()
            self.retransmitTimer = nil
            if let conn = self.conn {
                ngtcp2_conn_del(conn)
                self.conn = nil
            }
            self.udpConnection?.forceCancel()
            self.udpConnection = nil
            self.state = .closed
            // Fail any pending writes; drop pending datagrams
            let writes = self.pendingWrites
            self.pendingWrites.removeAll()
            self.pendingDatagrams.removeAll()
            let closeError = error ?? QUICError.closed
            for pw in writes { pw.completion(closeError) }
            self.connectionClosedHandler?(closeError)
            self.connectionClosedHandler = nil
        }
        // When called from the QUIC queue (e.g. handleReceivedPacket detecting
        // DRAINING), execute synchronously so the session's pool-visible state
        // is updated before the pool can hand out new streams.
        if isOnQueue {
            work()
        } else {
            queue.async(execute: work)
        }
    }

    // MARK: UDP

    private func setupUDP(completion: @escaping (Error?) -> Void) {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )
        let connection = NWConnection(to: endpoint, using: .udp)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.queue.async {
                    self.populateRemoteAddr()
                    do {
                        try self.initializeNgtcp2()
                        self.state = .handshaking
                        self.writeToUDP()
                        self.readFromUDP()
                        self.rescheduleTimer()
                    } catch {
                        self.state = .closed
                        completion(error)
                    }
                }
            case .failed(let error):
                self.state = .closed
                completion(error)
            default:
                break
            }
        }
        self.udpConnection = connection
        connection.start(queue: queue)
    }

    private func populateRemoteAddr() {
        // Try IPv4 first
        var addr4 = in_addr()
        if inet_pton(AF_INET, host, &addr4) == 1 {
            configureIPv4(addr4)
            return
        }

        // Try IPv6
        var addr6 = in6_addr()
        if inet_pton(AF_INET6, host, &addr6) == 1 {
            configureIPv6(addr6)
            return
        }

        // DNS resolution — prefer IPv6 if available, fall back to IPv4
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let res = result else { return }
        defer { freeaddrinfo(result) }

        // Walk the result list: prefer IPv4 for now, but accept IPv6
        var found4: UnsafeMutablePointer<addrinfo>?
        var found6: UnsafeMutablePointer<addrinfo>?
        var cur: UnsafeMutablePointer<addrinfo>? = res
        while let r = cur {
            if r.pointee.ai_family == AF_INET && found4 == nil { found4 = r }
            if r.pointee.ai_family == AF_INET6 && found6 == nil { found6 = r }
            cur = r.pointee.ai_next
        }

        if let r = found4, let sa = r.pointee.ai_addr {
            let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            configureIPv4(sin.sin_addr)
        } else if let r = found6, let sa = r.pointee.ai_addr {
            let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            configureIPv6(sin6.sin6_addr)
        }
    }

    private func configureIPv4(_ addr: in_addr) {
        addrLen = MemoryLayout<sockaddr_in>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_port = port.bigEndian
                sin.pointee.sin_addr = addr
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_addr.s_addr = INADDR_ANY
            }
        }
    }

    private func configureIPv6(_ addr: in6_addr) {
        addrLen = MemoryLayout<sockaddr_in6>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                sin6.pointee = sockaddr_in6()
                sin6.pointee.sin6_len = UInt8(addrLen)
                sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                sin6.pointee.sin6_port = port.bigEndian
                sin6.pointee.sin6_addr = addr
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                sin6.pointee = sockaddr_in6()
                sin6.pointee.sin6_len = UInt8(addrLen)
                sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                sin6.pointee.sin6_addr = in6addr_any
            }
        }
    }

    private func sendUDPPacket(_ data: Data) {
        // `.idempotent` skips per-packet completion delivery. UDP is
        // fire-and-forget; `NWConnection` still surfaces fatal transport
        // errors via its stateUpdateHandler, so we don't need per-datagram
        // error callbacks — and allocating a completion closure per packet
        // was a measurable hot-path cost under bulk (~9k packets/s at
        // 100 Mbps).
        udpConnection?.send(content: data, completion: .idempotent)
    }

    private func readFromUDP() {
        udpConnection?.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            // NWConnection dispatches on our queue (started with queue:),
            // so no need for queue.async — process immediately.
            if let data, !data.isEmpty {
                self.handleReceivedPacket(data)
            }
            if error == nil { self.readFromUDP() }
        }
    }

    // MARK: ngtcp2 Init

    private func initializeNgtcp2() throws {
        generateConnectionID(&dcid, length: 16)
        generateConnectionID(&scid, length: 16)

        tlsHandshaker = QUICTLSHandler(serverName: serverName, alpn: alpn)

        var callbacks = ngtcp2_callbacks()
        callbacks.client_initial = quicClientInitialCB
        callbacks.recv_crypto_data = quicRecvCryptoDataCB
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb
        callbacks.recv_stream_data = quicRecvStreamDataCB
        callbacks.acked_stream_data_offset = quicAckedCB
        callbacks.stream_close = quicStreamCloseCB
        callbacks.rand = quicRandCB
        callbacks.get_new_connection_id2 = quicGetNewCIDCB
        callbacks.update_key = ngtcp2_crypto_update_key_cb
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb
        callbacks.handshake_completed = quicHandshakeCompletedCB
        if datagramsEnabled {
            callbacks.recv_datagram = quicRecvDatagramCB
        }

        var settings = ngtcp2_settings()
        ngtcp2_swift_settings_default(&settings)
        settings.initial_ts = currentTimestamp()
        settings.max_tx_udp_payload_size = Self.maxUDPPayload
        settings.cc_algo = tuning.ccAlgo
        settings.max_stream_window = tuning.maxStreamWindow
        settings.max_window = tuning.maxWindow
        settings.handshake_timeout = tuning.handshakeTimeout
        var params = ngtcp2_transport_params()
        ngtcp2_swift_transport_params_default(&params)
        params.initial_max_streams_bidi = tuning.initialMaxStreamsBidi
        params.initial_max_streams_uni = tuning.initialMaxStreamsUni
        params.initial_max_data = tuning.initialMaxData
        params.initial_max_stream_data_bidi_local = tuning.initialMaxStreamDataBidiLocal
        params.initial_max_stream_data_bidi_remote = tuning.initialMaxStreamDataBidiRemote
        params.initial_max_stream_data_uni = tuning.initialMaxStreamDataUni
        params.max_idle_timeout = tuning.maxIdleTimeout
        params.disable_active_migration = tuning.disableActiveMigration ? 1 : 0
        if datagramsEnabled {
            params.max_datagram_frame_size = Self.maxDatagramFrameSize
        }

        var path = ngtcp2_path()
        withUnsafeMutablePointer(to: &localAddr) { local in
            withUnsafeMutablePointer(to: &remoteAddr) { remote in
                path.local = ngtcp2_addr(
                    addr: UnsafeMutableRawPointer(local).assumingMemoryBound(to: sockaddr.self),
                    addrlen: ngtcp2_socklen(addrLen))
                path.remote = ngtcp2_addr(
                    addr: UnsafeMutableRawPointer(remote).assumingMemoryBound(to: sockaddr.self),
                    addrlen: ngtcp2_socklen(addrLen))
            }
        }

        connRefStorage.user_data = Unmanaged.passUnretained(self).toOpaque()
        connRefStorage.get_conn = { ref in
            guard let ref, let ud = ref.pointee.user_data else { return nil }
            return Unmanaged<QUICConnection>.fromOpaque(ud).takeUnretainedValue().conn
        }

        var connPtr: OpaquePointer?
        let rv = Self.pmtudProbes.withUnsafeBufferPointer { probes -> Int32 in
            settings.pmtud_probes = probes.baseAddress
            settings.pmtud_probeslen = probes.count
            return ngtcp2_swift_conn_client_new(
                &connPtr, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                &callbacks, &settings, &params, nil, &connRefStorage
            )
        }
        guard rv == 0, let connPtr else {
            throw QUICError.connectionFailed("ngtcp2_conn_client_new: \(rv)")
        }
        self.conn = connPtr

        // Emit a PING every 15 s of inactivity so a silently-broken UDP path
        // (carrier NAT rebind, server-side idle sweep) surfaces as a loss /
        // idle-close within one retransmission cycle rather than waiting for
        // the next app write to hit CONNECTION_CLOSE. Mirrors naiveproxy's
        // `set_keep_alive_ping_timeout(kPingTimeoutSecs)`.
        ngtcp2_conn_set_keep_alive_timeout(connPtr, 15 * 1_000_000_000)

        ngtcp2_conn_set_tls_native_handle(connPtr,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256)))
    }

    // MARK: Packet Processing

    fileprivate func handleReceivedPacket(_ data: Data) {
        guard let conn else { return }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        inReadPkt = true
        defer { inReadPkt = false }

        let rv: Int32 = data.withUnsafeBytes { raw in
            guard let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            var path = ngtcp2_path()
            withUnsafeMutablePointer(to: &localAddr) { local in
                withUnsafeMutablePointer(to: &remoteAddr) { remote in
                    path.local = ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(local).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen))
                    path.remote = ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(remote).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen))
                }
            }
            return ngtcp2_swift_conn_read_pkt(conn, &path, &pi, ptr, data.count, ts)
        }

        if rv != 0 {
            logger.error("[QUIC] read_pkt error: \(rv)")
            if rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING {
                let error = QUICError.closed
                if let cb = connectCompletion {
                    connectCompletion = nil
                    cb(error)
                }
                close(error: error)
                return
            }
            // Fatal errors (e.g. TLS callback failure) — close and notify
            if rv == NGTCP2_ERR_CALLBACK_FAILURE || rv == NGTCP2_ERR_CRYPTO {
                let error = QUICError.handshakeFailed("ngtcp2 error: \(rv)")
                if let cb = connectCompletion {
                    connectCompletion = nil
                    cb(error)
                }
                close(error: error)
                return
            }
        }
        writeToUDP()
        // Incoming packets may contain MAX_STREAM_DATA, extending the send
        // window.  Retry any writes that were blocked by flow control.
        flushPendingWrites()
    }

    fileprivate func writeToUDP() {
        guard let conn else { return }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        // Drain pending datagrams first. `write_datagram` also flushes ACKs,
        // retransmissions and control frames — so the datagram is coalesced
        // into the same packet, giving it fair access to the congestion window
        // instead of being starved by `write_pkt`.
        while !pendingDatagrams.isEmpty {
            var accepted: Int32 = 0
            let dgram = pendingDatagrams[0]

            let nwrite: ngtcp2_ssize = dgram.withUnsafeBytes { rawBuf in
                guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return 0
                }
                return ngtcp2_swift_conn_write_datagram(
                    conn, nil, &pi, &sendBuf, sendBuf.count,
                    &accepted, 0, 0, ptr, dgram.count, ts
                )
            }

            if nwrite < 0 {
                // Fatal error (too large, unsupported) — drop this datagram
                pendingDatagrams.removeFirst()
                continue
            }
            if nwrite > 0 {
                sendUDPPacket(Data(sendBuf.prefix(Int(nwrite))))
            }
            if accepted != 0 {
                pendingDatagrams.removeFirst()
            } else {
                // Congestion window full — stop trying, remaining datagrams
                // will be attempted on the next writeToUDP() cycle.
                break
            }
        }

        // Flush any remaining control/stream packets that write_datagram
        // didn't cover (e.g. when no datagrams were pending).
        while true {
            let nwrite = ngtcp2_swift_conn_write_pkt(conn, nil, &pi, &sendBuf, sendBuf.count, ts)
            if nwrite <= 0 { break }
            sendUDPPacket(Data(sendBuf.prefix(Int(nwrite))))
        }
        // Any ngtcp2 operation may change the next deadline (retransmission,
        // ACK, PING, etc.).  Keep the timer aligned with ngtcp2's state.
        rescheduleTimer()
    }

    // MARK: Timer

    /// Schedules a one-shot timer at the exact deadline ngtcp2 needs
    /// (retransmission, loss detection, etc.).  Replaces the old 50ms
    /// polling timer with a precise, event-driven alarm — matching
    /// Chromium/QUICHE's QuicAlarm approach.
    private var lastScheduledExpiry: UInt64 = 0

    private func rescheduleTimer() {
        guard let conn else { return }
        let expiry = ngtcp2_conn_get_expiry(conn)

        // Short-circuit when the deadline hasn't moved.  Under bulk transfer
        // ngtcp2's expiry shifts on nearly every ACK — creating a fresh
        // DispatchSourceTimer each time was a measurable CPU sink.
        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        if retransmitTimer == nil {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.setEventHandler { [weak self] in
                guard let self, let conn = self.conn else { return }
                self.lastScheduledExpiry = 0
                let ts = self.currentTimestamp()
                let rv = ngtcp2_conn_handle_expiry(conn, ts)
                if rv != 0 {
                    let error = QUICError.connectionFailed("expiry error: \(rv)")
                    if let cb = self.connectCompletion {
                        self.connectCompletion = nil
                        cb(error)
                    }
                    self.close(error: error)
                    return
                }
                self.writeToUDP()
                // writeToUDP() calls rescheduleTimer() at the end
            }
            retransmitTimer = timer
            timer.resume()
        }

        let deadline: DispatchTime
        if expiry == UInt64.max {
            deadline = .distantFuture
        } else {
            let now = currentTimestamp()
            let delay = expiry > now ? expiry - now : 0
            deadline = .now() + .nanoseconds(Int(min(delay, UInt64(Int.max))))
        }
        // BBR relies on sub-millisecond inter-packet pacing accuracy; a loose
        // leeway lets the dispatch scheduler coalesce wakeups, converting
        // smooth pacing into bursts that trip loss detection.  Matches
        // QUICHE's `QuicAlarm` precision (no leeway).
        retransmitTimer?.schedule(deadline: deadline, leeway: .nanoseconds(0))
    }

    // MARK: Utilities

    fileprivate func currentTimestamp() -> ngtcp2_tstamp {
        ngtcp2_tstamp(DispatchTime.now().uptimeNanoseconds)
    }

    private func generateConnectionID(_ cid: inout ngtcp2_cid, length: Int) {
        var data = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &data)
        cid.datalen = length
        withUnsafeMutableBytes(of: &cid.data) { buf in
            data.withUnsafeBytes { src in
                buf.copyMemory(from: UnsafeRawBufferPointer(
                    start: src.baseAddress, count: min(length, buf.count)))
            }
        }
    }
}

// MARK: - ngtcp2 Callbacks

private func qcFromUserData(_ ud: UnsafeMutableRawPointer?) -> QUICConnection? {
    guard let ud else { return nil }
    let ref = ud.assumingMemoryBound(to: ngtcp2_crypto_conn_ref.self)
    guard let p = ref.pointee.user_data else { return nil }
    return Unmanaged<QUICConnection>.fromOpaque(p).takeUnretainedValue()
}

private let quicClientInitialCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { conn, ud in
    guard let conn else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let dcid = ngtcp2_conn_get_client_initial_dcid(conn) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    let n: UnsafeMutablePointer<UInt8>? = nil
    if ngtcp2_crypto_derive_and_install_initial_key(
        conn, n, n, n, n, n, n, n, n, n, NGTCP2_PROTO_VER_V1, dcid) != 0 {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    guard let qc = qcFromUserData(ud), let tls = qc.tlsHandshaker else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    var pb = [UInt8](repeating: 0, count: 256)
    let pLen = ngtcp2_conn_encode_local_transport_params(conn, &pb, pb.count)
    guard pLen >= 0 else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let ch = tls.buildClientHello(transportParams: Data(pb.prefix(Int(pLen)))) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    return ch.withUnsafeBytes { buf -> Int32 in
        guard let p = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return NGTCP2_ERR_CALLBACK_FAILURE
        }
        return ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, p, ch.count)
    }
}

private let quicRecvCryptoDataCB: @convention(c) (
    OpaquePointer?, ngtcp2_encryption_level, UInt64,
    UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { conn, level, _, data, datalen, ud in
    guard let conn, let data, datalen > 0 else { return 0 }
    guard let qc = qcFromUserData(ud), let tls = qc.tlsHandshaker else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    let d = Data(bytes: data, count: datalen)
    switch tls.processCryptoData(d, level: level, conn: conn) {
    case .success, .needMoreData: return 0
    case .error(let c): return c
    }
}

private let quicRecvStreamDataCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { conn, flags, sid, offset, data, datalen, ud, _ in
    guard let conn, let qc = qcFromUserData(ud) else { return 0 }
    let fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0
    if let data, datalen > 0 {
        // Wrap ngtcp2's buffer without copying. streamDataHandler runs
        // synchronously on this thread and appends into its own storage
        // before returning, so the pointer stays valid. Saves one
        // full memcpy (≈ datalen bytes) per received packet — meaningful
        // under bulk transfer where this fires thousands of times/s.
        let view = Data(
            bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
            count: datalen,
            deallocator: .none
        )
        qc.streamDataHandler?(sid, view, fin)
    } else if fin {
        qc.streamDataHandler?(sid, Data(), true)
    }
    // Flow control window is NOT extended here.  It is extended later by
    // extendStreamOffset() when the application actually consumes the data.
    // This provides backpressure to the server so it doesn't outrun lwIP's
    // pbuf pool.
    return 0
}

private let quicAckedCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, _, _, _, _, _ in 0 }

private let quicStreamCloseCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, _, _, _, _, _ in 0 }

private let quicRandCB: @convention(c) (
    UnsafeMutablePointer<UInt8>?, Int, UnsafePointer<ngtcp2_rand_ctx>?
) -> Void = { dest, len, _ in
    guard let dest else { return }
    _ = SecRandomCopyBytes(kSecRandomDefault, len, dest)
}

private let quicGetNewCIDCB: @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<ngtcp2_cid>?,
    UnsafeMutablePointer<ngtcp2_stateless_reset_token>?,
    Int, UnsafeMutableRawPointer?
) -> Int32 = { _, cid, token, cidlen, _ in
    guard let cid, let token else { return NGTCP2_ERR_CALLBACK_FAILURE }
    var d = [UInt8](repeating: 0, count: cidlen)
    guard SecRandomCopyBytes(kSecRandomDefault, cidlen, &d) == errSecSuccess else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    cid.pointee.datalen = cidlen
    withUnsafeMutableBytes(of: &cid.pointee.data) { buf in
        d.withUnsafeBytes { src in
            buf.copyMemory(from: UnsafeRawBufferPointer(start: src.baseAddress,
                                                         count: min(cidlen, buf.count)))
        }
    }
    withUnsafeMutableBytes(of: &token.pointee) { buf in
        _ = SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
    }
    return 0
}

private let quicHandshakeCompletedCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, ud in
    guard let qc = qcFromUserData(ud) else { return 0 }
    qc.queue.async {
        qc.state = .connected
        qc.connectCompletion?(nil)
        qc.connectCompletion = nil
    }
    return 0
}

private let quicRecvDatagramCB: @convention(c) (
    OpaquePointer?, UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { _, _, data, datalen, ud in
    guard let data, datalen > 0, let qc = qcFromUserData(ud) else { return 0 }
    let d = Data(bytes: data, count: datalen)
    qc.datagramHandler?(d)
    return 0
}
