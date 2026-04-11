//
//  QUICConnection.swift
//  Anywhere
//
//  Swift wrapper around ngtcp2 for QUIC client connections.
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
    private let sni: String
    private let alpn: [String]

    fileprivate var state: State = .idle
    fileprivate let queue = DispatchQueue(label: "com.argsment.Anywhere.quic")

    fileprivate var conn: OpaquePointer?
    private var connRefStorage = ngtcp2_crypto_conn_ref()

    private var udpConnection: NWConnection?
    private var localAddr: sockaddr_in = {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = INADDR_ANY
        return addr
    }()
    private var remoteAddr: sockaddr_in = {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        return addr
    }()

    fileprivate var tlsHandshaker: QUICTLSHandler?

    private var retransmitTimer: DispatchSourceTimer?

    private var dcid = ngtcp2_cid()
    private var scid = ngtcp2_cid()

    fileprivate var connectCompletion: ((Error?) -> Void)?
    var streamDataHandler: ((Int64, Data, Bool) -> Void)?

    static let maxUDPPayload = 1452

    // MARK: Init

    init(host: String, port: UInt16, sni: String? = nil, alpn: [String] = ["h3"]) {
        self.host = host
        self.port = port
        self.sni = sni ?? host
        self.alpn = alpn
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

    func writeStream(_ streamId: Int64, data: Data, fin: Bool = false,
                     completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, let conn = self.conn, self.state == .connected else {
                completion(QUICError.closed)
                return
            }

            let ts = self.currentTimestamp()
            var offset = 0

            while offset < data.count {
                var packetBuf = [UInt8](repeating: 0, count: Self.maxUDPPayload)
                var pi = ngtcp2_pkt_info()
                var pdatalen: ngtcp2_ssize = 0

                let remaining = data.count - offset
                let chunk = data[offset..<data.count]

                let nwrite: ngtcp2_ssize = chunk.withUnsafeBytes { rawBuf in
                    let ptr = rawBuf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    var vec = ngtcp2_vec(base: UnsafeMutablePointer(mutating: ptr),
                                        len: remaining)
                    let isFin = fin && (offset + remaining >= data.count)
                    let flags: UInt32 = isFin ? UInt32(NGTCP2_WRITE_STREAM_FLAG_FIN) : 0
                    return ngtcp2_swift_conn_writev_stream(
                        conn, nil, &pi, &packetBuf, packetBuf.count,
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
                    if code == NGTCP2_ERR_STREAM_DATA_BLOCKED { break }
                    logger.error("[QUIC] writev_stream failed: \(nwrite)")
                    completion(QUICError.streamError("Write failed: \(nwrite)"))
                    return
                }

                self.sendUDPPacket(Data(packetBuf.prefix(Int(nwrite))))
                if pdatalen > 0 { offset += Int(pdatalen) }
                if pdatalen == 0 { break }
            }

            self.writeToUDP()
            completion(nil)
        }
    }

    // MARK: Close

    func close() {
        queue.async { [weak self] in
            guard let self else { return }
            self.retransmitTimer?.cancel()
            self.retransmitTimer = nil
            if let conn = self.conn {
                ngtcp2_conn_del(conn)
                self.conn = nil
            }
            self.udpConnection?.forceCancel()
            self.udpConnection = nil
            self.state = .closed
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
                        self.startRetransmitTimer()
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
        remoteAddr.sin_port = port.bigEndian
        var addr = in_addr()
        if inet_pton(AF_INET, host, &addr) == 1 {
            remoteAddr.sin_addr = addr
        } else {
            var hints = addrinfo()
            hints.ai_family = AF_INET
            hints.ai_socktype = SOCK_DGRAM
            var result: UnsafeMutablePointer<addrinfo>?
            if getaddrinfo(host, nil, &hints, &result) == 0, let res = result {
                if let sa = res.pointee.ai_addr, res.pointee.ai_family == AF_INET {
                    let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    remoteAddr.sin_addr = sin.sin_addr
                }
                freeaddrinfo(result)
            }
        }
    }

    private func sendUDPPacket(_ data: Data) {
        udpConnection?.send(content: data, completion: .contentProcessed { error in
            if let error {
                logger.error("[QUIC] UDP send error: \(error.localizedDescription)")
            }
        })
    }

    private func readFromUDP() {
        udpConnection?.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.queue.async { self.handleReceivedPacket(data) }
            }
            if error == nil { self.readFromUDP() }
        }
    }

    // MARK: ngtcp2 Init

    private func initializeNgtcp2() throws {
        generateConnectionID(&dcid, length: 16)
        generateConnectionID(&scid, length: 16)

        tlsHandshaker = QUICTLSHandler(sni: sni, alpn: alpn)

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

        var settings = ngtcp2_settings()
        ngtcp2_swift_settings_default(&settings)
        settings.initial_ts = currentTimestamp()
        settings.max_tx_udp_payload_size = Self.maxUDPPayload

        var params = ngtcp2_transport_params()
        ngtcp2_swift_transport_params_default(&params)
        params.initial_max_streams_bidi = 100
        params.initial_max_streams_uni = 3
        params.initial_max_data = 64 * 1024 * 1024
        params.initial_max_stream_data_bidi_local = 64 * 1024 * 1024
        params.initial_max_stream_data_bidi_remote = 64 * 1024 * 1024
        params.initial_max_stream_data_uni = 64 * 1024 * 1024

        var path = ngtcp2_path()
        withUnsafeMutablePointer(to: &localAddr) { local in
            withUnsafeMutablePointer(to: &remoteAddr) { remote in
                path.local = ngtcp2_addr(
                    addr: UnsafeMutableRawPointer(local).assumingMemoryBound(to: sockaddr.self),
                    addrlen: ngtcp2_socklen(MemoryLayout<sockaddr_in>.size))
                path.remote = ngtcp2_addr(
                    addr: UnsafeMutableRawPointer(remote).assumingMemoryBound(to: sockaddr.self),
                    addrlen: ngtcp2_socklen(MemoryLayout<sockaddr_in>.size))
            }
        }

        connRefStorage.user_data = Unmanaged.passUnretained(self).toOpaque()
        connRefStorage.get_conn = { ref in
            guard let ref, let ud = ref.pointee.user_data else { return nil }
            return Unmanaged<QUICConnection>.fromOpaque(ud).takeUnretainedValue().conn
        }

        var connPtr: OpaquePointer?
        let rv = ngtcp2_swift_conn_client_new(
            &connPtr, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
            &callbacks, &settings, &params, nil, &connRefStorage
        )
        guard rv == 0, let connPtr else {
            throw QUICError.connectionFailed("ngtcp2_conn_client_new: \(rv)")
        }
        self.conn = connPtr

        ngtcp2_conn_set_tls_native_handle(connPtr,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256)))
    }

    // MARK: Packet Processing

    fileprivate func handleReceivedPacket(_ data: Data) {
        guard let conn else { return }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        let rv: Int32 = data.withUnsafeBytes { raw in
            guard let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            var path = ngtcp2_path()
            withUnsafeMutablePointer(to: &localAddr) { local in
                withUnsafeMutablePointer(to: &remoteAddr) { remote in
                    path.local = ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(local).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(MemoryLayout<sockaddr_in>.size))
                    path.remote = ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(remote).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(MemoryLayout<sockaddr_in>.size))
                }
            }
            return ngtcp2_swift_conn_read_pkt(conn, &path, &pi, ptr, data.count, ts)
        }

        if rv != 0 {
            logger.error("[QUIC] read_pkt error: \(rv)")
            if rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING {
                close()
                return
            }
        }
        writeToUDP()
    }

    fileprivate func writeToUDP() {
        guard let conn else { return }
        let ts = currentTimestamp()
        var buf = [UInt8](repeating: 0, count: Self.maxUDPPayload)
        var pi = ngtcp2_pkt_info()

        while true {
            let nwrite = ngtcp2_swift_conn_write_pkt(conn, nil, &pi, &buf, buf.count, ts)
            if nwrite <= 0 { break }
            sendUDPPacket(Data(buf.prefix(Int(nwrite))))
        }
    }

    // MARK: Timer

    private func startRetransmitTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(50),
                      repeating: .milliseconds(50), leeway: .milliseconds(10))
        timer.setEventHandler { [weak self] in
            guard let self, let conn = self.conn else { return }
            let ts = self.currentTimestamp()
            let expiry = ngtcp2_conn_get_expiry(conn)
            if expiry <= ts {
                let rv = ngtcp2_conn_handle_expiry(conn, ts)
                if rv != 0 { return }
                self.writeToUDP()
            }
        }
        timer.resume()
        retransmitTimer = timer
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
        qc.streamDataHandler?(sid, Data(bytes: data, count: datalen), fin)
    } else if fin {
        qc.streamDataHandler?(sid, Data(), true)
    }
    ngtcp2_conn_extend_max_stream_offset(conn, sid, UInt64(datalen))
    ngtcp2_conn_extend_max_offset(conn, UInt64(datalen))
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
