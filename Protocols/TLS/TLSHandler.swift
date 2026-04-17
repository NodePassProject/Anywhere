//
//  TLSHandler.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/17/26.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "TLS")

// MARK: - Session ticket cache

/// Serialized wolfSSL session keyed by `(serverName, alpn)`.
private let ticketCacheLock = UnfairLock()
private var sessionTicketCache: [String: Data] = [:]

private func sessionTicketCacheKey(serverName: String, alpn: [String]) -> String {
    return "\(serverName)\u{0}\(alpn.joined(separator: ","))"
}

func invalidateTLSSessionTicket(serverName: String, alpn: [String]) {
    let key = sessionTicketCacheKey(serverName: serverName, alpn: alpn)
    ticketCacheLock.lock()
    sessionTicketCache.removeValue(forKey: key)
    ticketCacheLock.unlock()
}

// MARK: - wolfSSL one-shot init

nonisolated(unsafe) private var wolfSSLInitRv: Int32 = 0
private let wolfSSLInitialized: Bool = {
    wolfSSLInitRv = wolfSSL_Init()
    // wolfSSL_Debugging_ON()  // uncomment + define DEBUG_WOLFSSL in user_settings.h
    return wolfSSLInitRv == WOLFSSL_SUCCESS
}()

// MARK: - TLSHandler

final class TLSHandler {

    // MARK: - Properties

    private let configuration: TLSConfiguration
    private var session: TLSSession?
    private var completion: ((Result<TLSRecordConnection, Error>) -> Void)?
    private let completionLock = UnfairLock()

    // MARK: - Lifecycle

    init(configuration: TLSConfiguration) {
        self.configuration = configuration
    }

    deinit {
        // If the caller never drove us to completion, the session and its
        // wolfSSL handles are still alive here; TLSSession.deinit cleans them up.
    }

    // MARK: - Public API

    func connect(
        host: String,
        port: UInt16,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        setCompletion(completion)
        do {
            let session = try buildSession()
            self.session = session
            let transport = RawTCPSocket()
            session.connection = transport
            transport.connect(host: host, port: port, initialData: nil) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.deliver(.failure(TLSError.connectionFailed(error.localizedDescription)))
                    return
                }
                self.startHandshake()
            }
        } catch {
            deliver(.failure(error))
        }
    }

    func connect(
        overTunnel tunnel: ProxyConnection,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        setCompletion(completion)
        do {
            let session = try buildSession()
            self.session = session
            session.connection = TunneledTransport(tunnel: tunnel)
            startHandshake()
        } catch {
            deliver(.failure(error))
        }
    }

    func cancel() {
        guard let session else { return }
        session.queue.async {
            session.cancelled = true
            session.connection?.forceCancel()
            session.connection = nil
        }
    }

    // MARK: - Session setup

    private func buildSession() throws -> TLSSession {
        guard wolfSSLInitialized else {
            throw TLSError.handshakeFailed("wolfSSL_Init failed rv=\(wolfSSLInitRv)")
        }

        // Version-flexible method: starts at the highest supported (TLS 1.3)
        // and flips `method->downgrade = 1` so a server that picks 1.2 via
        // legacy_version (no supported_versions extension in ServerHello)
        // falls through wolfSSL's internal 1.3→1.2 path instead of tripping
        // VERSION_ERROR. The browser-fingerprinted ClientHello already
        // advertises both 1.3 and 1.2 in supported_versions + cipher_suites,
        // so there's nothing extra to do on the emit side.
        //
        // Our custom-CH hook still fires because wolfSSL_connect starts on
        // the 1.3 emit path (SendTls13ClientHello); the downgrade branch
        // only runs inside DoTls13ServerHello, after our body is on the wire.
        guard let method = wolfSSLv23_client_method(),
              let ctx = wolfSSL_CTX_new(method) else {
            throw TLSError.handshakeFailed("wolfSSL_CTX_new failed")
        }

        wolfSSL_CTX_set_verify(ctx, Int32(WOLFSSL_VERIFY_PEER), certVerifyCallback)
        wolfSSL_CTX_sess_set_new_cb(ctx, sessionNewCallback)
        wolfSSL_CTX_SetIORecv(ctx, ioRecvCallback)
        wolfSSL_CTX_SetIOSend(ctx, ioSendCallback)

        guard let ssl = wolfSSL_new(ctx) else {
            wolfSSL_CTX_free(ctx)
            throw TLSError.handshakeFailed("wolfSSL_new failed")
        }

        let queue = DispatchQueue(label: "TLSHandler.session")
        let session = TLSSession(ctx: ctx, ssl: ssl, queue: queue)

        // Hand a borrowed pointer to wolfSSL for the BIO callbacks and the
        // session-ticket callback. TLSSession lives for as long as either
        // TLSHandler or (later) TLSRecordConnection holds a strong ref; the
        // pointer is valid for that entire window.
        let sessionHandle = UnsafeMutableRawPointer(
            Unmanaged.passUnretained(session).toOpaque())
        wolfSSL_SetIOReadCtx(ssl, sessionHandle)
        wolfSSL_SetIOWriteCtx(ssl, sessionHandle)
        _ = wolfSSL_set_ex_data(ssl, 1, sessionHandle)

        // SNI
        _ = configuration.serverName.withCString { name in
            wolfSSL_UseSNI(ssl, UInt8(WOLFSSL_SNI_HOST_NAME),
                           name, UInt16(strlen(name)))
        }

        // ALPN — OpenSSL wire format: length-prefixed concatenation.
        let alpnProtocols = configuration.alpn ?? ["h2", "http/1.1"]
        var alpnWire: [UInt8] = []
        for proto in alpnProtocols {
            let bytes = Array(proto.utf8)
            precondition(bytes.count <= 255, "ALPN protocol too long: \(proto)")
            alpnWire.append(UInt8(bytes.count))
            alpnWire.append(contentsOf: bytes)
        }
        _ = alpnWire.withUnsafeBufferPointer { buf in
            wolfSSL_set_alpn_protos(ssl, buf.baseAddress, UInt32(buf.count))
        }

        // Cached session (if any). Not fatal if it fails.
        loadCachedSession(into: ssl)

        // Client random — 32 bytes embedded at offset 2 of the custom body;
        // same bytes parked in ssl->arrays->clientRandom so key derivation
        // stays consistent.
        var clientRandom = [UInt8](repeating: 0, count: 32)
        _ = clientRandom.withUnsafeMutableBufferPointer { buf in
            SecRandomCopyBytes(kSecRandomDefault, 32, buf.baseAddress!)
        }

        // X25519 keypair. Browsers all include X25519 as their real
        // key_share; fingerprints that *also* announce P-256 or the
        // MLKEM hybrid in key_share get those as fake entries via the
        // builder — the server picks X25519 because it's the only real
        // one we can complete. If we ever need P-256 for real, add a
        // second OfferKeyShare call here.
        let x25519Priv = Curve25519.KeyAgreement.PrivateKey()
        let x25519PrivRaw = x25519Priv.rawRepresentation
        let x25519PubRaw  = x25519Priv.publicKey.rawRepresentation

        try x25519PubRaw.withUnsafeBytes { pubPtr in
            try x25519PrivRaw.withUnsafeBytes { privPtr in
                let pubBytes  = pubPtr.bindMemory(to: UInt8.self)
                let privBytes = privPtr.bindMemory(to: UInt8.self)
                let rv = wolfSSL_OfferKeyShare(
                    ssl, TLSNamedGroup.x25519,
                    pubBytes.baseAddress, UInt32(pubBytes.count),
                    privBytes.baseAddress, UInt32(privBytes.count))
                if rv != WOLFSSL_SUCCESS {
                    throw TLSError.handshakeFailed("OfferKeyShare rv=\(rv)")
                }
            }
        }

        // Build the fingerprinted ClientHello body. `buildRawClientHello`
        // emits type + 3-byte-length + body; wolfSSL adds its own
        // handshake header so we strip the first 4 bytes.
        var sessionIdBytes = [UInt8](repeating: 0, count: 32)
        _ = sessionIdBytes.withUnsafeMutableBufferPointer { buf in
            SecRandomCopyBytes(kSecRandomDefault, 32, buf.baseAddress!)
        }
        let fullHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: Data(clientRandom),
            sessionId: Data(sessionIdBytes),
            serverName: configuration.serverName,
            publicKey: x25519PubRaw,
            alpn: configuration.alpn ?? ["h2", "http/1.1"],
            omitPQKeyShares: true
        )
        guard fullHello.count > 4 else {
            throw TLSError.handshakeFailed("ClientHello build returned empty body")
        }
        // Strip extensions wolfSSL can't handle so the server doesn't send
        // response messages wolfSSL doesn't recognise. wolfSSL 5.9.1 has no
        // RFC 8879 CompressedCertificate support; if we advertise
        // compress_certificate (0x001B) the server sends message type 25
        // and wolfSSL errors with OUT_OF_ORDER_E (-394).
        let strippedBody = Self.stripExtensions(
            from: Array(fullHello[4...]),
            types: [0x001B])
        session.clientHelloBody = strippedBody

        // Push the client random into wolfSSL's arrays.
        let setRandomRv = clientRandom.withUnsafeBufferPointer { buf -> Int32 in
            wolfSSL_SetClientHelloRandom(ssl, buf.baseAddress)
        }
        if setRandomRv != WOLFSSL_SUCCESS {
            throw TLSError.handshakeFailed("SetClientHelloRandom rv=\(setRandomRv)")
        }

        // Park the legacy_session_id on ssl->session->sessionID. Without
        // this the server's echoed ID doesn't match what wolfSSL thinks
        // it sent (wolfSSL generated its own internally in GetTls13SessionId
        // before our patch overwrote the wire body) and DoTls13ServerHello
        // aborts with INVALID_PARAMETER (-425).
        let setIdRv = sessionIdBytes.withUnsafeBufferPointer { buf -> Int32 in
            wolfSSL_SetClientHelloLegacySessionId(ssl, buf.baseAddress, UInt32(buf.count))
        }
        if setIdRv != WOLFSSL_SUCCESS {
            throw TLSError.handshakeFailed("SetClientHelloLegacySessionId rv=\(setIdRv)")
        }

        // Parse the cipher-suite list out of the body and hand it back to
        // wolfSSL so ServerHello suite validation has the same set.
        //
        //     offset  field
        //     0..1    legacy_version
        //     2..33   random
        //     34      session_id length
        //     35..    session_id
        //     +0..1   cipher_suites length (U16)
        //     +2..    cipher_suites
        let body = session.clientHelloBody
        let sessIdLen = Int(body[34])
        let suitesLenOff = 34 + 1 + sessIdLen
        let suitesLen = (Int(body[suitesLenOff]) << 8) | Int(body[suitesLenOff + 1])
        let suitesStart = suitesLenOff + 2
        let suites = Array(body[suitesStart..<(suitesStart + suitesLen)])
        let setSuitesRv = suites.withUnsafeBufferPointer { buf -> Int32 in
            wolfSSL_OfferCipherSuites(ssl, buf.baseAddress, UInt32(buf.count))
        }
        if setSuitesRv != WOLFSSL_SUCCESS {
            throw TLSError.handshakeFailed("OfferCipherSuites rv=\(setSuitesRv)")
        }

        // Install the custom-CH callback. The callback returns a pointer
        // into `session.clientHelloBody`; wolfSSL copies immediately, so
        // the pointer only has to stay valid for the callback's duration.
        let installRv = wolfSSL_UseClientHelloRaw(ssl, clientHelloCallback, sessionHandle)
        if installRv != WOLFSSL_SUCCESS {
            throw TLSError.handshakeFailed("UseClientHelloRaw rv=\(installRv)")
        }

        return session
    }

    /// Walks the extensions block of a ClientHello body and removes any
    /// extension whose type is in `types`. Returns a new body with the
    /// extensions_length field and surrounding offsets rewritten.
    ///
    /// Body layout (offsets relative to start, i.e. after the 4-byte
    /// handshake header that wolfSSL stamps separately):
    ///
    ///     0..1     legacy_version
    ///     2..33    random
    ///     34       session_id_length  (N)
    ///     35..     session_id
    ///     +0..1    cipher_suites_length
    ///     +2..     cipher_suites
    ///     +0       compression_methods_length
    ///     +1..     compression_methods
    ///     +0..1    extensions_length
    ///     +2..     extensions (TLV: type(2) + length(2) + data)
    private static func stripExtensions(from body: [UInt8],
                                        types: Set<UInt16>) -> [UInt8] {
        var off = 0

        guard body.count > 34 else { return body }
        off = 2 + 32                                       // version + random
        let sessIdLen = Int(body[off]); off += 1 + sessIdLen
        guard off + 2 <= body.count else { return body }
        let suitesLen = (Int(body[off]) << 8) | Int(body[off+1]); off += 2 + suitesLen
        guard off + 1 <= body.count else { return body }
        let compLen = Int(body[off]); off += 1 + compLen
        guard off + 2 <= body.count else { return body }

        let extsTotalOff = off
        let extsTotal = (Int(body[off]) << 8) | Int(body[off+1]); off += 2
        let extsStart = off
        let extsEnd = min(extsStart + extsTotal, body.count)

        var kept = [UInt8]()
        kept.reserveCapacity(extsTotal)
        var cur = extsStart
        while cur + 4 <= extsEnd {
            let etype = (UInt16(body[cur]) << 8) | UInt16(body[cur+1])
            let elen  = (Int(body[cur+2]) << 8) | Int(body[cur+3])
            let next  = cur + 4 + elen
            guard next <= extsEnd else { break }
            if !types.contains(etype) {
                kept.append(contentsOf: body[cur..<next])
            }
            cur = next
        }

        if kept.count == extsTotal { return body }

        var result = Array(body[0..<extsTotalOff])
        result.append(UInt8(kept.count >> 8))
        result.append(UInt8(kept.count & 0xFF))
        result.append(contentsOf: kept)
        return result
    }

    private func loadCachedSession(into ssl: OpaquePointer) {
        let key = sessionTicketCacheKey(
            serverName: configuration.serverName,
            alpn: configuration.alpn ?? [])
        ticketCacheLock.lock()
        let cached = sessionTicketCache[key]
        ticketCacheLock.unlock()
        guard let cached, !cached.isEmpty else { return }
        let wolfSession: OpaquePointer? = cached.withUnsafeBytes { raw in
            guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
            else { return nil as OpaquePointer? }
            var cursor: UnsafePointer<UInt8>? = p
            return withUnsafeMutablePointer(to: &cursor) { pp in
                wolfSSL_d2i_SSL_SESSION(nil, pp, cached.count)
            }
        }
        guard let wolfSession else { return }
        defer { wolfSSL_SESSION_free(wolfSession) }
        _ = wolfSSL_set_session(ssl, wolfSession)
    }

    // MARK: - Handshake pump

    private func startHandshake() {
        guard let session else { return }
        session.queue.async { [weak self] in
            self?.pumpHandshake()
        }
    }

    private func pumpHandshake() {
        guard let session, !session.cancelled else { return }

        let rv = wolfSSL_connect(session.ssl)
        if rv == WOLFSSL_SUCCESS {
            flushTx(session: session) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.deliver(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }
                // Hand off the session to a TLSRecordConnection and deliver.
                let conn = TLSRecordConnection(session: session)
                self.session = nil
                self.deliver(.success(conn))
            }
            return
        }

        let err = wolfSSL_get_error(session.ssl, rv)
        if err == WOLFSSL_ERROR_WANT_READ {
            flushTx(session: session) { [weak self] error in
                guard let self, let session = self.session, !session.cancelled else { return }
                if let error {
                    self.deliver(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }
                self.pullFromNetwork(session: session) { [weak self] pullErr in
                    guard let self else { return }
                    if let pullErr {
                        self.deliver(.failure(TLSError.handshakeFailed(pullErr.localizedDescription)))
                        return
                    }
                    session.queue.async { self.pumpHandshake() }
                }
            }
        } else if err == WOLFSSL_ERROR_WANT_WRITE {
            flushTx(session: session) { [weak self] error in
                guard let self, let session = self.session, !session.cancelled else { return }
                if let error {
                    self.deliver(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }
                session.queue.async { self.pumpHandshake() }
            }
        } else {
            var alertHistory = WOLFSSL_ALERT_HISTORY()
            var detail = "wolfSSL rv=\(rv) err=\(err)"
            if wolfSSL_get_alert_history(session.ssl, &alertHistory) == WOLFSSL_SUCCESS {
                let rx = alertHistory.last_rx
                if rx.code != -1 {
                    detail += " alert_rx=\(rx.code)"
                }
            }
            deliver(.failure(TLSError.handshakeFailed(detail)))
        }
    }

    // MARK: - BIO pumps (shared with TLSRecordConnection via `session`)

    internal static func flushTx(
        session: TLSSession,
        completion: @escaping (Error?) -> Void
    ) {
        session.queue.async {
            guard !session.cancelled else { completion(nil); return }
            if session.txBuffer.isEmpty { completion(nil); return }
            let data = session.txBuffer
            session.txBuffer.removeAll(keepingCapacity: true)
            guard let connection = session.connection else {
                completion(TLSError.connectionFailed("Connection cancelled"))
                return
            }
            connection.send(data: data) { error in
                session.queue.async { completion(error) }
            }
        }
    }

    private func flushTx(session: TLSSession, completion: @escaping (Error?) -> Void) {
        Self.flushTx(session: session, completion: completion)
    }

    internal static func pullFromNetwork(
        session: TLSSession,
        completion: @escaping (Error?) -> Void
    ) {
        session.queue.async {
            guard !session.cancelled else { completion(nil); return }
            session.receiveWaiters.append(completion)
            if session.receiveInFlight { return }   // woken by the in-flight receive
            guard let connection = session.connection else {
                let waiters = session.receiveWaiters
                session.receiveWaiters.removeAll()
                for w in waiters { w(TLSError.connectionFailed("Connection cancelled")) }
                return
            }
            session.receiveInFlight = true
            connection.receive(maximumLength: 65536) { data, isComplete, error in
                session.queue.async {
                    session.receiveInFlight = false
                    if let data, !data.isEmpty { session.rxBuffer.append(data) }
                    let waiters = session.receiveWaiters
                    session.receiveWaiters.removeAll()
                    let finalError: Error?
                    if let error { finalError = error }
                    else if (data?.isEmpty ?? true) && isComplete {
                        finalError = TLSError.connectionFailed("Connection closed by peer")
                    } else {
                        finalError = nil
                    }
                    for w in waiters { w(finalError) }
                }
            }
        }
    }

    private func pullFromNetwork(session: TLSSession, completion: @escaping (Error?) -> Void) {
        Self.pullFromNetwork(session: session, completion: completion)
    }

    // MARK: - Completion delivery

    private func setCompletion(_ cb: @escaping (Result<TLSRecordConnection, Error>) -> Void) {
        completionLock.lock()
        completion = cb
        completionLock.unlock()
    }

    private func deliver(_ result: Result<TLSRecordConnection, Error>) {
        completionLock.lock()
        let cb = completion
        completion = nil
        completionLock.unlock()
        cb?(result)
    }
}

// MARK: - C callbacks

/// Custom ClientHello builder callback — returns a pointer into
/// `session.clientHelloBody`. Installed on `ssl` via
/// `wolfSSL_UseClientHelloRaw`.
private let clientHelloCallback: @convention(c) (
    OpaquePointer?,                               // WOLFSSL*
    UnsafeMutablePointer<UnsafePointer<UInt8>?>?, // bodyOut
    UnsafeMutablePointer<UInt32>?,                // bodyLenOut
    UnsafeMutableRawPointer?                      // ctx (TLSSession)
) -> Int32 = { _, bodyOut, bodyLenOut, ctx in
    guard let ctx, let bodyOut, let bodyLenOut else { return -1 }
    let session = Unmanaged<TLSSession>.fromOpaque(ctx).takeUnretainedValue()
    session.clientHelloBody.withUnsafeBufferPointer { buf in
        bodyOut.pointee = buf.baseAddress
        bodyLenOut.pointee = UInt32(buf.count)
    }
    return 0
}

/// IO receive callback — wolfSSL calls this to pull encrypted bytes from
/// the network. We copy from `session.rxBuffer`; empty means WANT_READ.
private let ioRecvCallback: @convention(c) (
    OpaquePointer?,                  // WOLFSSL*
    UnsafeMutablePointer<CChar>?,    // output buffer
    CInt,                            // requested length
    UnsafeMutableRawPointer?         // ctx (TLSSession)
) -> CInt = { _, buf, sz, ctx in
    guard let ctx, let buf, sz > 0 else { return TLSBIOStatus.generalError }
    let session = Unmanaged<TLSSession>.fromOpaque(ctx).takeUnretainedValue()
    if session.cancelled { return TLSBIOStatus.connectionClose }
    if session.rxBuffer.isEmpty { return TLSBIOStatus.wantRead }
    let wanted = Int(sz)
    let available = session.rxBuffer.count
    let n = min(wanted, available)
    session.rxBuffer.withUnsafeBytes { raw in
        let src = raw.bindMemory(to: UInt8.self).baseAddress!
        memcpy(UnsafeMutableRawPointer(buf), UnsafeRawPointer(src), n)
    }
    session.rxBuffer.removeFirst(n)
    return CInt(n)
}

/// IO send callback — wolfSSL calls this to push encrypted bytes onto the
/// network. We buffer into `session.txBuffer`; the pump drains it.
private let ioSendCallback: @convention(c) (
    OpaquePointer?,                  // WOLFSSL*
    UnsafeMutablePointer<CChar>?,    // input buffer
    CInt,                            // length
    UnsafeMutableRawPointer?         // ctx (TLSSession)
) -> CInt = { _, buf, sz, ctx in
    guard let ctx, let buf, sz > 0 else { return TLSBIOStatus.generalError }
    let session = Unmanaged<TLSSession>.fromOpaque(ctx).takeUnretainedValue()
    if session.cancelled { return TLSBIOStatus.connectionClose }
    session.txBuffer.append(UnsafeBufferPointer(
        start: UnsafePointer<UInt8>(OpaquePointer(buf)),
        count: Int(sz)))
    return sz
}

/// Cert chain validation — identical logic to QUICTLSHandler.
private let certVerifyCallback:
    @convention(c) (CInt, UnsafeMutablePointer<WOLFSSL_X509_STORE_CTX>?) -> CInt = {
        _, storeCtxPtr in
        guard let storeCtxPtr else { return 0 }
        let depth = wolfSSL_X509_STORE_CTX_get_error_depth(storeCtxPtr)
        if depth > 0 { return 1 }
        if CertificatePolicy.allowInsecure { return 1 }

        guard let sslVoid = wolfSSL_X509_STORE_CTX_get_ex_data(
            storeCtxPtr, wolfSSL_get_ex_data_X509_STORE_CTX_idx()) else {
            return 0
        }
        let ssl = OpaquePointer(sslVoid)

        let serverName: String
        if let sniPtr = wolfSSL_get_servername(ssl, UInt8(WOLFSSL_SNI_HOST_NAME)) {
            serverName = String(cString: sniPtr)
        } else {
            serverName = ""
        }

        guard let stack = wolfSSL_X509_STORE_CTX_get_chain(storeCtxPtr) else { return 0 }
        var certs: [SecCertificate] = []
        let count = wolfSSL_sk_X509_num(stack)
        for i in 0..<count {
            guard let x = wolfSSL_sk_X509_value(stack, i) else { continue }
            var size: Int32 = 0
            guard let der = wolfSSL_X509_get_der(x, &size), size > 0 else { continue }
            let data = Data(bytes: der, count: Int(size)) as CFData
            if let cert = SecCertificateCreateWithData(nil, data) {
                certs.append(cert)
            }
        }
        guard let leaf = certs.first else { return 0 }

        let policy = SecPolicyCreateSSL(true, serverName as CFString)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(
            certs as CFArray, policy, &trust) == errSecSuccess,
              let trust else { return 0 }

        var evalErr: CFError?
        if SecTrustEvaluateWithError(trust, &evalErr) { return 1 }

        let pinned = CertificatePolicy.trustedFingerprints
        if !pinned.isEmpty {
            let certData = SecCertificateCopyData(leaf) as Data
            let digest = SHA256.hash(data: certData)
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            if pinned.contains(hex) { return 1 }
        }
        return 0
    }

/// Session ticket cache — stashes the DER-encoded session into the
/// process-wide cache keyed by (SNI, ALPN).
private let sessionNewCallback:
    @convention(c) (OpaquePointer?, OpaquePointer?) -> CInt = { sslPtr, sessionPtr in
        guard let sslPtr, let sessionPtr else { return 0 }

        // Recover (serverName, alpn) from SNI + ALPN on the SSL handle.
        let serverName: String
        if let sniPtr = wolfSSL_get_servername(sslPtr, UInt8(WOLFSSL_SNI_HOST_NAME)) {
            serverName = String(cString: sniPtr)
        } else {
            return 0
        }
        var alpnName: UnsafeMutablePointer<CChar>? = nil
        var alpnLen: UInt16 = 0
        var alpn: [String] = []
        if wolfSSL_ALPN_GetProtocol(sslPtr, &alpnName, &alpnLen) == WOLFSSL_SUCCESS,
           let alpnName, alpnLen > 0 {
            let proto = String(bytesNoCopy: alpnName, length: Int(alpnLen),
                               encoding: .utf8, freeWhenDone: false) ?? ""
            if !proto.isEmpty { alpn = [proto] }
        }

        // Two-phase i2d: first NULL-call sizes, second encodes.
        var nullOut: UnsafeMutablePointer<UInt8>? = nil
        let len = withUnsafeMutablePointer(to: &nullOut) { pp -> CInt in
            wolfSSL_i2d_SSL_SESSION(sessionPtr, pp)
        }
        guard len > 0 else { return 0 }
        var buf = [UInt8](repeating: 0, count: Int(len))
        let written = buf.withUnsafeMutableBufferPointer { bufPtr -> CInt in
            var cursor: UnsafeMutablePointer<UInt8>? = bufPtr.baseAddress
            return withUnsafeMutablePointer(to: &cursor) { pp in
                wolfSSL_i2d_SSL_SESSION(sessionPtr, pp)
            }
        }
        guard written == len else { return 0 }

        let key = sessionTicketCacheKey(serverName: serverName, alpn: alpn)
        ticketCacheLock.lock()
        sessionTicketCache[key] = Data(buf)
        ticketCacheLock.unlock()
        return 0
    }
