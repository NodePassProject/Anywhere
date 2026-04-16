//
//  QUICTLSHandler.swift
//  Anywhere
//
//  Per-connection wolfSSL TLS 1.3 handler for QUIC.
//
//  Owns a WOLFSSL_CTX* and WOLFSSL*. Once `ngtcp2_conn_set_tls_native_handle`
//  has wired this handler's `sslHandle` into the ngtcp2 connection, the entire
//  handshake is driven by ngtcp2's `client_initial` / `recv_crypto_data` crypto
//  helpers (shared.c): they feed CRYPTO frames into `wolfSSL_quic_do_handshake`
//  and wolfSSL pushes keys back through the QUIC_METHOD callbacks wired in
//  `ngtcp2_crypto_wolfssl_configure_client_context`.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "QUIC-TLS")

// MARK: - Session ticket cache

/// Serialized wolfSSL sessions keyed by `"\(SNI)\u{0}\(alpn.joined(","))"`.
/// Tickets are not portable across ALPN contexts. In-memory only; lost on
/// process restart (matches the pre-migration behavior).
private let ticketCacheLock = UnfairLock()
private var sessionTicketCache: [String: Data] = [:]

private func sessionTicketCacheKey(serverName: String, alpn: [String]) -> String {
    return "\(serverName)\u{0}\(alpn.joined(separator: ","))"
}

/// Drops any cached session for `(serverName, alpn)`. Called by QUICConnection
/// when a handshake fails before reaching `.connected` — a cached session
/// whose keys the server has rotated would otherwise send us into a permanent
/// HANDSHAKE_TIMEOUT loop on resumption retries.
func invalidateCachedSessionTicket(serverName: String, alpn: [String]) {
    let key = sessionTicketCacheKey(serverName: serverName, alpn: alpn)
    ticketCacheLock.lock()
    sessionTicketCache.removeValue(forKey: key)
    ticketCacheLock.unlock()
}

// MARK: - QUICTLSHandler

/// Lazy, process-wide `wolfSSL_Init()`. Every wolfSSL entry point assumes the
/// library has been initialized; skipping this produces silent NULLs from
/// `wolfSSL_CTX_new` and friends.
nonisolated(unsafe) private var wolfSSLInitRv: Int32 = 0
private let wolfSSLInitialized: Bool = {
    wolfSSLInitRv = wolfSSL_Init()
    return wolfSSLInitRv == WOLFSSL_SUCCESS
}()

final class QUICTLSHandler {

    private var ctx: OpaquePointer?
    private var ssl: OpaquePointer?
    private let serverName: String
    private let alpn: [String]

    /// Raw `WOLFSSL*` for `ngtcp2_conn_set_tls_native_handle` and
    /// `ngtcp2_crypto_set_local_transport_params`.
    var sslHandle: UnsafeMutableRawPointer? {
        ssl.map { UnsafeMutableRawPointer($0) }
    }

    /// Negotiated ALPN protocol. `nil` until the handshake has produced one.
    var negotiatedALPN: String? {
        guard let ssl else { return nil }
        var name: UnsafeMutablePointer<CChar>? = nil
        var length: UInt16 = 0
        guard wolfSSL_ALPN_GetProtocol(ssl, &name, &length) == WOLFSSL_SUCCESS,
              let name, length > 0 else { return nil }
        return String(
            bytesNoCopy: name, length: Int(length),
            encoding: .utf8, freeWhenDone: false)
    }

    /// Creates the wolfSSL context + SSL object and wires it to `connRef` so
    /// wolfSSL's QUIC callbacks (set_encryption_secrets / add_handshake_data /
    /// send_alert) can reach back into ngtcp2. Returns `nil` on any wolfSSL
    /// setup failure.
    ///
    /// The caller is expected to immediately call
    /// `ngtcp2_conn_set_tls_native_handle(conn, sslHandle)` and
    /// `ngtcp2_crypto_set_local_transport_params(sslHandle, bytes, len)` before
    /// driving any packet I/O.
    init?(serverName: String, alpn: [String],
          connRef: UnsafeMutablePointer<ngtcp2_crypto_conn_ref>) {
        self.serverName = serverName
        self.alpn = alpn

        guard wolfSSLInitialized else {
            logger.error("wolfSSL_Init failed rv=\(wolfSSLInitRv)")
            return nil
        }
        wolfSSL_Debugging_ON()
        guard let method = wolfTLSv1_3_client_method() else {
            logger.error("wolfTLSv1_3_client_method returned NULL")
            return nil
        }
        guard let ctxPtr = wolfSSL_CTX_new(method) else {
            logger.error("wolfSSL_CTX_new returned NULL")
            return nil
        }
        self.ctx = ctxPtr

        guard ngtcp2_crypto_wolfssl_configure_client_context(ctxPtr) == 0 else {
            logger.error("ngtcp2_crypto_wolfssl_configure_client_context failed")
            wolfSSL_CTX_free(ctxPtr)
            self.ctx = nil
            return nil
        }

        // Route all chain validation through our SecTrust-backed callback.
        wolfSSL_CTX_set_verify(
            ctxPtr, Int32(WOLFSSL_VERIFY_PEER), certVerifyCallback)

        // Capture NewSessionTickets as they arrive so the next connection to
        // the same (SNI, ALPN) can resume.
        wolfSSL_CTX_sess_set_new_cb(ctxPtr, sessionNewCallback)

        guard let sslPtr = wolfSSL_new(ctxPtr) else {
            logger.error("wolfSSL_new returned NULL")
            wolfSSL_CTX_free(ctxPtr)
            self.ctx = nil
            return nil
        }
        self.ssl = sslPtr

        // App-data slot is where ngtcp2_crypto_wolfssl.c reads conn_ref.
        _ = wolfSSL_set_app_data(sslPtr, UnsafeMutableRawPointer(connRef))

        // Stash self at ex_data idx 1 so the session-new callback can build
        // the cache key from (serverName, alpn) without touching QUICConnection.
        let selfPtr = UnsafeMutableRawPointer(
            Unmanaged.passUnretained(self).toOpaque())
        _ = wolfSSL_set_ex_data(sslPtr, 1, selfPtr)

        // SNI (server_name extension + hostname used by our verify callback
        // via wolfSSL_get_servername lookup).
        _ = serverName.withCString { name in
            wolfSSL_UseSNI(sslPtr, UInt8(WOLFSSL_SNI_HOST_NAME),
                           name, UInt16(strlen(name)))
        }

        // ALPN — OpenSSL wire format: length-prefixed concatenation.
        var alpnWire: [UInt8] = []
        for proto in alpn {
            let bytes = Array(proto.utf8)
            precondition(bytes.count <= 255, "ALPN protocol too long: \(proto)")
            alpnWire.append(UInt8(bytes.count))
            alpnWire.append(contentsOf: bytes)
        }
        _ = alpnWire.withUnsafeBufferPointer { buf in
            wolfSSL_set_alpn_protos(sslPtr, buf.baseAddress, UInt32(buf.count))
        }

        // If we have a cached session for this (SNI, ALPN), install it before
        // the handshake starts so wolfSSL sends the PSK in ClientHello.
        loadCachedSession(into: sslPtr)
    }

    deinit {
        if let s = ssl { wolfSSL_free(s) }
        if let c = ctx { wolfSSL_CTX_free(c) }
    }

    fileprivate func storeSession(_ data: Data) {
        let key = sessionTicketCacheKey(serverName: serverName, alpn: alpn)
        ticketCacheLock.lock()
        sessionTicketCache[key] = data
        ticketCacheLock.unlock()
    }

    private func loadCachedSession(into ssl: OpaquePointer) {
        let key = sessionTicketCacheKey(serverName: serverName, alpn: alpn)
        ticketCacheLock.lock()
        let cached = sessionTicketCache[key]
        ticketCacheLock.unlock()
        guard let bytes = cached else { return }
        let length = bytes.count

        let session: OpaquePointer? = bytes.withUnsafeBytes { raw in
            guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
            else { return nil as OpaquePointer? }
            var cursor: UnsafePointer<UInt8>? = p
            return withUnsafeMutablePointer(to: &cursor) { pp in
                wolfSSL_d2i_SSL_SESSION(nil, pp, length)
            }
        }
        guard let session else { return }
        defer { wolfSSL_SESSION_free(session) }
        _ = wolfSSL_set_session(ssl, session)
    }
}

// MARK: - Certificate verification

/// Called once per certificate in the received chain, leaf-last.
/// Strategy: rubber-stamp everything above depth 0 so wolfSSL walks the full
/// chain into the store, then at depth 0 pull the accumulated chain out and
/// validate with Security.framework — matching the pre-migration behavior
/// (system trust roots + `CertificatePolicy.allowInsecure` + fingerprint pins).
private let certVerifyCallback:
    @convention(c) (CInt, UnsafeMutablePointer<WOLFSSL_X509_STORE_CTX>?)
    -> CInt = { _, storeCtxPtr in
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
        if let sniPtr = wolfSSL_get_servername(
            ssl, UInt8(WOLFSSL_SNI_HOST_NAME)) {
            serverName = String(cString: sniPtr)
        } else {
            serverName = ""
        }

        guard let stack = wolfSSL_X509_STORE_CTX_get_chain(storeCtxPtr) else {
            return 0
        }
        var certs: [SecCertificate] = []
        let count = wolfSSL_sk_X509_num(stack)
        for i in 0..<count {
            guard let x = wolfSSL_sk_X509_value(stack, i) else { continue }
            var size: Int32 = 0
            guard let der = wolfSSL_X509_get_der(x, &size), size > 0 else {
                continue
            }
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
        if SecTrustEvaluateWithError(trust, &evalErr) {
            return 1
        }

        // Pinned-fingerprint override.
        let pinned = CertificatePolicy.trustedFingerprints
        if !pinned.isEmpty {
            let certData = SecCertificateCopyData(leaf) as Data
            let digest = SHA256.hash(data: certData)
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            if pinned.contains(hex) { return 1 }
        }
        return 0
    }

// MARK: - Session resumption

/// Invoked by wolfSSL when a NewSessionTicket arrives. Serializes the session
/// into the Swift cache keyed by the handler's (SNI, ALPN). We return 0 to
/// let wolfSSL free its own reference — we keep the serialized bytes, not the
/// WOLFSSL_SESSION object.
private let sessionNewCallback:
    @convention(c) (OpaquePointer?, OpaquePointer?) -> CInt = { sslPtr, sessionPtr in
        guard let sslPtr, let sessionPtr else { return 0 }
        guard let selfVoid = wolfSSL_get_ex_data(sslPtr, 1) else { return 0 }
        let handler = Unmanaged<QUICTLSHandler>.fromOpaque(selfVoid)
            .takeUnretainedValue()

        // Two-phase i2d: first NULL call sizes, second encodes. wolfSSL's
        // wolfSSL_i2d_SSL_SESSION writes into a caller-supplied buffer if
        // `*out` is non-NULL and advances the pointer.
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
        handler.storeSession(Data(buf))
        return 0
    }
