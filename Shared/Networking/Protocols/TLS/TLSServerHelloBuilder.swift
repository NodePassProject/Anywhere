//
//  TLSServerHelloBuilder.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

enum TLSServerHelloBuilder {

    // MARK: - ServerHello

    /// Builds a TLS 1.3 ServerHello.
    ///
    /// - Parameters:
    ///   - legacySessionID: The 32-byte session ID echoed verbatim from the
    ///     ClientHello (RFC 8446 §4.1.3).
    ///   - cipherSuite: The cipher suite the server has chosen.
    ///   - x25519PublicKey: 32-byte server X25519 public key for the
    ///     `key_share` extension.
    /// - Returns: A complete handshake-layer ServerHello (no record header).
    static func buildServerHello(
        legacySessionID: Data,
        cipherSuite: UInt16,
        x25519PublicKey: Data
    ) -> Data {
        precondition(x25519PublicKey.count == 32)

        var random = Data(count: 32)
        random.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }

        var body = Data()
        body.append(0x03); body.append(0x03)                          // legacy_version = TLS 1.2
        body.append(random)                                           // 32-byte random
        body.append(UInt8(legacySessionID.count))                     // legacy_session_id_echo
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))                 // cipher_suite
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)                                             // legacy_compression_method = null

        // Extensions
        var extensions = Data()
        extensions.append(buildSupportedVersionsServerExt())
        extensions.append(buildKeyShareServerExt(group: 0x001D, key: x25519PublicKey))
        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: 0x02, body: body)
    }

    /// Builds a HelloRetryRequest. Same wire shape as ServerHello but with
    /// the well-known SHA-256("HelloRetryRequest") sentinel as Random and
    /// a `key_share` extension naming only the requested group.
    static func buildHelloRetryRequest(
        legacySessionID: Data,
        cipherSuite: UInt16,
        requestedGroup: UInt16
    ) -> Data {
        // SHA-256("HelloRetryRequest")
        let hrrRandom = Data([
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ])

        var body = Data()
        body.append(0x03); body.append(0x03)
        body.append(hrrRandom)
        body.append(UInt8(legacySessionID.count))
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)

        var extensions = Data()
        extensions.append(buildSupportedVersionsServerExt())
        // key_share for HRR is just the named group (no exchange data).
        var keyShareExt = Data()
        keyShareExt.append(0x00); keyShareExt.append(0x33)            // ext type = key_share
        let groupBytes = Data([
            UInt8((requestedGroup >> 8) & 0xFF),
            UInt8(requestedGroup & 0xFF),
        ])
        keyShareExt.append(0x00); keyShareExt.append(0x02)            // ext data len
        keyShareExt.append(groupBytes)
        extensions.append(keyShareExt)

        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: 0x02, body: body)
    }

    // MARK: - TLS 1.2 ServerHello

    /// Builds a TLS 1.2 ServerHello.
    ///
    /// Differs from the TLS 1.3 form in three ways: legacy_version is the
    /// negotiated value (0x0303) rather than the supported_versions sentinel;
    /// no `supported_versions` extension is emitted; and ALPN/EMS extensions
    /// (which TLS 1.3 carries inside the encrypted EncryptedExtensions
    /// message) appear directly in the ServerHello extension list.
    ///
    /// - Parameters:
    ///   - legacySessionID: 32-byte session ID echoed verbatim from the
    ///     ClientHello (RFC 5246 §7.4.1.3).
    ///   - cipherSuite: The TLS 1.2 cipher suite the server chose.
    ///   - alpn: The negotiated ALPN protocol, or nil to omit the extension.
    ///   - extendedMasterSecret: Whether to advertise EMS (RFC 7627) — set
    ///     when the client offered the extension.
    ///   - serverRandom: 32-byte server-side random (returned by the caller
    ///     so it can mix into the master_secret seed downstream).
    /// - Returns: A complete handshake-layer ServerHello (no record header).
    static func buildServerHello12(
        legacySessionID: Data,
        cipherSuite: UInt16,
        alpn: String?,
        extendedMasterSecret: Bool,
        secureRenegotiation: Bool,
        serverRandom: Data
    ) -> Data {
        precondition(serverRandom.count == 32)

        var body = Data()
        body.append(0x03); body.append(0x03)                          // version = TLS 1.2
        body.append(serverRandom)
        body.append(UInt8(legacySessionID.count))
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)                                             // legacy_compression_method = null

        // Extensions. RFC 5246 §7.4.1.4: an extension MUST NOT appear in
        // the ServerHello unless it appeared in the ClientHello. Each
        // extension is gated on the corresponding ClientHello signal.
        var extensions = Data()
        if extendedMasterSecret {
            extensions.append(0x00); extensions.append(0x17)          // ext type = extended_master_secret
            extensions.append(0x00); extensions.append(0x00)          // ext data len = 0
        }
        if let alpn {
            extensions.append(buildALPNExtension(protocols: [alpn]))
        }
        if secureRenegotiation {
            extensions.append(0xFF); extensions.append(0x01)          // ext type = renegotiation_info
            extensions.append(0x00); extensions.append(0x01)          // ext data len = 1
            extensions.append(0x00)                                   // empty renegotiated_connection
        }

        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: 0x02, body: body)
    }

    // MARK: - TLS 1.2 Certificate

    /// Builds a TLS 1.2 Certificate message (RFC 5246 §7.4.2).
    ///
    /// Wire shape differs from TLS 1.3: no `certificate_request_context`
    /// length prefix and no per-entry extension list — just a length-
    /// prefixed list of length-prefixed cert bodies.
    static func buildCertificate12(leafCertDER: Data) -> Data {
        var body = Data()

        // certificate_list: each entry is length(3) + cert
        var entry = Data()
        let certLen = leafCertDER.count
        entry.append(UInt8((certLen >> 16) & 0xFF))
        entry.append(UInt8((certLen >> 8) & 0xFF))
        entry.append(UInt8(certLen & 0xFF))
        entry.append(leafCertDER)

        let listLen = entry.count
        body.append(UInt8((listLen >> 16) & 0xFF))
        body.append(UInt8((listLen >> 8) & 0xFF))
        body.append(UInt8(listLen & 0xFF))
        body.append(entry)

        return wrapHandshake(type: 0x0B, body: body)
    }

    // MARK: - TLS 1.2 ServerKeyExchange

    /// Builds the ECDHE ServerKeyExchange params blob (the bytes that get
    /// signed and that prefix the SKE message).
    ///
    /// Format (RFC 8422 §5.4): curve_type(1) || named_curve(2) ||
    /// pubkey_len(1) || pubkey(N).
    static func serverECDHEParams(namedCurve: UInt16, publicKey: Data) -> Data {
        var params = Data()
        params.append(0x03)                                           // curve_type = named_curve
        params.append(UInt8((namedCurve >> 8) & 0xFF))
        params.append(UInt8(namedCurve & 0xFF))
        params.append(UInt8(publicKey.count))
        params.append(publicKey)
        return params
    }

    /// Builds a TLS 1.2 ServerKeyExchange message for an ECDHE_ECDSA cipher
    /// suite (RFC 5246 §7.4.3, RFC 8422 §5.4).
    ///
    /// - Parameters:
    ///   - params: The pre-built params blob — also the prefix of the
    ///     signed payload (caller computed `client_random || server_random
    ///     || params` and signed that).
    ///   - signatureAlgorithm: 0x0403 = ecdsa_secp256r1_sha256.
    ///   - signature: DER-encoded ECDSA signature.
    static func buildServerKeyExchange(
        params: Data,
        signatureAlgorithm: UInt16,
        signature: Data
    ) -> Data {
        var body = Data()
        body.append(params)
        body.append(UInt8((signatureAlgorithm >> 8) & 0xFF))
        body.append(UInt8(signatureAlgorithm & 0xFF))
        body.append(UInt8((signature.count >> 8) & 0xFF))
        body.append(UInt8(signature.count & 0xFF))
        body.append(signature)
        return wrapHandshake(type: 0x0C, body: body)
    }

    // MARK: - TLS 1.2 ServerHelloDone

    /// Builds a TLS 1.2 ServerHelloDone message (RFC 5246 §7.4.5).
    static func buildServerHelloDone() -> Data {
        wrapHandshake(type: 0x0E, body: Data())
    }

    // MARK: - TLS 1.2 Finished

    /// Builds a TLS 1.2 Finished message (RFC 5246 §7.4.9). Verify data is
    /// always 12 bytes for TLS 1.2.
    static func buildFinished12(verifyData: Data) -> Data {
        wrapHandshake(type: 0x14, body: verifyData)
    }

    // MARK: - EncryptedExtensions

    /// Builds an EncryptedExtensions handshake message advertising the
    /// negotiated ALPN. Empty body if `alpn` is nil.
    static func buildEncryptedExtensions(alpn: String?) -> Data {
        var body = Data()
        var extensions = Data()
        if let alpn {
            extensions.append(buildALPNExtension(protocols: [alpn]))
        }
        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)
        return wrapHandshake(type: 0x08, body: body)
    }

    // MARK: - Certificate

    /// Builds a Certificate message for a single leaf certificate.
    /// Per RFC 8446 §4.4.2: certificate_request_context length (0 here),
    /// then a CertificateList ::= sequence of CertificateEntry.
    static func buildCertificate(leafCertDER: Data) -> Data {
        var body = Data()
        body.append(0x00)                                             // certificate_request_context length

        var entry = Data()
        // cert_data length (3 bytes)
        let certLen = leafCertDER.count
        entry.append(UInt8((certLen >> 16) & 0xFF))
        entry.append(UInt8((certLen >> 8) & 0xFF))
        entry.append(UInt8(certLen & 0xFF))
        entry.append(leafCertDER)
        // extensions length (2 bytes) — empty
        entry.append(0x00); entry.append(0x00)

        // certificate_list length (3 bytes)
        let listLen = entry.count
        body.append(UInt8((listLen >> 16) & 0xFF))
        body.append(UInt8((listLen >> 8) & 0xFF))
        body.append(UInt8(listLen & 0xFF))
        body.append(entry)

        return wrapHandshake(type: 0x0B, body: body)
    }

    // MARK: - CertificateVerify

    /// Builds a CertificateVerify carrying an ECDSA signature over the
    /// transcript-hash context string (RFC 8446 §4.4.3).
    ///
    /// - Parameters:
    ///   - signatureAlgorithm: 0x0403 = ecdsa_secp256r1_sha256.
    ///   - signature: DER-encoded ECDSA signature (as returned by
    ///     ``SecKeyCreateSignature``).
    static func buildCertificateVerify(signatureAlgorithm: UInt16, signature: Data) -> Data {
        var body = Data()
        body.append(UInt8((signatureAlgorithm >> 8) & 0xFF))
        body.append(UInt8(signatureAlgorithm & 0xFF))
        body.append(UInt8((signature.count >> 8) & 0xFF))
        body.append(UInt8(signature.count & 0xFF))
        body.append(signature)
        return wrapHandshake(type: 0x0F, body: body)
    }

    // MARK: - Finished

    /// Builds a Finished message carrying the verify_data MAC.
    static func buildFinished(verifyData: Data) -> Data {
        wrapHandshake(type: 0x14, body: verifyData)
    }

    // MARK: - CertificateVerify Signing Helpers

    /// Builds the buffer that is signed for a server-side CertificateVerify.
    /// Per RFC 8446 §4.4.3, the input is:
    ///   octet 0x20 × 64 || "TLS 1.3, server CertificateVerify" ||
    ///   0x00 || transcript_hash
    static func certificateVerifyContext(transcriptHash: Data) -> Data {
        var ctx = Data(repeating: 0x20, count: 64)
        ctx.append(Data("TLS 1.3, server CertificateVerify".utf8))
        ctx.append(0x00)
        ctx.append(transcriptHash)
        return ctx
    }

    // MARK: - Alerts

    /// Builds a TLS Alert payload (level + description), without the record
    /// header. Caller wraps it in either a plain record (for
    /// pre-handshake-keys alerts) or an encrypted record.
    static func alert(level: UInt8, description: UInt8) -> Data {
        Data([level, description])
    }

    // MARK: - Extension builders

    private static func buildSupportedVersionsServerExt() -> Data {
        // ServerHello supported_versions: a single uint16 (no list-length byte).
        var ext = Data()
        ext.append(0x00); ext.append(0x2B)                            // ext type
        ext.append(0x00); ext.append(0x02)                            // ext data len
        ext.append(0x03); ext.append(0x04)                            // TLS 1.3
        return ext
    }

    private static func buildKeyShareServerExt(group: UInt16, key: Data) -> Data {
        var ext = Data()
        ext.append(0x00); ext.append(0x33)                            // ext type
        let payloadLen = 4 + key.count
        ext.append(UInt8((payloadLen >> 8) & 0xFF))
        ext.append(UInt8(payloadLen & 0xFF))
        ext.append(UInt8((group >> 8) & 0xFF))
        ext.append(UInt8(group & 0xFF))
        ext.append(UInt8((key.count >> 8) & 0xFF))
        ext.append(UInt8(key.count & 0xFF))
        ext.append(key)
        return ext
    }

    private static func buildALPNExtension(protocols: [String]) -> Data {
        var list = Data()
        for p in protocols {
            let bytes = Data(p.utf8)
            list.append(UInt8(bytes.count))
            list.append(bytes)
        }
        var ext = Data()
        ext.append(0x00); ext.append(0x10)                            // ext type
        let payloadLen = 2 + list.count
        ext.append(UInt8((payloadLen >> 8) & 0xFF))
        ext.append(UInt8(payloadLen & 0xFF))
        ext.append(UInt8((list.count >> 8) & 0xFF))
        ext.append(UInt8(list.count & 0xFF))
        ext.append(list)
        return ext
    }

    /// Wraps a handshake body in the `[type:1][length:3][body]` framing.
    private static func wrapHandshake(type: UInt8, body: Data) -> Data {
        var out = Data()
        out.append(type)
        let len = body.count
        out.append(UInt8((len >> 16) & 0xFF))
        out.append(UInt8((len >> 8) & 0xFF))
        out.append(UInt8(len & 0xFF))
        out.append(body)
        return out
    }
}
