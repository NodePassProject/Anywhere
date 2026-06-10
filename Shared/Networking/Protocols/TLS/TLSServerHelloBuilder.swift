//
//  TLSServerHelloBuilder.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

enum TLSServerHelloBuilder {

    // MARK: - ServerHello

    /// Builds a TLS 1.3 ServerHello (handshake layer, no record header); the session ID is
    /// echoed verbatim from the ClientHello per RFC 8446 §4.1.3.
    static func buildServerHello(
        legacySessionID: Data,
        cipherSuite: UInt16,
        x25519PublicKey: Data
    ) -> Data {
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

        var extensions = Data()
        extensions.append(buildSupportedVersionsServerExt())
        extensions.append(buildKeyShareServerExt(group: 0x001D, key: x25519PublicKey))
        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: 0x02, body: body)
    }

    /// Builds a HelloRetryRequest: a ServerHello with the SHA-256("HelloRetryRequest") sentinel
    /// as Random and a key_share naming only the requested group.
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

    /// Builds a TLS 1.2 ServerHello: no supported_versions extension, and ALPN/EMS
    /// (which TLS 1.3 carries in EncryptedExtensions) appear directly in the extension list.
    static func buildServerHello12(
        legacySessionID: Data,
        cipherSuite: UInt16,
        alpn: String?,
        extendedMasterSecret: Bool,
        secureRenegotiation: Bool,
        serverRandom: Data
    ) -> Data {
        var body = Data()
        body.append(0x03); body.append(0x03)                          // version = TLS 1.2
        body.append(serverRandom)
        body.append(UInt8(legacySessionID.count))
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)                                             // legacy_compression_method = null

        // RFC 5246 §7.4.1.4: only echo extensions the client offered.
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

    /// Builds a TLS 1.2 Certificate message (RFC 5246 §7.4.2): unlike TLS 1.3, no request
    /// context or per-entry extensions — just a length-prefixed list of cert bodies.
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

    /// ECDHE ServerKeyExchange params blob (RFC 8422 §5.4): curve_type(1) || named_curve(2) ||
    /// pubkey_len(1) || pubkey(N) — the bytes that get signed and prefix the SKE message.
    static func serverECDHEParams(namedCurve: UInt16, publicKey: Data) -> Data {
        var params = Data()
        params.append(0x03)                                           // curve_type = named_curve
        params.append(UInt8((namedCurve >> 8) & 0xFF))
        params.append(UInt8(namedCurve & 0xFF))
        params.append(UInt8(publicKey.count))
        params.append(publicKey)
        return params
    }

    /// Builds a TLS 1.2 ECDHE_ECDSA ServerKeyExchange (RFC 8422 §5.4); the caller signed
    /// client_random || server_random || params.
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

    /// ServerHelloDone — RFC 5246 §7.4.5.
    static func buildServerHelloDone() -> Data {
        wrapHandshake(type: 0x0E, body: Data())
    }

    // MARK: - TLS 1.2 Finished

    /// TLS 1.2 Finished (RFC 5246 §7.4.9); verify_data is always 12 bytes.
    static func buildFinished12(verifyData: Data) -> Data {
        wrapHandshake(type: 0x14, body: verifyData)
    }

    // MARK: - EncryptedExtensions

    /// Builds an EncryptedExtensions message advertising the negotiated ALPN.
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

    /// Builds a single-leaf TLS 1.3 Certificate message (RFC 8446 §4.4.2).
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

    /// Builds a CertificateVerify carrying a DER-encoded ECDSA signature (RFC 8446 §4.4.3).
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

    static func buildFinished(verifyData: Data) -> Data {
        wrapHandshake(type: 0x14, body: verifyData)
    }

    // MARK: - CertificateVerify Signing Helpers

    /// Builds the server-side CertificateVerify signing input (RFC 8446 §4.4.3).
    static func certificateVerifyContext(transcriptHash: Data) -> Data {
        var ctx = Data(repeating: 0x20, count: 64)
        ctx.append(Data("TLS 1.3, server CertificateVerify".utf8))
        ctx.append(0x00)
        ctx.append(transcriptHash)
        return ctx
    }

    // MARK: - Alerts

    /// TLS Alert payload (level + description), without the record header.
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

    /// Handshake framing: `[type:1][length:3][body]`.
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
