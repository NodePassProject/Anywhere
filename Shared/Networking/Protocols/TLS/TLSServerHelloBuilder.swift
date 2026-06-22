//
//  TLSServerHelloBuilder.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

enum TLSServerHelloBuilder {

    // MARK: - ServerHello

    static func buildServerHello(
        legacySessionID: Data,
        cipherSuite: UInt16,
        x25519PublicKey: Data
    ) -> Data {
        var random = Data(count: 32)
        random.withUnsafeMutableBytes { pointer in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, pointer.baseAddress!)
        }

        var body = Data()
        body.append(0x03); body.append(0x03)
        body.append(random)
        body.append(UInt8(legacySessionID.count))
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)

        var extensions = Data()
        extensions.append(buildSupportedVersionsServerExt())
        extensions.append(buildKeyShareServerExt(group: TLSNamedGroup.x25519, key: x25519PublicKey))
        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: TLSHandshakeType.serverHello, body: body)
    }

    static func buildHelloRetryRequest(
        legacySessionID: Data,
        cipherSuite: UInt16,
        requestedGroup: UInt16
    ) -> Data {
        var body = Data()
        body.append(0x03); body.append(0x03)
        body.append(TLSRandom.helloRetryRequest)
        body.append(UInt8(legacySessionID.count))
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)

        var extensions = Data()
        extensions.append(buildSupportedVersionsServerExt())
        var keyShareExt = Data()
        appendU16(&keyShareExt, TLSExtensionType.keyShare)
        let groupBytes = Data([
            UInt8((requestedGroup >> 8) & 0xFF),
            UInt8(requestedGroup & 0xFF),
        ])
        appendU16(&keyShareExt, 0x0002)
        keyShareExt.append(groupBytes)
        extensions.append(keyShareExt)

        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: TLSHandshakeType.serverHello, body: body)
    }

    // MARK: - TLS 1.2 ServerHello

    static func buildServerHello12(
        legacySessionID: Data,
        cipherSuite: UInt16,
        alpn: String?,
        extendedMasterSecret: Bool,
        secureRenegotiation: Bool,
        serverRandom: Data
    ) -> Data {
        var body = Data()
        body.append(0x03); body.append(0x03)
        body.append(serverRandom)
        body.append(UInt8(legacySessionID.count))
        body.append(legacySessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xFF))
        body.append(UInt8(cipherSuite & 0xFF))
        body.append(0x00)

        var extensions = Data()
        if extendedMasterSecret {
            appendU16(&extensions, TLSExtensionType.extendedMasterSecret)
            appendU16(&extensions, 0x0000)
        }
        if let alpn {
            extensions.append(buildALPNExtension(protocols: [alpn]))
        }
        if secureRenegotiation {
            appendU16(&extensions, TLSExtensionType.renegotiationInfo)
            appendU16(&extensions, 0x0001)
            extensions.append(0x00)
        }

        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)

        return wrapHandshake(type: TLSHandshakeType.serverHello, body: body)
    }

    // MARK: - TLS 1.2 Certificate

    static func buildCertificate12(leafCertDER: Data) -> Data {
        var body = Data()

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

        return wrapHandshake(type: TLSHandshakeType.certificate, body: body)
    }

    // MARK: - TLS 1.2 ServerKeyExchange

    static func serverECDHEParams(namedCurve: UInt16, publicKey: Data) -> Data {
        var parameters = Data()
        parameters.append(0x03)
        parameters.append(UInt8((namedCurve >> 8) & 0xFF))
        parameters.append(UInt8(namedCurve & 0xFF))
        parameters.append(UInt8(publicKey.count))
        parameters.append(publicKey)
        return parameters
    }

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
        return wrapHandshake(type: TLSHandshakeType.serverKeyExchange, body: body)
    }

    // MARK: - TLS 1.2 ServerHelloDone

    static func buildServerHelloDone() -> Data {
        wrapHandshake(type: TLSHandshakeType.serverHelloDone, body: Data())
    }

    // MARK: - TLS 1.2 Finished

    static func buildFinished12(verifyData: Data) -> Data {
        wrapHandshake(type: TLSHandshakeType.finished, body: verifyData)
    }

    // MARK: - EncryptedExtensions

    static func buildEncryptedExtensions(alpn: String?) -> Data {
        var body = Data()
        var extensions = Data()
        if let alpn {
            extensions.append(buildALPNExtension(protocols: [alpn]))
        }
        body.append(UInt8((extensions.count >> 8) & 0xFF))
        body.append(UInt8(extensions.count & 0xFF))
        body.append(extensions)
        return wrapHandshake(type: TLSHandshakeType.encryptedExtensions, body: body)
    }

    // MARK: - Certificate

    static func buildCertificate(leafCertDER: Data) -> Data {
        var body = Data()
        body.append(0x00)

        var entry = Data()
        let certLen = leafCertDER.count
        entry.append(UInt8((certLen >> 16) & 0xFF))
        entry.append(UInt8((certLen >> 8) & 0xFF))
        entry.append(UInt8(certLen & 0xFF))
        entry.append(leafCertDER)
        entry.append(0x00); entry.append(0x00)

        let listLen = entry.count
        body.append(UInt8((listLen >> 16) & 0xFF))
        body.append(UInt8((listLen >> 8) & 0xFF))
        body.append(UInt8(listLen & 0xFF))
        body.append(entry)

        return wrapHandshake(type: TLSHandshakeType.certificate, body: body)
    }

    // MARK: - CertificateVerify

    static func buildCertificateVerify(signatureAlgorithm: UInt16, signature: Data) -> Data {
        var body = Data()
        body.append(UInt8((signatureAlgorithm >> 8) & 0xFF))
        body.append(UInt8(signatureAlgorithm & 0xFF))
        body.append(UInt8((signature.count >> 8) & 0xFF))
        body.append(UInt8(signature.count & 0xFF))
        body.append(signature)
        return wrapHandshake(type: TLSHandshakeType.certificateVerify, body: body)
    }

    // MARK: - Finished

    static func buildFinished(verifyData: Data) -> Data {
        wrapHandshake(type: TLSHandshakeType.finished, body: verifyData)
    }

    // MARK: - CertificateVerify Signing Helpers

    static func certificateVerifyContext(transcriptHash: Data) -> Data {
        var context = Data(repeating: 0x20, count: 64)
        context.append(Data("TLS 1.3, server CertificateVerify".utf8))
        context.append(0x00)
        context.append(transcriptHash)
        return context
    }

    // MARK: - Alerts

    static func alert(level: UInt8, description: UInt8) -> Data {
        Data([level, description])
    }

    // MARK: - Extension builders

    @inline(__always)
    private static func appendU16(_ data: inout Data, _ value: UInt16) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }

    private static func buildSupportedVersionsServerExt() -> Data {
        var ext = Data()
        appendU16(&ext, TLSExtensionType.supportedVersions)
        appendU16(&ext, 0x0002)
        appendU16(&ext, 0x0304)
        return ext
    }

    private static func buildKeyShareServerExt(group: UInt16, key: Data) -> Data {
        var ext = Data()
        appendU16(&ext, TLSExtensionType.keyShare)
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
        appendU16(&ext, TLSExtensionType.applicationLayerProtocolNegotiation)
        let payloadLen = 2 + list.count
        ext.append(UInt8((payloadLen >> 8) & 0xFF))
        ext.append(UInt8(payloadLen & 0xFF))
        ext.append(UInt8((list.count >> 8) & 0xFF))
        ext.append(UInt8(list.count & 0xFF))
        ext.append(list)
        return ext
    }

    private static func wrapHandshake(type: UInt8, body: Data) -> Data {
        var out = Data()
        out.append(type)
        let length = body.count
        out.append(UInt8((length >> 16) & 0xFF))
        out.append(UInt8((length >> 8) & 0xFF))
        out.append(UInt8(length & 0xFF))
        out.append(body)
        return out
    }
}
