//
//  X509Builder.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation
import CryptoKit
import Security

enum X509BuilderError: Error {
    case signingFailed(String)
    case publicKeyExportFailed
    case invalidPublicKey
    case asn1ParseFailed(String)
}

enum X509Builder {

    // MARK: - Public API

    /// Builds a self-signed CA certificate. The CA private key signs its own
    /// `tbsCertificate`; the public key embedded in the cert is the same
    /// key's public half.
    ///
    /// - Parameters:
    ///   - privateKey: ECDSA P-256 private key reference. May live in the
    ///     Secure Enclave or in software — this method only needs
    ///     ``SecKeyCreateSignature`` and ``SecKeyCopyPublicKey``, both of
    ///     which work transparently against either.
    ///   - subjectCN: Common Name for the CA subject (and issuer, since
    ///     it's self-signed).
    ///   - organization: Organization name written into the DN.
    ///   - serial: Monotonic 16-byte big-endian serial. Bits of all zeros
    ///     are normalized to 1 (RFC 5280 §4.1.2.2 forbids serial 0).
    ///   - notBefore: Validity start.
    ///   - notAfter: Validity end (typically +10 years).
    /// - Returns: DER-encoded certificate.
    static func buildCACertificate(
        privateKey: SecKey,
        subjectCN: String,
        organization: String,
        serial: Data,
        notBefore: Date,
        notAfter: Date
    ) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw X509BuilderError.publicKeyExportFailed
        }
        let spki = try buildECP256SPKI(publicKey: publicKey)
        let subject = encodeName(commonName: subjectCN, organization: organization)

        let extensions = encodeExtensions([
            encodeBasicConstraintsCA(pathLen: 0),
            encodeKeyUsage(keyCertSign: true, cRLSign: true, digitalSignature: false),
            try encodeSubjectKeyIdentifier(spki: spki),
        ])

        let tbs = encodeTBSCertificate(
            serial: normalizeSerial(serial),
            issuer: subject,
            validity: encodeValidity(notBefore: notBefore, notAfter: notAfter),
            subject: subject,
            spki: spki,
            extensions: extensions
        )

        let signature = try sign(privateKey: privateKey, data: tbs)
        return encodeCertificate(tbs: tbs, signature: signature)
    }

    /// Builds a leaf certificate signed by the CA private key.
    ///
    /// - Parameters:
    ///   - leafPublicKey: ECDSA P-256 public key for the leaf.
    ///   - caPrivateKey: ECDSA P-256 private key of the issuing CA.
    ///   - caCertificateDER: DER-encoded CA certificate. Issuer DN and AKID
    ///     are read directly from this blob so there's no chance of drift
    ///     between what the CA presents and what the leaf claims.
    ///   - hostname: SNI to embed into the SAN and Common Name.
    ///   - serial: Monotonic 16-byte big-endian serial.
    ///   - notBefore: Validity start (typically now − 1h for clock skew).
    ///   - notAfter: Validity end (typically now + 7d).
    /// - Returns: DER-encoded leaf certificate.
    static func buildLeafCertificate(
        leafPublicKey: P256.Signing.PublicKey,
        caPrivateKey: SecKey,
        caCertificateDER: Data,
        hostname: String,
        serial: Data,
        notBefore: Date,
        notAfter: Date
    ) throws -> Data {
        let leafSPKI = try buildECP256SPKI(publicKeyX963: leafPublicKey.x963Representation)
        let caComponents = try parseCAComponents(certDER: caCertificateDER)

        let subject = encodeName(commonName: hostname, organization: "Anywhere MITM")
        let validity = encodeValidity(notBefore: notBefore, notAfter: notAfter)

        let extensions = encodeExtensions([
            encodeBasicConstraintsLeaf(),
            encodeKeyUsage(keyCertSign: false, cRLSign: false, digitalSignature: true),
            encodeExtendedKeyUsageServerAuth(),
            try encodeSubjectKeyIdentifier(spki: leafSPKI),
            encodeAuthorityKeyIdentifier(keyIdentifier: caComponents.subjectKeyIdentifier),
            encodeSubjectAltName(dnsName: hostname),
        ])

        let tbs = encodeTBSCertificate(
            serial: normalizeSerial(serial),
            issuer: caComponents.subjectDN,
            validity: validity,
            subject: subject,
            spki: leafSPKI,
            extensions: extensions
        )

        let signature = try sign(privateKey: caPrivateKey, data: tbs)
        return encodeCertificate(tbs: tbs, signature: signature)
    }

    // MARK: - Subject / Issuer

    private static func encodeName(commonName: String, organization: String) -> Data {
        var rdnSequence = Data()
        rdnSequence.append(encodeRDN(oid: ASN1OID.organizationName, value: organization))
        rdnSequence.append(encodeRDN(oid: ASN1OID.commonName, value: commonName))
        return ASN1.sequence(rdnSequence)
    }

    /// Encodes a single RDN as a SET containing one AttributeTypeAndValue.
    private static func encodeRDN(oid: Data, value: String) -> Data {
        var atv = Data()
        atv.append(oid)
        atv.append(ASN1.utf8String(value))
        let atvSeq = ASN1.sequence(atv)
        return ASN1.set(atvSeq)
    }

    // MARK: - Validity

    private static func encodeValidity(notBefore: Date, notAfter: Date) -> Data {
        var validity = Data()
        validity.append(encodeTime(notBefore))
        validity.append(encodeTime(notAfter))
        return ASN1.sequence(validity)
    }

    /// RFC 5280 §4.1.2.5: UTCTime for years 1950..2049, GeneralizedTime
    /// otherwise. UTCTime is two-digit year, GeneralizedTime is four.
    private static func encodeTime(_ date: Date) -> Data {
        let calendar = Calendar(identifier: .gregorian)
        var calCopy = calendar
        calCopy.timeZone = TimeZone(identifier: "UTC")!
        let components = calCopy.dateComponents(
            [.year, .month, .day, .hour, .minute, .second],
            from: date
        )
        let year = components.year ?? 0
        let month = components.month ?? 0
        let day = components.day ?? 0
        let hour = components.hour ?? 0
        let minute = components.minute ?? 0
        let second = components.second ?? 0

        if year >= 1950 && year <= 2049 {
            let yy = year % 100
            let utc = String(format: "%02d%02d%02d%02d%02d%02dZ",
                             yy, month, day, hour, minute, second)
            return ASN1.utcTime(utc)
        } else {
            let gen = String(format: "%04d%02d%02d%02d%02d%02dZ",
                             year, month, day, hour, minute, second)
            return ASN1.generalizedTime(gen)
        }
    }

    // MARK: - SubjectPublicKeyInfo

    /// Builds an SPKI from a `SecKey`. Only ECDSA P-256 is supported.
    private static func buildECP256SPKI(publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            _ = error?.takeRetainedValue()
            throw X509BuilderError.publicKeyExportFailed
        }
        return try buildECP256SPKI(publicKeyX963: raw)
    }

    /// Builds an SPKI from the X9.63 (uncompressed) point representation.
    /// CryptoKit returns X9.63 directly; ``SecKeyCopyExternalRepresentation``
    /// also returns X9.63 for ECC keys.
    private static func buildECP256SPKI(publicKeyX963: Data) throws -> Data {
        guard publicKeyX963.count == 65, publicKeyX963.first == 0x04 else {
            throw X509BuilderError.invalidPublicKey
        }

        var algorithm = Data()
        algorithm.append(ASN1OID.ecPublicKey)
        algorithm.append(ASN1OID.prime256v1)
        let algorithmSeq = ASN1.sequence(algorithm)

        // SubjectPublicKey is a BIT STRING wrapping the uncompressed point.
        let subjectPublicKey = ASN1.bitString(unusedBits: 0, content: publicKeyX963)

        var spki = Data()
        spki.append(algorithmSeq)
        spki.append(subjectPublicKey)
        return ASN1.sequence(spki)
    }

    // MARK: - Extensions

    private static func encodeExtensions(_ extensions: [Data]) -> Data {
        var inner = Data()
        for e in extensions { inner.append(e) }
        let seq = ASN1.sequence(inner)
        // Wrapped in [3] EXPLICIT
        return ASN1.contextSpecific(tag: 3, constructed: true, content: seq)
    }

    private static func encodeExtension(oid: Data, critical: Bool, value: Data) -> Data {
        var inner = Data()
        inner.append(oid)
        if critical {
            inner.append(ASN1.boolean(true))
        }
        inner.append(ASN1.octetString(value))
        return ASN1.sequence(inner)
    }

    private static func encodeBasicConstraintsCA(pathLen: Int) -> Data {
        var bc = Data()
        bc.append(ASN1.boolean(true))                 // cA = TRUE
        bc.append(ASN1.integer(Int64(pathLen)))       // pathLenConstraint
        let value = ASN1.sequence(bc)
        return encodeExtension(oid: ASN1OID.basicConstraints, critical: true, value: value)
    }

    private static func encodeBasicConstraintsLeaf() -> Data {
        // Empty SEQUENCE — cA defaults to FALSE.
        let value = ASN1.sequence(Data())
        return encodeExtension(oid: ASN1OID.basicConstraints, critical: true, value: value)
    }

    /// Bits per RFC 5280 §4.2.1.3:
    ///   0 digitalSignature, 1 nonRepudiation, 2 keyEncipherment,
    ///   3 dataEncipherment, 4 keyAgreement, 5 keyCertSign, 6 cRLSign.
    private static func encodeKeyUsage(keyCertSign: Bool, cRLSign: Bool, digitalSignature: Bool) -> Data {
        var byte: UInt8 = 0
        if digitalSignature { byte |= 0b1000_0000 }
        if keyCertSign      { byte |= 0b0000_0100 }
        if cRLSign          { byte |= 0b0000_0010 }

        // Compute unused bits: number of trailing zero bits in the active byte.
        var unused: UInt8 = 0
        if byte == 0 {
            unused = 8
        } else {
            var b = byte
            while b & 1 == 0 {
                unused += 1
                b >>= 1
            }
        }
        let bitString = ASN1.bitString(unusedBits: unused, content: Data([byte]))
        return encodeExtension(oid: ASN1OID.keyUsage, critical: true, value: bitString)
    }

    /// SAN: GeneralName = [2] dNSName.
    private static func encodeSubjectAltName(dnsName: String) -> Data {
        let nameBytes = Data(dnsName.utf8)
        let dnsGeneralName = ASN1.contextSpecific(tag: 2, constructed: false, content: nameBytes)
        let value = ASN1.sequence(dnsGeneralName)
        return encodeExtension(oid: ASN1OID.subjectAltName, critical: false, value: value)
    }

    private static func encodeExtendedKeyUsageServerAuth() -> Data {
        let value = ASN1.sequence(ASN1OID.serverAuth)
        return encodeExtension(oid: ASN1OID.extKeyUsage, critical: false, value: value)
    }

    private static func encodeSubjectKeyIdentifier(spki: Data) throws -> Data {
        // SKI is the SHA-1 of the SubjectPublicKey BIT STRING content (RFC 5280 §4.2.1.2 method (1)).
        let publicKeyContent = try extractSubjectPublicKey(spki: spki)
        let digest = sha1(publicKeyContent)
        let value = ASN1.octetString(Data(digest))
        return encodeExtension(oid: ASN1OID.subjectKeyIdentifier, critical: false, value: value)
    }

    private static func encodeAuthorityKeyIdentifier(keyIdentifier: Data) -> Data {
        // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OCTET STRING OPTIONAL, ... }
        let inner = ASN1.contextSpecific(tag: 0, constructed: false, content: keyIdentifier)
        let value = ASN1.sequence(inner)
        return encodeExtension(oid: ASN1OID.authorityKeyIdentifier, critical: false, value: value)
    }

    // MARK: - Algorithm Identifier

    /// ECDSA-with-SHA256 — used both inside `tbsCertificate.signature` and
    /// in the outer `signatureAlgorithm` field.
    private static let algorithmECDSAWithSHA256: Data = {
        ASN1.sequence(ASN1OID.ecdsaWithSHA256)
    }()

    // MARK: - TBSCertificate

    private static func encodeTBSCertificate(
        serial: Data,
        issuer: Data,
        validity: Data,
        subject: Data,
        spki: Data,
        extensions: Data
    ) -> Data {
        var tbs = Data()
        // version [0] EXPLICIT INTEGER (v3 = 2)
        let versionInner = ASN1.integer(2)
        let versionWrapped = ASN1.contextSpecific(tag: 0, constructed: true, content: versionInner)
        tbs.append(versionWrapped)

        // serialNumber INTEGER
        tbs.append(ASN1.rawInteger(serial))

        // signature AlgorithmIdentifier
        tbs.append(algorithmECDSAWithSHA256)

        // issuer Name
        tbs.append(issuer)

        // validity
        tbs.append(validity)

        // subject Name
        tbs.append(subject)

        // SubjectPublicKeyInfo
        tbs.append(spki)

        // extensions [3] EXPLICIT
        tbs.append(extensions)

        return ASN1.sequence(tbs)
    }

    // MARK: - Outer Certificate

    private static func encodeCertificate(tbs: Data, signature: Data) -> Data {
        var inner = Data()
        inner.append(tbs)
        inner.append(algorithmECDSAWithSHA256)
        inner.append(ASN1.bitString(unusedBits: 0, content: signature))
        return ASN1.sequence(inner)
    }

    // MARK: - Signing

    private static func sign(privateKey: SecKey, data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            let err = error?.takeRetainedValue()
            throw X509BuilderError.signingFailed(err.flatMap { CFErrorCopyDescription($0) as String? } ?? "unknown")
        }
        return signature
    }

    // MARK: - CA Component Reuse
    //
    // To keep the leaf's "issuer" field byte-identical to the CA's "subject"
    // field, we read the CA cert's DER directly rather than re-encoding from
    // the parameters. Same for the AKID — the CA's SKI is what the AKID
    // references.

    private struct CAComponents {
        let subjectDN: Data
        let subjectKeyIdentifier: Data
    }

    private static func parseCAComponents(certDER: Data) throws -> CAComponents {
        var parser = ASN1Parser(data: certDER)
        let cert = try parser.readSequence()                        // Certificate
        var certParser = ASN1Parser(data: cert)
        let tbs = try certParser.readSequence()                     // TBSCertificate
        var tbsParser = ASN1Parser(data: tbs)
        try tbsParser.skipExplicitContextSpecific(tag: 0)           // version
        try tbsParser.skipNext()                                    // serialNumber
        try tbsParser.skipNext()                                    // signature algorithm
        try tbsParser.skipNext()                                    // issuer (we don't need it here)
        try tbsParser.skipNext()                                    // validity
        let subjectDN = try tbsParser.readNextWithHeader(expectedTag: 0x30)
        try tbsParser.skipNext()                                    // SPKI
        let extensionsBlob = try tbsParser.readExplicitContextSpecific(tag: 3)
        let ski = try extractSKIFromExtensions(extensionsBlob)
        return CAComponents(subjectDN: subjectDN, subjectKeyIdentifier: ski)
    }

    private static func extractSKIFromExtensions(_ blob: Data) throws -> Data {
        var parser = ASN1Parser(data: blob)
        let seq = try parser.readSequence()
        var seqParser = ASN1Parser(data: seq)
        while !seqParser.isAtEnd {
            let ext = try seqParser.readSequence()
            var extParser = ASN1Parser(data: ext)
            let oid = try extParser.readNextWithHeader(expectedTag: 0x06)
            // Drop the tag/length to compare contents only.
            let oidContent = try ASN1Parser.contentOf(oid)
            // Optional `critical` BOOLEAN
            if try extParser.peekTag() == 0x01 {
                try extParser.skipNext()
            }
            let octets = try extParser.readNextWithHeader(expectedTag: 0x04)
            let octetContent = try ASN1Parser.contentOf(octets)
            if oidContent == ASN1OID.contentSubjectKeyIdentifier {
                // octetContent is an OCTET STRING wrapping another OCTET STRING.
                var inner = ASN1Parser(data: octetContent)
                let identifier = try inner.readNextWithHeader(expectedTag: 0x04)
                return try ASN1Parser.contentOf(identifier)
            }
        }
        throw X509BuilderError.asn1ParseFailed("CA cert missing SubjectKeyIdentifier")
    }

    private static func extractSubjectPublicKey(spki: Data) throws -> Data {
        var parser = ASN1Parser(data: spki)
        let seq = try parser.readSequence()
        var seqParser = ASN1Parser(data: seq)
        try seqParser.skipNext()                                    // algorithm
        let bitString = try seqParser.readNextWithHeader(expectedTag: 0x03)
        let content = try ASN1Parser.contentOf(bitString)
        // First content byte is "unused bits" — skip it.
        guard let first = content.first else {
            throw X509BuilderError.asn1ParseFailed("Empty BIT STRING")
        }
        _ = first
        return content.dropFirst()
    }

    // MARK: - Helpers

    private static func normalizeSerial(_ serial: Data) -> Data {
        // RFC 5280: serial must be a positive integer. Strip any leading
        // zeros, then ensure top bit is clear (otherwise INTEGER would be
        // negative, requiring a 0x00 prefix — easier to just zero the top
        // bit and re-add a 0x00 if needed below).
        var trimmed = serial
        while trimmed.count > 1 && trimmed.first == 0x00 {
            trimmed = trimmed.dropFirst()
        }
        if trimmed.isEmpty { trimmed = Data([0x01]) }
        // If top bit set, prepend 0x00 to keep INTEGER positive.
        if let first = trimmed.first, first & 0x80 != 0 {
            var prefixed = Data([0x00])
            prefixed.append(trimmed)
            return prefixed
        }
        return trimmed
    }

    private static func sha1(_ data: Data) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }
}

// MARK: - ASN.1 Encoding Primitives

private enum ASN1 {

    static func sequence(_ content: Data) -> Data {
        emit(tag: 0x30, content: content)
    }

    static func set(_ content: Data) -> Data {
        emit(tag: 0x31, content: content)
    }

    static func contextSpecific(tag: UInt8, constructed: Bool, content: Data) -> Data {
        let classBits: UInt8 = 0x80
        let constructedBit: UInt8 = constructed ? 0x20 : 0x00
        return emit(tag: classBits | constructedBit | (tag & 0x1F), content: content)
    }

    static func integer(_ value: Int64) -> Data {
        if value == 0 {
            return Data([0x02, 0x01, 0x00])
        }
        var bytes: [UInt8] = []
        var v = value
        let negative = v < 0
        repeat {
            bytes.insert(UInt8(truncatingIfNeeded: v & 0xFF), at: 0)
            v >>= 8
        } while !(v == 0 || v == -1)

        // Sign correction
        if !negative, let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        } else if negative, let first = bytes.first, first & 0x80 == 0 {
            bytes.insert(0xFF, at: 0)
        }
        return emit(tag: 0x02, content: Data(bytes))
    }

    /// Wraps a raw big-endian INTEGER content blob — caller is responsible
    /// for sign-correctness.
    static func rawInteger(_ content: Data) -> Data {
        emit(tag: 0x02, content: content)
    }

    static func boolean(_ value: Bool) -> Data {
        emit(tag: 0x01, content: Data([value ? 0xFF : 0x00]))
    }

    static func octetString(_ content: Data) -> Data {
        emit(tag: 0x04, content: content)
    }

    static func bitString(unusedBits: UInt8, content: Data) -> Data {
        var payload = Data([unusedBits])
        payload.append(content)
        return emit(tag: 0x03, content: payload)
    }

    static func utf8String(_ value: String) -> Data {
        emit(tag: 0x0C, content: Data(value.utf8))
    }

    static func utcTime(_ value: String) -> Data {
        emit(tag: 0x17, content: Data(value.utf8))
    }

    static func generalizedTime(_ value: String) -> Data {
        emit(tag: 0x18, content: Data(value.utf8))
    }

    static func emit(tag: UInt8, content: Data) -> Data {
        var out = Data()
        out.append(tag)
        out.append(encodeLength(content.count))
        out.append(content)
        return out
    }

    static func encodeLength(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        }
        var bytes: [UInt8] = []
        var v = length
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

// MARK: - Pre-encoded OIDs and constants

private enum ASN1OID {
    static let commonName               = Data([0x06, 0x03, 0x55, 0x04, 0x03])              // 2.5.4.3
    static let organizationName         = Data([0x06, 0x03, 0x55, 0x04, 0x0A])              // 2.5.4.10
    static let basicConstraints         = Data([0x06, 0x03, 0x55, 0x1D, 0x13])              // 2.5.29.19
    static let keyUsage                 = Data([0x06, 0x03, 0x55, 0x1D, 0x0F])              // 2.5.29.15
    static let extKeyUsage              = Data([0x06, 0x03, 0x55, 0x1D, 0x25])              // 2.5.29.37
    static let subjectAltName           = Data([0x06, 0x03, 0x55, 0x1D, 0x11])              // 2.5.29.17
    static let subjectKeyIdentifier     = Data([0x06, 0x03, 0x55, 0x1D, 0x0E])              // 2.5.29.14
    static let authorityKeyIdentifier   = Data([0x06, 0x03, 0x55, 0x1D, 0x23])              // 2.5.29.35

    /// The raw OID body (minus tag/length), used for parsing comparisons.
    static let contentSubjectKeyIdentifier = Data([0x55, 0x1D, 0x0E])

    /// id-ecPublicKey 1.2.840.10045.2.1
    static let ecPublicKey = Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
    /// secp256r1 1.2.840.10045.3.1.7
    static let prime256v1  = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    /// ecdsa-with-SHA256 1.2.840.10045.4.3.2
    static let ecdsaWithSHA256 = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
    /// id-kp-serverAuth 1.3.6.1.5.5.7.3.1
    static let serverAuth  = Data([0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
}

// MARK: - Minimal ASN.1 Parser

private struct ASN1Parser {
    let data: Data
    var offset: Int

    init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    var isAtEnd: Bool { offset >= data.endIndex }

    mutating func peekTag() throws -> UInt8 {
        guard offset < data.endIndex else {
            throw X509BuilderError.asn1ParseFailed("Unexpected end of data")
        }
        return data[offset]
    }

    mutating func readSequence() throws -> Data {
        try readContent(expectedTag: 0x30)
    }

    mutating func readNextWithHeader(expectedTag: UInt8?) throws -> Data {
        guard offset < data.endIndex else {
            throw X509BuilderError.asn1ParseFailed("Unexpected end of data")
        }
        let tag = data[offset]
        if let expected = expectedTag, tag != expected {
            throw X509BuilderError.asn1ParseFailed("Tag mismatch: expected \(expected), got \(tag)")
        }
        let start = offset
        let (length, lengthBytes) = try parseLength(at: offset + 1)
        let total = 1 + lengthBytes + length
        let end = start + total
        guard end <= data.endIndex else {
            throw X509BuilderError.asn1ParseFailed("Length overrun")
        }
        offset = end
        return data[start..<end]
    }

    mutating func skipNext() throws {
        _ = try readNextWithHeader(expectedTag: nil)
    }

    mutating func readExplicitContextSpecific(tag: UInt8) throws -> Data {
        let expected: UInt8 = 0xA0 | (tag & 0x1F)
        let blob = try readNextWithHeader(expectedTag: expected)
        return try ASN1Parser.contentOf(blob)
    }

    mutating func skipExplicitContextSpecific(tag: UInt8) throws {
        let expected: UInt8 = 0xA0 | (tag & 0x1F)
        _ = try readNextWithHeader(expectedTag: expected)
    }

    private mutating func readContent(expectedTag: UInt8) throws -> Data {
        let blob = try readNextWithHeader(expectedTag: expectedTag)
        return try ASN1Parser.contentOf(blob)
    }

    private func parseLength(at start: Int) throws -> (length: Int, bytes: Int) {
        guard start < data.endIndex else {
            throw X509BuilderError.asn1ParseFailed("Length truncated")
        }
        let first = data[start]
        if first & 0x80 == 0 {
            return (Int(first), 1)
        }
        let count = Int(first & 0x7F)
        guard count > 0, count <= 4, start + count < data.endIndex else {
            throw X509BuilderError.asn1ParseFailed("Length encoding invalid")
        }
        var length = 0
        for i in 0..<count {
            length = (length << 8) | Int(data[start + 1 + i])
        }
        return (length, 1 + count)
    }

    /// Returns the content bytes of a tag-length-value blob (skips the
    /// tag and length header).
    static func contentOf(_ tlv: Data) throws -> Data {
        guard !tlv.isEmpty else {
            throw X509BuilderError.asn1ParseFailed("Empty TLV")
        }
        let lengthByte = tlv[tlv.startIndex + 1]
        let lengthHeaderBytes: Int
        if lengthByte & 0x80 == 0 {
            lengthHeaderBytes = 1
        } else {
            lengthHeaderBytes = 1 + Int(lengthByte & 0x7F)
        }
        let prefix = 1 + lengthHeaderBytes
        guard tlv.count >= prefix else {
            throw X509BuilderError.asn1ParseFailed("TLV truncated")
        }
        return tlv.suffix(from: tlv.startIndex + prefix)
    }
}
