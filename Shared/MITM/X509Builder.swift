//
//  X509Builder.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Network
import Security

enum X509BuilderError: Error {
    case signingFailed(String)
    case publicKeyExportFailed
    case invalidPublicKey
    case asn1ParseFailed(String)
}

enum X509Builder {

    // MARK: - Public API

    /// Builds a self-signed CA certificate (ECDSA P-256); returns DER.
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

    /// Builds a leaf certificate signed by the CA key; issuer DN and AKID are
    /// parsed from `caCertificateDER` for byte-exact agreement. Returns DER.
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

        // Strip IPv6 URI brackets so the CN matches the bracket-free SAN address.
        let cnHostname: String
        if hostname.hasPrefix("["), hostname.hasSuffix("]"), hostname.count >= 2 {
            cnHostname = String(hostname.dropFirst().dropLast())
        } else {
            cnHostname = hostname
        }
        let subject = encodeName(commonName: cnHostname, organization: "Anywhere")
        let validity = encodeValidity(notBefore: notBefore, notAfter: notAfter)

        let extensions = encodeExtensions([
            encodeBasicConstraintsLeaf(),
            encodeKeyUsage(keyCertSign: false, cRLSign: false, digitalSignature: true),
            encodeExtendedKeyUsageServerAuth(),
            try encodeSubjectKeyIdentifier(spki: leafSPKI),
            encodeAuthorityKeyIdentifier(keyIdentifier: caComponents.subjectKeyIdentifier),
            encodeSubjectAltName(hostname: hostname),
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

    /// Builds a short-lived leaf certificate issued by the CA for signing a
    /// document (e.g. a configuration profile). Returns DER.
    static func buildSigningCertificate(
        signingKey: SecKey,
        caPrivateKey: SecKey,
        caCertificateDER: Data,
        commonName: String,
        serial: Data,
        notBefore: Date,
        notAfter: Date
    ) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(signingKey) else {
            throw X509BuilderError.publicKeyExportFailed
        }
        let spki = try buildECP256SPKI(publicKey: publicKey)
        let caComponents = try parseCAComponents(certDER: caCertificateDER)
        let subject = encodeName(commonName: commonName, organization: "Anywhere")

        let extensions = encodeExtensions([
            encodeBasicConstraintsLeaf(),
            encodeKeyUsage(keyCertSign: false, cRLSign: false, digitalSignature: true),
            try encodeSubjectKeyIdentifier(spki: spki),
            encodeAuthorityKeyIdentifier(keyIdentifier: caComponents.subjectKeyIdentifier),
        ])

        let tbs = encodeTBSCertificate(
            serial: normalizeSerial(serial),
            issuer: caComponents.subjectDN,
            validity: encodeValidity(notBefore: notBefore, notAfter: notAfter),
            subject: subject,
            spki: spki,
            extensions: extensions
        )

        let signature = try sign(privateKey: caPrivateKey, data: tbs)
        return encodeCertificate(tbs: tbs, signature: signature)
    }

    // MARK: - CMS Profile Signing

    /// Wraps `profileData` (a `.mobileconfig` plist) in a CMS SignedData structure
    /// (RFC 5652) signed by `signerPrivateKey`. `certificates` should carry the
    /// signer's certificate followed by any chain up to the CA.
    static func buildSignedProfile(
        profileData: Data,
        signerPrivateKey: SecKey,
        signerCertificateDER: Data,
        certificates: [Data]
    ) throws -> Data {
        let (issuer, serial) = try parseIssuerAndSerial(certDER: signerCertificateDER)

        // digestAlgorithm SHA-256; parameters omitted per RFC 5754 §2.
        let digestAlgorithm = ASN1.sequence(ASN1OID.sha256)

        // Authenticated attributes bind the signature to the content type and a
        // digest of the payload (RFC 5652 §5.3). When present, the signature is
        // computed over their DER, not over the content directly.
        let contentTypeAttr = ASN1.sequence(
            ASN1OID.attrContentType + ASN1.set(ASN1OID.data)
        )
        let messageDigestAttr = ASN1.sequence(
            ASN1OID.attrMessageDigest + ASN1.set(ASN1.octetString(Data(SHA256.hash(data: profileData))))
        )
        // DER SET OF requires the elements sorted by their encodings (X.690 §11.6).
        let attributes = derSortedSetOf([contentTypeAttr, messageDigestAttr])

        // Sign the attributes under the explicit SET OF tag (0x31); they appear in
        // the SignerInfo under the [0] IMPLICIT tag (0xA0) with identical content.
        let signature = try sign(privateKey: signerPrivateKey, data: ASN1.set(attributes))
        let signedAttrs = ASN1.contextSpecific(tag: 0, constructed: true, content: attributes)

        // SignerInfo (RFC 5652 §5.3); version 1 for the IssuerAndSerialNumber sid.
        var signerInfo = Data()
        signerInfo.append(ASN1.integer(1))
        signerInfo.append(ASN1.sequence(issuer + serial))       // sid = IssuerAndSerialNumber
        signerInfo.append(digestAlgorithm)
        signerInfo.append(signedAttrs)
        signerInfo.append(algorithmECDSAWithSHA256)             // signatureAlgorithm
        signerInfo.append(ASN1.octetString(signature))

        // EncapsulatedContentInfo: attached id-data payload (RFC 5652 §5.2).
        let eContent = ASN1.contextSpecific(tag: 0, constructed: true, content: ASN1.octetString(profileData))
        let encapContentInfo = ASN1.sequence(ASN1OID.data + eContent)

        // SignedData (RFC 5652 §5.1), version 1; the signer + chain ride in [0] IMPLICIT.
        var certificateSet = Data()
        for certificate in certificates { certificateSet.append(certificate) }

        var signedData = Data()
        signedData.append(ASN1.integer(1))
        signedData.append(ASN1.set(digestAlgorithm))            // digestAlgorithms
        signedData.append(encapContentInfo)
        signedData.append(ASN1.contextSpecific(tag: 0, constructed: true, content: certificateSet))  // certificates [0]
        signedData.append(ASN1.set(ASN1.sequence(signerInfo)))  // signerInfos

        // ContentInfo: id-signedData wrapping SignedData in [0] EXPLICIT.
        let content = ASN1.contextSpecific(tag: 0, constructed: true, content: ASN1.sequence(signedData))
        return ASN1.sequence(ASN1OID.signedData + content)
    }

    /// Reads the `issuer` DN and `serialNumber` (full TLVs) from a certificate for
    /// use as a CMS `IssuerAndSerialNumber`. Assumes the v3 layout this builder emits.
    private static func parseIssuerAndSerial(certDER: Data) throws -> (issuer: Data, serial: Data) {
        var parser = ASN1Parser(data: certDER)
        let cert = try parser.readSequence()                    // Certificate
        var certParser = ASN1Parser(data: cert)
        let tbs = try certParser.readSequence()                 // TBSCertificate
        var tbsParser = ASN1Parser(data: tbs)
        try tbsParser.skipExplicitContextSpecific(tag: 0)       // version [0]
        let serial = try tbsParser.readNextWithHeader(expectedTag: 0x02)   // serialNumber
        try tbsParser.skipNext()                                // signature algorithm
        let issuer = try tbsParser.readNextWithHeader(expectedTag: 0x30)   // issuer Name
        return (issuer, serial)
    }

    /// Concatenates DER elements in ascending encoding order (X.690 §11.6): octet
    /// strings compared with the shorter padded by trailing zero octets.
    private static func derSortedSetOf(_ elements: [Data]) -> Data {
        let sorted = elements.sorted { lhs, rhs in
            let count = max(lhs.count, rhs.count)
            for i in 0..<count {
                let l = i < lhs.count ? lhs[lhs.startIndex + i] : 0
                let r = i < rhs.count ? rhs[rhs.startIndex + i] : 0
                if l != r { return l < r }
            }
            return lhs.count < rhs.count
        }
        var out = Data()
        for element in sorted { out.append(element) }
        return out
    }

    // MARK: - Subject / Issuer

    private static func encodeName(commonName: String, organization: String) -> Data {
        var rdnSequence = Data()
        rdnSequence.append(encodeRDN(oid: ASN1OID.organizationName, value: organization))
        rdnSequence.append(encodeRDN(oid: ASN1OID.commonName, value: commonName))
        return ASN1.sequence(rdnSequence)
    }

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

    /// RFC 5280 §4.1.2.5: UTCTime for years 1950–2049, GeneralizedTime otherwise.
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

    /// Builds an SPKI from the X9.63 (uncompressed, 0x04-prefixed) point format
    /// that both CryptoKit and `SecKeyCopyExternalRepresentation` emit for P-256.
    private static func buildECP256SPKI(publicKeyX963: Data) throws -> Data {
        guard publicKeyX963.count == 65, publicKeyX963.first == 0x04 else {
            throw X509BuilderError.invalidPublicKey
        }

        var algorithm = Data()
        algorithm.append(ASN1OID.ecPublicKey)
        algorithm.append(ASN1OID.prime256v1)
        let algorithmSeq = ASN1.sequence(algorithm)

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
        var basicConstraints = Data()
        basicConstraints.append(ASN1.boolean(true))                 // cA = TRUE
        basicConstraints.append(ASN1.integer(Int64(pathLen)))       // pathLenConstraint
        let value = ASN1.sequence(basicConstraints)
        return encodeExtension(oid: ASN1OID.basicConstraints, critical: true, value: value)
    }

    private static func encodeBasicConstraintsLeaf() -> Data {
        // Empty SEQUENCE — cA defaults to FALSE.
        let value = ASN1.sequence(Data())
        return encodeExtension(oid: ASN1OID.basicConstraints, critical: true, value: value)
    }

    /// RFC 5280 §4.2.1.3 bits (MSB-first): 0 digitalSignature, 5 keyCertSign,
    /// 6 cRLSign; unusedBits = 7 − highest set position.
    private static func encodeKeyUsage(keyCertSign: Bool, cRLSign: Bool, digitalSignature: Bool) -> Data {
        var positions: [Int] = []
        if digitalSignature { positions.append(0) }
        if keyCertSign      { positions.append(5) }
        if cRLSign          { positions.append(6) }
        guard let highest = positions.max() else {
            // No bits set: emit a well-formed empty BIT STRING rather than malformed DER.
            let bitString = ASN1.bitString(unusedBits: 0, content: Data())
            return encodeExtension(oid: ASN1OID.keyUsage, critical: true, value: bitString)
        }
        var byte: UInt8 = 0
        for position in positions {
            byte |= UInt8(0x80 >> position)
        }
        let unused = UInt8(7 - highest)
        let bitString = ASN1.bitString(unusedBits: unused, content: Data([byte]))
        return encodeExtension(oid: ASN1OID.keyUsage, critical: true, value: bitString)
    }

    /// Emits an `iPAddress` GeneralName for IP literals (RFC 5280 §4.2.1.6 —
    /// Safari and Chrome reject a `dNSName` holding an IP), `dNSName` otherwise.
    private static func encodeSubjectAltName(hostname: String) -> Data {
        let generalName: Data
        if let ipBytes = parseIPAddress(hostname) {
            generalName = ASN1.contextSpecific(tag: 7, constructed: false, content: ipBytes)
        } else {
            // dNSName is IA5String (ASCII only); convert U-labels to IDNA A-labels
            // or SecTrust hostname matching fails.
            let asciiHost = Self.idnaASCII(hostname) ?? hostname
            let nameBytes = Data(asciiHost.utf8)
            generalName = ASN1.contextSpecific(tag: 2, constructed: false, content: nameBytes)
        }
        let value = ASN1.sequence(generalName)
        return encodeExtension(oid: ASN1OID.subjectAltName, critical: false, value: value)
    }

    /// Returns the 4- or 16-byte network-order address, or nil if `hostname` is not an
    /// IP literal; zone identifiers (`%en0`) are invalid in certificates.
    private static func parseIPAddress(_ hostname: String) -> Data? {
        // SNI wraps IPv6 literals in [brackets].
        let trimmed: String
        if hostname.hasPrefix("["), hostname.hasSuffix("]") {
            trimmed = String(hostname.dropFirst().dropLast())
        } else {
            trimmed = hostname
        }
        if trimmed.contains("%") { return nil }
        // `IPv4Address` accepts inet_aton shorthands ("1.2.3") that are valid DNS
        // hostnames; gate on a strict dotted-quad so such hosts aren't mis-encoded
        // as `iPAddress` SANs.
        if Self.isDottedQuadIPv4(trimmed), let v4 = IPv4Address(trimmed) {
            return v4.rawValue
        }
        if trimmed.contains(":"), let v6 = IPv6Address(trimmed) {
            return v6.rawValue
        }
        return nil
    }

    /// True only for a canonical dotted-quad; rejects inet_aton shorthands.
    private static func isDottedQuadIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        for part in parts {
            guard (1...3).contains(part.count),
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let value = Int(part), value <= 255
            else { return false }
        }
        return true
    }

    /// Converts `hostname` to IDNA ASCII (A-label); nil only on Punycode delta overflow.
    private static func idnaASCII(_ hostname: String) -> String? {
        guard hostname.contains(where: { !$0.isASCII }) else { return hostname }
        var labels: [String] = []
        for label in hostname.split(separator: ".", omittingEmptySubsequences: false) {
            if label.allSatisfy({ $0.isASCII }) {
                labels.append(String(label))
            } else {
                guard let puny = punycodeEncode(String(label)) else { return nil }
                labels.append("xn--" + puny)
            }
        }
        return labels.joined(separator: ".")
    }

    /// RFC 3492 Punycode encode of one label (no `xn--` prefix); nil on delta overflow.
    private static func punycodeEncode(_ input: String) -> String? {
        let base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700
        let initialBias = 72, initialN = 128
        func adapt(_ delta: Int, _ numPoints: Int, _ firstTime: Bool) -> Int {
            var delta = firstTime ? delta / damp : delta / 2
            delta += delta / numPoints
            var k = 0
            while delta > ((base - tmin) * tmax) / 2 {
                delta /= (base - tmin)
                k += base
            }
            return k + (((base - tmin + 1) * delta) / (delta + skew))
        }
        // 0…25 → 'a'…'z', 26…35 → '0'…'9'.
        func digit(_ d: Int) -> Character {
            Character(UnicodeScalar(UInt8(d < 26 ? d + 97 : d - 26 + 48)))
        }
        let scalars = Array(input.unicodeScalars)
        var output = ""
        var n = initialN, delta = 0, bias = initialBias
        var basic = 0
        for s in scalars where s.value < 0x80 {
            output.append(Character(s))
            basic += 1
        }
        if basic > 0 { output.append("-") }
        var handled = basic
        while handled < scalars.count {
            var m = Int.max
            for s in scalars where Int(s.value) >= n && Int(s.value) < m { m = Int(s.value) }
            if m - n > (Int.max - delta) / (handled + 1) { return nil }
            delta += (m - n) * (handled + 1)
            n = m
            for s in scalars {
                let c = Int(s.value)
                if c < n {
                    delta += 1
                    if delta == 0 { return nil }
                }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, handled + 1, handled == basic)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return output
    }

    private static func encodeExtendedKeyUsageServerAuth() -> Data {
        let value = ASN1.sequence(ASN1OID.serverAuth)
        return encodeExtension(oid: ASN1OID.extKeyUsage, critical: false, value: value)
    }

    private static func encodeSubjectKeyIdentifier(spki: Data) throws -> Data {
        // SKI = SHA-1 of the BIT STRING content (RFC 5280 §4.2.1.2, method 1).
        let publicKeyContent = try extractSubjectPublicKey(spki: spki)
        let digest = sha1(publicKeyContent)
        let value = ASN1.octetString(Data(digest))
        return encodeExtension(oid: ASN1OID.subjectKeyIdentifier, critical: false, value: value)
    }

    private static func encodeAuthorityKeyIdentifier(keyIdentifier: Data) -> Data {
        // AuthorityKeyIdentifier: keyIdentifier is [0] IMPLICIT OCTET STRING.
        let inner = ASN1.contextSpecific(tag: 0, constructed: false, content: keyIdentifier)
        let value = ASN1.sequence(inner)
        return encodeExtension(oid: ASN1OID.authorityKeyIdentifier, critical: false, value: value)
    }

    // MARK: - Algorithm Identifier

    /// ECDSA-with-SHA256, used in both `tbsCertificate.signature` and the outer `signatureAlgorithm`.
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
        tbs.append(ASN1.rawInteger(serial))
        tbs.append(algorithmECDSAWithSHA256)
        tbs.append(issuer)
        tbs.append(validity)
        tbs.append(subject)
        tbs.append(spki)
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
        try tbsParser.skipNext()                                    // issuer
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
            let oidContent = try ASN1Parser.contentOf(oid)
            if try extParser.peekTag() == 0x01 {  // skip optional critical BOOLEAN
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
        // RFC 5280 §4.1.2.2: serial must be a positive integer.
        var trimmed = serial
        while trimmed.count > 1 && trimmed.first == 0x00 {
            trimmed = trimmed.dropFirst()
        }
        // All-zero collapses to 0x00; substitute 1 (RFC 5280 forbids serial 0).
        if trimmed.isEmpty || (trimmed.count == 1 && trimmed.first == 0x00) {
            trimmed = Data([0x01])
        }
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

        // DER INTEGER sign correction: pad 0x00 to keep positives positive, 0xFF for negatives.
        if !negative, let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        } else if negative, let first = bytes.first, first & 0x80 == 0 {
            bytes.insert(0xFF, at: 0)
        }
        return emit(tag: 0x02, content: Data(bytes))
    }

    /// Wraps a raw big-endian INTEGER content blob; caller ensures sign-correctness.
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

    // CMS / PKCS#7 (RFC 5652) — used to wrap the .mobileconfig in a SignedData.
    /// id-data 1.2.840.113549.1.7.1
    static let data             = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
    /// id-signedData 1.2.840.113549.1.7.2
    static let signedData       = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
    /// id-sha256 2.16.840.1.101.3.4.2.1
    static let sha256           = Data([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
    /// id-contentType 1.2.840.113549.1.9.3
    static let attrContentType  = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03])
    /// id-messageDigest 1.2.840.113549.1.9.4
    static let attrMessageDigest = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04])
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
        // 0x80 alone is BER indefinite-length (invalid DER); cap length bytes at 4.
        guard count > 0, count <= 4, start + count < data.endIndex else {
            throw X509BuilderError.asn1ParseFailed("Length encoding invalid")
        }
        // Accumulate in UInt64 — a 4-byte length can overflow a 32-bit `Int`.
        var length: UInt64 = 0
        for i in 0..<count {
            length = (length << 8) | UInt64(data[start + 1 + i])
        }
        // Bound to remaining buffer; a huge length would overflow Int in readNextWithHeader.
        let remaining = data.endIndex - (start + 1 + count)
        guard length <= UInt64(Int.max), length <= UInt64(remaining) else {
            throw X509BuilderError.asn1ParseFailed(
                "Length \(length) exceeds remaining buffer \(remaining)"
            )
        }
        return (Int(length), 1 + count)
    }

    /// Returns the content bytes of a TLV blob (strips the tag and length header).
    static func contentOf(_ tlv: Data) throws -> Data {
        guard tlv.count >= 2 else {
            throw X509BuilderError.asn1ParseFailed("TLV too short")
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
