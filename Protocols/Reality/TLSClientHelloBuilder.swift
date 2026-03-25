//
//  TLSClientHelloBuilder.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import CryptoKit

struct TLSClientHelloBuilder {

    // MARK: - GREASE

    private static let greaseTable: [UInt16] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
    ]

    /// Returns a GREASE value deterministically selected by `seed`.
    private static func grease(_ seed: UInt8) -> UInt16 {
        greaseTable[Int(seed) % greaseTable.count]
    }

    private static func isGREASE(_ value: UInt16) -> Bool {
        (value & 0x0F0F) == 0x0A0A
    }

    // MARK: - Deterministic Pseudo-Random Derivation

    /// Derives deterministic pseudo-random bytes from the connection random + label.
    private static func derivePRBytes(from random: Data, label: String, length: Int) -> Data {
        var result = Data()
        var counter: UInt8 = 0
        while result.count < length {
            var input = random
            input.append(contentsOf: label.utf8)
            input.append(counter)
            let hash = SHA256.hash(data: input)
            result.append(contentsOf: hash)
            counter &+= 1
        }
        return Data(result.prefix(length))
    }

    // MARK: - Generic Extension Helpers

    @inline(__always)
    private static func appendU16(_ data: inout Data, _ value: UInt16) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }

    /// Wraps payload with a TLS extension header (type + length).
    private static func ext(_ type: UInt16, _ payload: Data) -> Data {
        var e = Data(capacity: 4 + payload.count)
        appendU16(&e, type)
        appendU16(&e, UInt16(payload.count))
        e.append(payload)
        return e
    }

    /// Empty extension (type + zero-length).
    private static func ext(_ type: UInt16) -> Data {
        ext(type, Data())
    }

    // MARK: - Individual Extension Builders

    /// 0x0000 — Server Name Indication (SNI).
    static func buildSNIExtension(serverName: String) -> Data {
        let nameBytes = Array(serverName.utf8)
        var payload = Data()
        let listLen = nameBytes.count + 3
        appendU16(&payload, UInt16(listLen))
        payload.append(0x00) // Host name type: DNS
        appendU16(&payload, UInt16(nameBytes.count))
        payload.append(contentsOf: nameBytes)
        return ext(0x0000, payload)
    }

    /// 0x0005 — OCSP status request.
    private static func statusRequestExt() -> Data {
        ext(0x0005, Data([0x01, 0x00, 0x00, 0x00, 0x00]))
    }

    /// 0x000A — Supported groups / named curves.
    private static func supportedGroupsExt(_ groups: [UInt16]) -> Data {
        var payload = Data()
        appendU16(&payload, UInt16(groups.count * 2))
        for g in groups { appendU16(&payload, g) }
        return ext(0x000A, payload)
    }

    /// 0x000B — EC point formats (uncompressed only).
    private static func ecPointFormatsExt() -> Data {
        ext(0x000B, Data([0x01, 0x00]))
    }

    /// 0x000D — Signature algorithms.
    private static func signatureAlgorithmsExt(_ algs: [UInt16]) -> Data {
        var payload = Data()
        appendU16(&payload, UInt16(algs.count * 2))
        for a in algs { appendU16(&payload, a) }
        return ext(0x000D, payload)
    }

    /// 0x0010 — ALPN.
    private static func alpnExt(_ protocols: [String]) -> Data {
        var list = Data()
        for proto in protocols {
            let bytes = Array(proto.utf8)
            list.append(UInt8(bytes.count))
            list.append(contentsOf: bytes)
        }
        var payload = Data()
        appendU16(&payload, UInt16(list.count))
        payload.append(list)
        return ext(0x0010, payload)
    }

    /// 0x0012 — Signed certificate timestamp (empty, requesting SCTs).
    private static func sctExt() -> Data { ext(0x0012) }

    /// 0x0015 — Padding extension.
    private static func paddingExt(_ length: Int) -> Data {
        ext(0x0015, Data(count: max(0, length)))
    }

    /// 0x0017 — Extended master secret.
    private static func extendedMasterSecretExt() -> Data { ext(0x0017) }

    /// 0x001B — Compress certificate (RFC 8879).
    private static func compressCertExt(_ algorithms: [UInt16]) -> Data {
        var payload = Data()
        payload.append(UInt8(algorithms.count * 2))
        for a in algorithms { appendU16(&payload, a) }
        return ext(0x001B, payload)
    }

    /// 0x001C — Record size limit.
    private static func recordSizeLimitExt(_ limit: UInt16) -> Data {
        var payload = Data()
        appendU16(&payload, limit)
        return ext(0x001C, payload)
    }

    /// 0x0022 — Delegated credentials.
    private static func delegatedCredentialsExt(_ algs: [UInt16]) -> Data {
        var payload = Data()
        appendU16(&payload, UInt16(algs.count * 2))
        for a in algs { appendU16(&payload, a) }
        return ext(0x0022, payload)
    }

    /// 0x0023 — Session ticket.
    private static func sessionTicketExt() -> Data { ext(0x0023) }

    /// 0x002B — Supported versions.
    private static func supportedVersionsExt(_ versions: [UInt16]) -> Data {
        var payload = Data()
        payload.append(UInt8(versions.count * 2))
        for v in versions { appendU16(&payload, v) }
        return ext(0x002B, payload)
    }

    /// 0x002D — PSK key exchange modes.
    private static func pskKeyExchangeModesExt() -> Data {
        ext(0x002D, Data([0x01, 0x01])) // 1 mode: psk_dhe_ke (0x01)
    }

    /// 0x0033 — Key share.
    private static func keyShareExt(_ entries: [(group: UInt16, keyData: Data)]) -> Data {
        var list = Data()
        for entry in entries {
            appendU16(&list, entry.group)
            appendU16(&list, UInt16(entry.keyData.count))
            list.append(entry.keyData)
        }
        var payload = Data()
        appendU16(&payload, UInt16(list.count))
        payload.append(list)
        return ext(0x0033, payload)
    }

    /// 0x3374 (13172) — Next Protocol Negotiation (legacy, for 360 Browser).
    private static func npnExt() -> Data { ext(0x3374) }

    /// 0x4469 (17513) — Application settings (ALPS, old codepoint).
    private static func applicationSettingsExt(_ protocols: [String]) -> Data {
        var list = Data()
        for proto in protocols {
            let bytes = Array(proto.utf8)
            list.append(UInt8(bytes.count))
            list.append(contentsOf: bytes)
        }
        var payload = Data()
        appendU16(&payload, UInt16(list.count))
        payload.append(list)
        return ext(0x4469, payload)
    }

    /// 0x44CD (17613) — Application settings (ALPS, new codepoint for Chrome 133+).
    private static func applicationSettingsNewExt(_ protocols: [String]) -> Data {
        var list = Data()
        for proto in protocols {
            let bytes = Array(proto.utf8)
            list.append(UInt8(bytes.count))
            list.append(contentsOf: bytes)
        }
        var payload = Data()
        appendU16(&payload, UInt16(list.count))
        payload.append(list)
        return ext(0x44CD, payload)
    }

    /// 0x754F (30031) — Fake Channel ID (old extension ID, for 360 Browser).
    private static func fakeChannelIDOldExt() -> Data { ext(0x754F) }

    /// 0xFE0D — GREASE Encrypted Client Hello.
    private static func greaseECHExt(random: Data, kdfId: UInt16, aeadId: UInt16, payloadLen: Int) -> Data {
        let enc = derivePRBytes(from: random, label: "ech-enc", length: 32)
        let payload = derivePRBytes(from: random, label: "ech-payload", length: payloadLen)
        let configId = derivePRBytes(from: random, label: "ech-config", length: 1)[0]

        var data = Data()
        data.append(0x00) // ClientHello type: outer
        appendU16(&data, kdfId)
        appendU16(&data, aeadId)
        data.append(configId)
        appendU16(&data, UInt16(enc.count))
        data.append(enc)
        appendU16(&data, UInt16(payload.count))
        data.append(payload)
        return ext(0xFE0D, data)
    }

    /// 0xFF01 — Renegotiation info (empty, initial handshake).
    private static func renegotiationInfoExt() -> Data {
        ext(0xFF01, Data([0x00]))
    }

    /// GREASE extension (random type, empty data).
    private static func greaseExt(_ value: UInt16) -> Data { ext(value) }

    // MARK: - Cipher Suite Serialization

    private static func cipherSuitesData(_ suites: [UInt16]) -> Data {
        var data = Data(capacity: suites.count * 2)
        for s in suites { appendU16(&data, s) }
        return data
    }

    // MARK: - BoringSSL Padding

    /// Calculates BoringSSL-style padding: if the full record (5 + ClientHello) is 256–511 bytes,
    /// pad to exactly 512. Returns the padding data length (excluding extension header).
    private static func boringPaddingDataLength(clientHelloLen: Int) -> Int? {
        let unpaddedLen = clientHelloLen
        guard unpaddedLen > 0xFF && unpaddedLen < 0x200 else { return nil }
        let needed = 0x200 - unpaddedLen
        return needed >= 4 ? (needed - 4) : nil
    }

    // MARK: - Chrome Extension Shuffling

    /// Shuffles extension data blocks deterministically for the Chrome fingerprint.
    /// GREASE extensions and padding are kept at their original positions.
    private static func shuffleChromeExtensions(_ exts: inout [Data], random: Data) {
        var fixed = Set<Int>()
        for i in 0..<exts.count {
            guard exts[i].count >= 2 else { continue }
            let type = UInt16(exts[i][0]) << 8 | UInt16(exts[i][1])
            if isGREASE(type) || type == 0x0015 {
                fixed.insert(i)
            }
        }

        let shuffleable = (0..<exts.count).filter { !fixed.contains($0) }
        guard shuffleable.count > 1 else { return }

        // Deterministic PRNG seeded from random bytes 24-31
        var seed: UInt64 = random.withUnsafeBytes { buf in
            guard buf.count >= 32 else { return 0 }
            return buf.load(fromByteOffset: 24, as: UInt64.self)
        }

        // Fisher-Yates shuffle on shuffleable indices
        for i in stride(from: shuffleable.count - 1, through: 1, by: -1) {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            let j = Int(seed >> 33) % (i + 1)
            if i != j {
                exts.swapAt(shuffleable[i], shuffleable[j])
            }
        }
    }

    // MARK: - P256 Key Derivation (Firefox)

    /// Derives a deterministic P256 public key from the connection random.
    private static func deriveP256PublicKey(from random: Data) -> Data {
        let seed = Data(SHA256.hash(data: random + Data("p256-fingerprint".utf8)))
        if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: seed) {
            return key.publicKey.x963Representation // 65 bytes (uncompressed)
        }
        return Data(count: 65)
    }

    // MARK: - X25519MLKEM768 Key Share Generation

    /// Generates a fake X25519MLKEM768 hybrid key share for fingerprinting.
    ///
    /// The key share data is 1216 bytes: 1184 bytes of random data (ML-KEM-768
    /// encapsulation key placeholder) + 32 bytes of the real X25519 public key.
    /// Servers that don't support ML-KEM will negotiate using the separate X25519
    /// key share entry, so the ML-KEM portion is never actually used.
    private static func mlkem768HybridKeyShare(random: Data, publicKey: Data) -> Data {
        let mlkemPart = derivePRBytes(from: random, label: "mlkem768", length: 1184)
        var hybrid = mlkemPart
        hybrid.append(publicKey)
        return hybrid // 1216 bytes total
    }

    // MARK: - BoringGREASEECH (Chrome style)

    /// Builds a GREASE ECH extension matching BoringSSL's default.
    /// KDF=HKDF-SHA256(0x0001), AEAD=AES-128-GCM(0x0001).
    /// Payload length picked from [128,160,192,224] + 16 AEAD overhead.
    private static func boringGREASEECH(random: Data) -> Data {
        let echPayloadLens = [144, 176, 208, 240]
        let echPayloadLen = echPayloadLens[Int(random[30]) % echPayloadLens.count]
        return greaseECHExt(random: random, kdfId: 0x0001, aeadId: 0x0001, payloadLen: echPayloadLen)
    }

    /// Builds a GREASE ECH extension matching Firefox's style.
    /// KDF=HKDF-SHA256, AEAD randomly chosen between AES-128-GCM and ChaCha20-Poly1305.
    /// Fixed payload length of 239.
    private static func firefoxGREASEECH(random: Data) -> Data {
        let echAead: UInt16 = (random[30] % 2 == 0) ? 0x0001 : 0x0003
        return greaseECHExt(random: random, kdfId: 0x0001, aeadId: echAead, payloadLen: 239)
    }

    // MARK: - Fingerprinted ClientHello Builder

    /// Build a TLS ClientHello with browser-specific fingerprint emulation.
    ///
    /// Each fingerprint produces a ClientHello matching the corresponding browser's
    /// real TLS implementation (cipher suites, extensions, ordering) as defined by
    /// the uTLS library.
    static func buildRawClientHello(
        fingerprint: TLSFingerprint,
        random: Data,
        sessionId: Data,
        serverName: String,
        publicKey: Data,
        alpn: [String]? = nil,
        omitPQKeyShares: Bool = false
    ) -> Data {
        let resolved: TLSFingerprint
        if fingerprint == .random {
            let options = TLSFingerprint.concreteFingerprints
            resolved = options[Int(random[0]) % options.count]
        } else {
            resolved = fingerprint
        }

        let (suites, extensions, padded) = buildFingerprintedParts(
            fingerprint: resolved,
            random: random,
            serverName: serverName,
            publicKey: publicKey,
            alpn: alpn,
            omitPQKeyShares: omitPQKeyShares
        )

        return assembleClientHello(
            random: random,
            sessionId: sessionId,
            cipherSuites: suites,
            extensions: extensions,
            applyBoringPadding: padded
        )
    }

    /// Assembles a complete ClientHello handshake message from pre-built parts.
    private static func assembleClientHello(
        random: Data,
        sessionId: Data,
        cipherSuites: Data,
        extensions: Data,
        applyBoringPadding: Bool
    ) -> Data {
        var ch = Data()
        ch.append(0x01) // Handshake type: ClientHello
        let lengthOffset = ch.count
        ch.append(contentsOf: [0x00, 0x00, 0x00]) // length placeholder
        ch.append(contentsOf: [0x03, 0x03]) // Legacy version: TLS 1.2
        ch.append(random)
        ch.append(UInt8(sessionId.count))
        ch.append(sessionId)
        appendU16(&ch, UInt16(cipherSuites.count))
        ch.append(cipherSuites)
        ch.append(0x01) // Compression methods length
        ch.append(0x00) // null compression

        var exts = extensions

        if applyBoringPadding {
            let unpaddedLen = ch.count + 2 + exts.count
            if let padLen = boringPaddingDataLength(clientHelloLen: unpaddedLen) {
                exts.append(paddingExt(padLen))
            }
        }

        appendU16(&ch, UInt16(exts.count))
        ch.append(exts)

        // Fill handshake length (excludes type byte and 3-byte length field)
        let length = ch.count - 4
        ch[lengthOffset] = UInt8((length >> 16) & 0xFF)
        ch[lengthOffset + 1] = UInt8((length >> 8) & 0xFF)
        ch[lengthOffset + 2] = UInt8(length & 0xFF)

        return ch
    }

    // MARK: - Per-Browser Fingerprint Dispatch

    private static func buildFingerprintedParts(
        fingerprint: TLSFingerprint,
        random: Data,
        serverName: String,
        publicKey: Data,
        alpn: [String]?,
        omitPQKeyShares: Bool = false
    ) -> (cipherSuites: Data, extensions: Data, needsPadding: Bool) {
        switch fingerprint {
        case .chrome133:  return buildChrome133(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn, omitPQKeyShares: omitPQKeyShares)
        case .chrome120:  return buildChrome120(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .firefox148: return buildFirefox148(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn, omitPQKeyShares: omitPQKeyShares)
        case .firefox120: return buildFirefox120(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .safari26:   return buildSafari26(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn, omitPQKeyShares: omitPQKeyShares)
        case .safari16:   return buildSafari16(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .ios14:      return buildIOS14(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .edge85:     return buildEdge85(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .edge106:    return buildEdge106(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .android11:  return buildAndroid11(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .qq11:       return buildQQ11(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .browser360: return build360_7(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .random: fatalError("random fingerprint must be resolved before dispatch")
        }
    }

    // MARK: - Chrome 133 (HelloChrome_Auto)

    private static func buildChrome133(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?, omitPQKeyShares: Bool = false
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02B, 0xC02F, 0xC02C, 0xC030,                 // ECDHE AES-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC013, 0xC014,                                   // ECDHE AES-CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let supportedGroups: [UInt16]
        var keyShares: [(group: UInt16, keyData: Data)] = [
            (group: gGroup, keyData: Data([0x00])),           // GREASE key share
        ]

        if omitPQKeyShares {
            supportedGroups = [gGroup, 0x001D, 0x0017, 0x0018]
        } else {
            let mlkemKey = mlkem768HybridKeyShare(random: random, publicKey: publicKey)
            supportedGroups = [gGroup, 0x11EC, 0x001D, 0x0017, 0x0018]
            keyShares.append((group: 0x11EC, keyData: mlkemKey))
        }
        keyShares.append((group: 0x001D, keyData: publicKey))

        var exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(supportedGroups),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,  // ECDSA-P256-SHA256, PSS-SHA256, PKCS1-SHA256
                0x0503, 0x0805, 0x0501,  // ECDSA-P384-SHA384, PSS-SHA384, PKCS1-SHA384
                0x0806, 0x0601           // PSS-SHA512, PKCS1-SHA512
            ]),
            sctExt(),
            keyShareExt(keyShares),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),                        // Brotli
            applicationSettingsNewExt(["h2"]),                // New ALPS codepoint
            boringGREASEECH(random: random),
            greaseExt(gExt2),
        ]

        // Chrome 106+ shuffles non-GREASE, non-padding extensions
        shuffleChromeExtensions(&exts, random: random)

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Chrome 120 (legacy)

    private static func buildChrome120(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030,
            0xCCA9, 0xCCA8,
            0xC013, 0xC014,
            0x009C, 0x009D,
            0x002F, 0x0035
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let echPayloadLens = [144, 176, 208, 240]
        let echPayloadLen = echPayloadLens[Int(random[30]) % echPayloadLens.count]

        var exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0501,
                0x0806, 0x0601
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),
            applicationSettingsExt(["h2"]),
            greaseECHExt(random: random, kdfId: 0x0001, aeadId: 0x0001, payloadLen: echPayloadLen),
            greaseExt(gExt2),
        ]

        shuffleChromeExtensions(&exts, random: random)

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Firefox 148 (HelloFirefox_Auto)

    private static func buildFirefox148(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?, omitPQKeyShares: Bool = false
    ) -> (Data, Data, Bool) {
        let suites = cipherSuitesData([
            0x1301, 0x1303, 0x1302,                           // TLS 1.3 (ChaCha20 before AES-256)
            0xC02B, 0xC02F,                                   // ECDHE AES-128-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC02C, 0xC030,                                   // ECDHE AES-256-GCM
            0xC00A, 0xC009,                                   // ECDHE ECDSA CBC
            0xC013, 0xC014,                                   // ECDHE RSA CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]
        let p256PublicKey = deriveP256PublicKey(from: random)

        let supportedGroups: [UInt16]
        var keyShares: [(group: UInt16, keyData: Data)] = []

        if omitPQKeyShares {
            supportedGroups = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
        } else {
            let mlkemKey = mlkem768HybridKeyShare(random: random, publicKey: publicKey)
            supportedGroups = [0x11EC, 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            keyShares.append((group: 0x11EC, keyData: mlkemKey))
        }
        keyShares.append((group: 0x001D, keyData: publicKey))
        keyShares.append((group: 0x0017, keyData: p256PublicKey))

        let exts: [Data] = [
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(supportedGroups),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            delegatedCredentialsExt([0x0403, 0x0503, 0x0603, 0x0203]),
            sctExt(),
            keyShareExt(keyShares),
            supportedVersionsExt([0x0304, 0x0303]),
            signatureAlgorithmsExt([
                0x0403, 0x0503, 0x0603,                       // ECDSA P256/P384/P521
                0x0804, 0x0805, 0x0806,                       // PSS SHA256/384/512
                0x0401, 0x0501, 0x0601,                       // PKCS1 SHA256/384/512
                0x0203, 0x0201                                // ECDSA-SHA1, PKCS1-SHA1
            ]),
            pskKeyExchangeModesExt(),
            recordSizeLimitExt(0x4001),
            compressCertExt([0x0001, 0x0002, 0x0003]),        // Zlib, Brotli, Zstd
            firefoxGREASEECH(random: random),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, false) // No BoringSSL padding
    }

    // MARK: - Firefox 120 (legacy)

    private static func buildFirefox120(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let suites = cipherSuitesData([
            0x1301, 0x1303, 0x1302,
            0xC02B, 0xC02F,
            0xCCA9, 0xCCA8,
            0xC02C, 0xC030,
            0xC00A, 0xC009,
            0xC013, 0xC014,
            0x009C, 0x009D,
            0x002F, 0x0035
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]
        let p256PublicKey = deriveP256PublicKey(from: random)
        let echAead: UInt16 = (random[30] % 2 == 0) ? 0x0001 : 0x0003

        let exts: [Data] = [
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([
                0x001D, 0x0017, 0x0018, 0x0019,
                0x0100, 0x0101
            ]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            delegatedCredentialsExt([0x0403, 0x0503, 0x0603, 0x0203]),
            keyShareExt([
                (group: 0x001D, keyData: publicKey),
                (group: 0x0017, keyData: p256PublicKey)
            ]),
            supportedVersionsExt([0x0304, 0x0303]),
            signatureAlgorithmsExt([
                0x0403, 0x0503, 0x0603,
                0x0804, 0x0805, 0x0806,
                0x0401, 0x0501, 0x0601,
                0x0203, 0x0201
            ]),
            pskKeyExchangeModesExt(),
            recordSizeLimitExt(0x4001),
            greaseECHExt(random: random, kdfId: 0x0001, aeadId: echAead, payloadLen: 239),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, false)
    }

    // MARK: - Safari 26.3 (HelloSafari_Auto)

    private static func buildSafari26(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?, omitPQKeyShares: Bool = false
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1302, 0x1303, 0x1301,                         // TLS 1.3 (AES-256 first)
            0xC02C, 0xC02B, 0xCCA9,                         // ECDHE ECDSA
            0xC030, 0xC02F, 0xCCA8,                         // ECDHE RSA
            0xC00A, 0xC009,                                   // ECDHE ECDSA CBC
            0xC014, 0xC013,                                   // ECDHE RSA CBC
            0x009D, 0x009C,                                   // RSA GCM
            0x0035, 0x002F,                                   // RSA CBC
            0xC008, 0xC012, 0x000A                           // 3DES (legacy)
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let supportedGroups: [UInt16]
        var keyShares: [(group: UInt16, keyData: Data)] = [
            (group: gGroup, keyData: Data([0x00])),           // GREASE key share
        ]

        if omitPQKeyShares {
            supportedGroups = [gGroup, 0x001D, 0x0017, 0x0018, 0x0019]
        } else {
            let mlkemKey = mlkem768HybridKeyShare(random: random, publicKey: publicKey)
            supportedGroups = [gGroup, 0x11EC, 0x001D, 0x0017, 0x0018, 0x0019]
            keyShares.append((group: 0x11EC, keyData: mlkemKey))
        }
        keyShares.append((group: 0x001D, keyData: publicKey))

        let exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(supportedGroups),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0805,                       // Intentional duplicate (real Safari)
                0x0501,
                0x0806, 0x0601,
                0x0201
            ]),
            sctExt(),
            keyShareExt(keyShares),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0001]),                        // Zlib
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Safari 16.0 (legacy)

    private static func buildSafari16(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,
            0xC02C, 0xC02B, 0xCCA9,
            0xC030, 0xC02F, 0xCCA8,
            0xC00A, 0xC009,
            0xC014, 0xC013,
            0x009D, 0x009C,
            0x0035, 0x002F,
            0xC008, 0xC012, 0x000A
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018, 0x0019]),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0203,
                0x0805, 0x0805,
                0x0501,
                0x0806, 0x0601,
                0x0201
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0001]),
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - iOS 14 (HelloIOS_Auto)

    private static func buildIOS14(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,                         // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,                         // ECDHE RSA (GCM, ChaCha)
            0xC024, 0xC023, 0xC00A, 0xC009,                 // ECDHE ECDSA CBC
            0xC028, 0xC027, 0xC014, 0xC013,                 // ECDHE RSA CBC
            0x009D, 0x009C,                                   // RSA GCM
            0x003D, 0x003C,                                   // RSA CBC SHA256
            0x0035, 0x002F,                                   // RSA CBC SHA
            0xC008, 0xC012, 0x000A                           // 3DES (legacy)
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018, 0x0019]),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0203,
                0x0805, 0x0805,                               // Intentional duplicate (real iOS)
                0x0501,
                0x0806, 0x0601,
                0x0201
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Edge 85 (HelloEdge_Auto)

    private static func buildEdge85(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02B, 0xC02F, 0xC02C, 0xC030,                 // ECDHE AES-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC013, 0xC014,                                   // ECDHE AES-CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0501,
                0x0806, 0x0601
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0002]),                        // Brotli
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Edge 106 (legacy)

    private static func buildEdge106(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030,
            0xCCA9, 0xCCA8,
            0xC013, 0xC014,
            0x009C, 0x009D,
            0x002F, 0x0035
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0501,
                0x0806, 0x0601
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),
            applicationSettingsExt(["h2"]),
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Android 11 OkHttp

    private static func buildAndroid11(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        // Android 11 OkHttp: no GREASE, no TLS 1.3, minimal extensions
        let suites = cipherSuitesData([
            0xC02B, 0xC02C,                                   // ECDHE ECDSA AES-GCM
            0xCCA9,                                            // ECDHE ECDSA ChaCha20
            0xC02F, 0xC030,                                   // ECDHE RSA AES-GCM
            0xCCA8,                                            // ECDHE RSA ChaCha20
            0xC013, 0xC014,                                   // ECDHE RSA CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ])

        let exts: [Data] = [
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([0x001D, 0x0017, 0x0018]),    // X25519, P256, P384
            ecPointFormatsExt(),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0501,
                0x0806, 0x0601,
                0x0201                                        // PKCS1-SHA1
            ]),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, false) // No padding
    }

    // MARK: - QQ Browser 11.1 (HelloQQ_Auto)

    private static func buildQQ11(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if gExt2 == gExt1 { gExt2 = grease(random[29] &+ 1) }

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02B, 0xC02F, 0xC02C, 0xC030,                 // ECDHE AES-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC013, 0xC014,                                   // ECDHE AES-CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0501,
                0x0806, 0x0601
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0002]),                        // Brotli
            applicationSettingsExt(["h2"]),                   // Old ALPS codepoint
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - 360 Browser 7.5 (Hello360_Auto)

    private static func build360_7(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        // 360 Browser 7.5: legacy TLS 1.0-1.2 only, no GREASE, no TLS 1.3
        let suites = cipherSuitesData([
            0xC00A,                                            // ECDHE_ECDSA_AES_256_CBC_SHA
            0xC014,                                            // ECDHE_RSA_AES_256_CBC_SHA
            0x0039,                                            // DHE_RSA_AES_256_CBC_SHA
            0x006B,                                            // DHE_RSA_AES_256_CBC_SHA256
            0x0035,                                            // RSA_AES_256_CBC_SHA
            0x003D,                                            // RSA_AES_256_CBC_SHA256
            0xC007,                                            // ECDHE_ECDSA_RC4_128_SHA
            0xC009,                                            // ECDHE_ECDSA_AES_128_CBC_SHA
            0xC023,                                            // ECDHE_ECDSA_AES_128_CBC_SHA256
            0xC011,                                            // ECDHE_RSA_RC4_128_SHA
            0xC013,                                            // ECDHE_RSA_AES_128_CBC_SHA
            0xC027,                                            // ECDHE_RSA_AES_128_CBC_SHA256
            0x0033,                                            // DHE_RSA_AES_128_CBC_SHA
            0x0067,                                            // DHE_RSA_AES_128_CBC_SHA256
            0x0032,                                            // DHE_DSS_AES_128_CBC_SHA
            0x0005,                                            // RSA_RC4_128_SHA
            0x0004,                                            // RSA_RC4_128_MD5
            0x002F,                                            // RSA_AES_128_CBC_SHA
            0x003C,                                            // RSA_AES_128_CBC_SHA256
            0x000A                                             // RSA_3DES_EDE_CBC_SHA
        ])

        let protocols = alpn ?? ["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"]

        let exts: [Data] = [
            buildSNIExtension(serverName: serverName),
            renegotiationInfoExt(),
            supportedGroupsExt([0x0017, 0x0018, 0x0019]),    // P256, P384, P521
            ecPointFormatsExt(),
            sessionTicketExt(),
            npnExt(),                                          // Next Protocol Negotiation (legacy)
            alpnExt(protocols),
            fakeChannelIDOldExt(),                             // Channel ID (old extension ID)
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0401, 0x0501, 0x0201,                       // PKCS1 SHA256/384/SHA1
                0x0403, 0x0503,                                // ECDSA P256/P384
                0x0203,                                        // ECDSA SHA1
                0x0402, 0x0202                                // SHA256WithDSA, SHA1WithDSA
            ]),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, false) // No padding
    }

    /// Wrap a ClientHello message in a TLS record.
    static func wrapInTLSRecord(clientHello: Data) -> Data {
        var record = Data()
        record.append(0x16) // Content type: Handshake
        record.append(0x03)
        record.append(0x01) // TLS 1.0 for compatibility
        appendU16(&record, UInt16(clientHello.count))
        record.append(clientHello)
        return record
    }
}
