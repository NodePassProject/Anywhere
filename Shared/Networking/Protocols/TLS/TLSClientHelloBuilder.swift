//
//  TLSClientHelloBuilder.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import CryptoKit

struct TLSClientHelloBuilder {

    // MARK: - GREASE

    private static let greaseTable: [UInt16] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
    ]

    private static func grease(_ seed: UInt8) -> UInt16 {
        greaseTable[Int(seed) % greaseTable.count]
    }

    private static func isGREASE(_ value: UInt16) -> Bool {
        (value & 0x0F0F) == 0x0A0A
    }

    // MARK: - Deterministic Pseudo-Random Derivation

    private static func derivePseudoRandomBytes(from random: Data, label: String, length: Int) -> Data {
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

    private static func ext(_ type: UInt16, _ payload: Data) -> Data {
        var e = Data(capacity: 4 + payload.count)
        appendU16(&e, type)
        appendU16(&e, UInt16(payload.count))
        e.append(payload)
        return e
    }

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
        payload.append(0x00)
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
        for proto in protocols where !proto.isEmpty {
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
        ext(0x002D, Data([0x01, 0x01]))
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

    /// 0x3374 (13172) — Next Protocol Negotiation (legacy).
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

    /// 0x754F (30031) — Fake Channel ID (old extension ID).
    private static func fakeChannelIDOldExt() -> Data { ext(0x754F) }

    /// 0xFE0D — GREASE Encrypted Client Hello.
    private static func greaseECHExt(random: Data, kdfId: UInt16, aeadId: UInt16, payloadLen: Int) -> Data {
        let enc = derivePseudoRandomBytes(from: random, label: "ech-enc", length: 32)
        let payload = derivePseudoRandomBytes(from: random, label: "ech-payload", length: payloadLen)
        let configId = derivePseudoRandomBytes(from: random, label: "ech-config", length: 1)[0]

        var data = Data()
        data.append(0x00)
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

    private static func boringPaddingDataLength(clientHelloLen: Int) -> Int? {
        let unpaddedLen = clientHelloLen
        guard unpaddedLen > 0xFF && unpaddedLen < 0x200 else { return nil }
        let needed = 0x200 - unpaddedLen
        return needed >= 4 ? (needed - 4) : nil
    }

    // MARK: - Chrome Extension Shuffling

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

        var seed: UInt64 = random.withUnsafeBytes { buffer in
            guard buffer.count >= 32 else { return 0 }
            return buffer.load(fromByteOffset: 24, as: UInt64.self)
        }

        for i in stride(from: shuffleable.count - 1, through: 1, by: -1) {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            let j = Int(seed >> 33) % (i + 1)
            if i != j {
                exts.swapAt(shuffleable[i], shuffleable[j])
            }
        }
    }

    // MARK: - P256 Key Derivation (Firefox)

    private static func deriveP256PublicKey(from random: Data) -> Data {
        let seed = Data(SHA256.hash(data: random + Data("p256-fingerprint".utf8)))
        if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: seed) {
            return key.publicKey.x963Representation
        }
        return Data(count: 65)
    }

    // MARK: - X25519MLKEM768 Key Share Generation

    private static func mlkem768HybridKeyShare(mlkemEncapsulationKey: Data, publicKey: Data) -> Data {
        var hybrid = mlkemEncapsulationKey
        hybrid.append(publicKey)
        return hybrid
    }

    // MARK: - BoringGREASEECH (Chrome style)

    private static func boringGREASEECH(random: Data) -> Data {
        let echPayloadLens = [144, 176, 208, 240]
        let echPayloadLen = echPayloadLens[Int(random[30]) % echPayloadLens.count]
        return greaseECHExt(random: random, kdfId: 0x0001, aeadId: 0x0001, payloadLen: echPayloadLen)
    }

    private static func firefoxGREASEECH(random: Data) -> Data {
        let echAead: UInt16 = (random[30] % 2 == 0) ? 0x0001 : 0x0003
        return greaseECHExt(random: random, kdfId: 0x0001, aeadId: echAead, payloadLen: 239)
    }

    // MARK: - Fingerprinted ClientHello Builder

    static func buildRawClientHello(
        fingerprint: TLSFingerprint,
        random: Data,
        sessionId: Data,
        serverName: String,
        publicKey: Data,
        alpn: [String]? = nil,
        omitPQKeyShares: Bool = false,
        mlkemEncapsulationKey: Data? = nil
    ) -> Data {
        let (suites, extensions, padded) = buildFingerprintedParts(
            fingerprint: fingerprint,
            random: random,
            serverName: serverName,
            publicKey: publicKey,
            alpn: alpn,
            omitPQKeyShares: omitPQKeyShares,
            mlkemEncapsulationKey: mlkemEncapsulationKey
        )

        return assembleClientHello(
            random: random,
            sessionId: sessionId,
            cipherSuites: suites,
            extensions: extensions,
            applyBoringPadding: padded
        )
    }

    private static func assembleClientHello(
        random: Data,
        sessionId: Data,
        cipherSuites: Data,
        extensions: Data,
        applyBoringPadding: Bool
    ) -> Data {
        var ch = Data()
        ch.append(TLSHandshakeType.clientHello)
        let lengthOffset = ch.count
        ch.append(contentsOf: [0x00, 0x00, 0x00])
        ch.append(contentsOf: [0x03, 0x03])
        ch.append(random)
        ch.append(UInt8(sessionId.count))
        ch.append(sessionId)
        appendU16(&ch, UInt16(cipherSuites.count))
        ch.append(cipherSuites)
        ch.append(0x01)
        ch.append(0x00)

        var exts = extensions

        if applyBoringPadding {
            let unpaddedLen = ch.count + 2 + exts.count
            if let padLen = boringPaddingDataLength(clientHelloLen: unpaddedLen) {
                exts.append(paddingExt(padLen))
            }
        }

        appendU16(&ch, UInt16(exts.count))
        ch.append(exts)

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
        omitPQKeyShares: Bool = false,
        mlkemEncapsulationKey: Data? = nil
    ) -> (cipherSuites: Data, extensions: Data, needsPadding: Bool) {
        switch fingerprint {
        case .nonBrowser: return buildNonBrowser(serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .chrome133:  return buildChrome133(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn, omitPQKeyShares: omitPQKeyShares, mlkemEncapsulationKey: mlkemEncapsulationKey)
        case .chrome120:  return buildChrome120(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .chrome106:  return buildChrome106(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .firefox148: return buildFirefox148(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn, omitPQKeyShares: omitPQKeyShares, mlkemEncapsulationKey: mlkemEncapsulationKey)
        case .firefox120: return buildFirefox120(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .safari26:   return buildSafari26(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn, omitPQKeyShares: omitPQKeyShares, mlkemEncapsulationKey: mlkemEncapsulationKey)
        case .edge106:    return buildEdge106(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        }
    }

    // MARK: - Non-Browser (minimal, honest client)

    private static func buildNonBrowser(
        serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let suites = cipherSuitesData([
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02B, 0xC02F, 0xC02C, 0xC030,                 // ECDHE AES-GCM
            0xCCA9, 0xCCA8,                                 // ECDHE ChaCha20
            0xC013, 0xC014,                                 // ECDHE AES-CBC
            0x009C, 0x009D,                                 // RSA AES-GCM
            0x002F, 0x0035                                  // RSA AES-CBC
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        let exts: [Data] = [
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([0x001D, 0x0017, 0x0018]),   // X25519, secp256r1, secp384r1
            ecPointFormatsExt(),
            alpnExt(protocols),
            signatureAlgorithmsExt([
                0x0403, 0x0804, 0x0401,  // ECDSA-P256-SHA256, PSS-SHA256, PKCS1-SHA256
                0x0503, 0x0805, 0x0501,  // ECDSA-P384-SHA384, PSS-SHA384, PKCS1-SHA384
                0x0806, 0x0601           // PSS-SHA512, PKCS1-SHA512
            ]),
            keyShareExt([(group: 0x001D, keyData: publicKey)]),   // X25519 only
            pskKeyExchangeModesExt(),
            supportedVersionsExt([0x0304, 0x0303]),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, false)   // no BoringSSL padding
    }

    // MARK: - Chrome 133 (HelloChrome_Auto)

    private static func buildChrome133(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?, omitPQKeyShares: Bool = false, mlkemEncapsulationKey: Data? = nil
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

        if !omitPQKeyShares, let encapsulationKey = mlkemEncapsulationKey {
            let hybrid = mlkem768HybridKeyShare(mlkemEncapsulationKey: encapsulationKey, publicKey: publicKey)
            supportedGroups = [gGroup, 0x11EC, 0x001D, 0x0017, 0x0018]
            keyShares.append((group: 0x11EC, keyData: hybrid))
        } else {
            supportedGroups = [gGroup, 0x001D, 0x0017, 0x0018]
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
            applicationSettingsNewExt(["h2"]),
            boringGREASEECH(random: random),
            greaseExt(gExt2),
        ]

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

    // MARK: - Chrome 106 (HelloChrome_106_Shuffle — Chrome 120 without ECH)

    private static func buildChrome106(
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
            compressCertExt([0x0002]),                        // Brotli
            applicationSettingsExt(["h2"]),
            greaseExt(gExt2),
        ]

        shuffleChromeExtensions(&exts, random: random)

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Firefox 148 (HelloFirefox_Auto)

    private static func buildFirefox148(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?, omitPQKeyShares: Bool = false, mlkemEncapsulationKey: Data? = nil
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

        if !omitPQKeyShares, let encapsulationKey = mlkemEncapsulationKey {
            let hybrid = mlkem768HybridKeyShare(mlkemEncapsulationKey: encapsulationKey, publicKey: publicKey)
            supportedGroups = [0x11EC, 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            keyShares.append((group: 0x11EC, keyData: hybrid))
        } else {
            supportedGroups = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
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
        random: Data, serverName: String, publicKey: Data, alpn: [String]?, omitPQKeyShares: Bool = false, mlkemEncapsulationKey: Data? = nil
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

        if !omitPQKeyShares, let encapsulationKey = mlkemEncapsulationKey {
            let hybrid = mlkem768HybridKeyShare(mlkemEncapsulationKey: encapsulationKey, publicKey: publicKey)
            supportedGroups = [gGroup, 0x11EC, 0x001D, 0x0017, 0x0018, 0x0019]
            keyShares.append((group: 0x11EC, keyData: hybrid))
        } else {
            supportedGroups = [gGroup, 0x001D, 0x0017, 0x0018, 0x0019]
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
            applicationSettingsExt(["h2"]),
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
            npnExt(),
            alpnExt(protocols),
            fakeChannelIDOldExt(),
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

    // MARK: - Encrypted Client Hello (real ECH)

    private static let echSignatureAlgorithms: [UInt16] = [
        0x0403, 0x0804, 0x0401,  // ECDSA-P256-SHA256, PSS-SHA256, PKCS1-SHA256
        0x0503, 0x0805, 0x0501,  // ECDSA-P384-SHA384, PSS-SHA384, PKCS1-SHA384
        0x0806, 0x0601,          // PSS-SHA512, PKCS1-SHA512
    ]

    /// TLS 1.3-only inner hello carrying the real SNI and the ECH inner marker
    /// (extension 0xFE0D = [0x01]). TLS 1.2-only extensions (ec_point_formats,
    /// session_ticket, renegotiation_info, extended_master_secret) are omitted.
    /// `sessionId` is empty for the encoded (encrypted) form, the outer's
    /// session_id for the transcript form.
    private static func buildECHInnerHello(
        random: Data, sessionId: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> Data {
        let suites = cipherSuitesData([0x1301, 0x1302, 0x1303])
        let protocols = alpn ?? ["h2", "http/1.1"]

        var exts = Data()
        exts.append(buildSNIExtension(serverName: serverName))
        exts.append(supportedGroupsExt([0x001D, 0x0017, 0x0018]))   // X25519, secp256r1, secp384r1
        exts.append(signatureAlgorithmsExt(echSignatureAlgorithms))
        exts.append(alpnExt(protocols))
        exts.append(keyShareExt([(group: 0x001D, keyData: publicKey)]))   // X25519 (shared with outer)
        exts.append(pskKeyExchangeModesExt())
        exts.append(supportedVersionsExt([0x0304]))                  // TLS 1.3 only
        exts.append(ext(0xFE0D, Data([0x01])))                       // encrypted_client_hello: inner

        return assembleClientHello(
            random: random,
            sessionId: sessionId,
            cipherSuites: suites,
            extensions: exts,
            applyBoringPadding: false
        )
    }

    /// Chrome-120-style camouflage outer hello: cover `publicName` as SNI plus a
    /// real outer encrypted_client_hello carrying the sealed inner. Its X25519
    /// key share matches the inner's, so the ECDHE result is identical whether or
    /// not the server accepts ECH.
    private static func buildECHOuterHello(
        random: Data, sessionId: Data, publicName: String, publicKey: Data, alpn: [String]?, echExtData: Data
    ) -> Data {
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
            0x002F, 0x0035,
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        var exts: [Data] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName: publicName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(echSignatureAlgorithms),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),
                (group: 0x001D, keyData: publicKey),
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),
            applicationSettingsExt(["h2"]),
            ext(0xFE0D, echExtData),                                 // encrypted_client_hello: outer
            greaseExt(gExt2),
        ]

        shuffleChromeExtensions(&exts, random: random)

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return assembleClientHello(
            random: random,
            sessionId: sessionId,
            cipherSuites: suites,
            extensions: extensionsData,
            applyBoringPadding: true
        )
    }

    /// Assemble the ECH ClientHelloOuter and matching inner state, performing the
    /// HPKE seal. Returns the outer wire message and an `ECHClientContext` with
    /// the inner transcript material needed to detect acceptance.
    ///
    /// Two-pass to resolve the seal's AAD chicken-and-egg: the AAD is the
    /// serialized outer with a zero-filled payload of the eventual ciphertext
    /// length, so we build the outer with zeros, seal against it, then rebuild
    /// with the real ciphertext (same length → identical layout, which the
    /// server zeroes and re-derives).
    static func buildECHClientHello(
        outerRandom: Data,
        innerRandom: Data,
        sessionId: Data,
        innerServerName: String,
        publicKey: Data,
        alpn: [String]?,
        config: ECHConfig,
        cipherSuite: ECHCipherSuite
    ) throws -> (outerMessage: Data, context: ECHClientContext) {
        let context = try ECHClientContext(config: config, cipherSuite: cipherSuite)

        // Encoded inner: empty session_id, then header-stripped and padded.
        let innerEncodedMessage = buildECHInnerHello(
            random: innerRandom, sessionId: Data(), serverName: innerServerName, publicKey: publicKey, alpn: alpn
        )
        let encodedInner = try ECHEncryption.encodeInnerClientHello(
            innerEncodedMessage, serverName: innerServerName, maxNameLength: Int(config.maxNameLength)
        )
        let ciphertextLength = encodedInner.count + ECHEncryption.aeadTagLength

        // Pass 1 — outer with a zero-filled payload, used as the seal's AAD.
        let zeroExtData = ECHEncryption.outerExtensionData(
            configID: config.configID, kdfID: cipherSuite.kdfID, aeadID: cipherSuite.aeadID,
            enc: context.encapsulatedKey, payload: Data(count: ciphertextLength)
        )
        let outerForAAD = buildECHOuterHello(
            random: outerRandom, sessionId: sessionId, publicName: config.publicName,
            publicKey: publicKey, alpn: alpn, echExtData: zeroExtData
        )
        let aad = Data(outerForAAD.dropFirst(4))   // strip the 4-byte handshake header
        let ciphertext = try context.seal(plaintext: encodedInner, aad: aad)

        // Pass 2 — outer with the real ciphertext (identical length → identical layout).
        let realExtData = ECHEncryption.outerExtensionData(
            configID: config.configID, kdfID: cipherSuite.kdfID, aeadID: cipherSuite.aeadID,
            enc: context.encapsulatedKey, payload: ciphertext
        )
        let outerMessage = buildECHOuterHello(
            random: outerRandom, sessionId: sessionId, publicName: config.publicName,
            publicKey: publicKey, alpn: alpn, echExtData: realExtData
        )

        // Transcript inner: identical to the encoded inner but with the outer's
        // session_id, matching what the server reconstructs and feeds its keys.
        context.innerTranscriptMessage = buildECHInnerHello(
            random: innerRandom, sessionId: sessionId, serverName: innerServerName, publicKey: publicKey, alpn: alpn
        )
        context.innerRandom = innerRandom

        return (outerMessage, context)
    }

    // MARK: - QUIC ClientHello

    static let quicSignatureAlgorithms: [UInt16] = [
        TLSSignatureScheme.ecdsa_secp256r1_sha256,
        TLSSignatureScheme.rsa_pss_rsae_sha256,
        TLSSignatureScheme.rsa_pkcs1_sha256,
        TLSSignatureScheme.ecdsa_secp384r1_sha384,
        TLSSignatureScheme.rsa_pss_rsae_sha384,
        TLSSignatureScheme.rsa_pkcs1_sha384,
        TLSSignatureScheme.rsa_pss_rsae_sha512,
        TLSSignatureScheme.rsa_pkcs1_sha512,
        TLSSignatureScheme.ecdsa_sha1,
        TLSSignatureScheme.rsa_pkcs1_sha1,
    ]

    static func buildQUICClientHello(
        random: Data,
        serverName: String,
        alpn: [String],
        keyShares: [(group: UInt16, keyData: Data)],
        quicTransportParams: Data,
        pskExtension: Data? = nil
    ) -> Data {
        let suites = cipherSuitesData([
            TLSCipherSuite.TLS_AES_128_GCM_SHA256,
            TLSCipherSuite.TLS_AES_256_GCM_SHA384,
            TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ])

        var extsData = Data()
        extsData.append(buildSNIExtension(serverName: serverName))
        extsData.append(supportedGroupsExt([TLSNamedGroup.x25519, TLSNamedGroup.secp256]))
        extsData.append(signatureAlgorithmsExt(quicSignatureAlgorithms))
        extsData.append(alpnExt(alpn))
        extsData.append(supportedVersionsExt([0x0304]))
        extsData.append(pskKeyExchangeModesExt())
        extsData.append(keyShareExt(keyShares))
        extsData.append(ext(TLSExtensionType.quicTransportParameters, quicTransportParams))

        if let pskExtension {
            extsData.append(pskExtension)
        }

        return assembleClientHello(
            random: random,
            sessionId: Data(),
            cipherSuites: suites,
            extensions: extsData,
            applyBoringPadding: false
        )
    }

    static func wrapInTLSRecord(clientHello: Data) -> Data {
        var record = Data()
        record.append(TLSContentType.handshake)
        record.append(0x03)
        record.append(0x01)
        appendU16(&record, UInt16(clientHello.count))
        record.append(clientHello)
        return record
    }

    static func clampSupportedVersionsToTLS12(_ clientHello: Data) -> Data {
        let bytes = [UInt8](clientHello)
        guard bytes.count >= 4, bytes[0] == 0x01 else { return clientHello }

        var position = 4 + 2 + 32                                          // hs header + legacy_version + random
        guard position < bytes.count else { return clientHello }
        let sidLen = Int(bytes[position]); position += 1 + sidLen
        guard position + 2 <= bytes.count else { return clientHello }
        let csLen = (Int(bytes[position]) << 8) | Int(bytes[position + 1])
        position += 2 + csLen
        guard position < bytes.count else { return clientHello }
        let cmLen = Int(bytes[position]); position += 1 + cmLen
        guard position + 2 <= bytes.count else { return clientHello }
        let extsLenOffset = position
        let extsLen = (Int(bytes[position]) << 8) | Int(bytes[position + 1]); position += 2
        let extsStart = position
        let extsEnd = position + extsLen
        guard extsEnd <= bytes.count else { return clientHello }

        var current = extsStart
        while current + 4 <= extsEnd {
            let extType = (UInt16(bytes[current]) << 8) | UInt16(bytes[current + 1])
            let extDataLen = (Int(bytes[current + 2]) << 8) | Int(bytes[current + 3])
            let dataStart = current + 4
            let dataEnd = dataStart + extDataLen
            guard dataEnd <= extsEnd else { return clientHello }

            if extType == TLSExtensionType.supportedVersions {
                guard extDataLen >= 1 else { return clientHello }
                let listLen = Int(bytes[dataStart])
                guard dataStart + 1 + listLen == dataEnd, listLen % 2 == 0 else {
                    return clientHello
                }

                var versions: [UInt16] = []
                var v = dataStart + 1
                while v + 2 <= dataEnd {
                    versions.append((UInt16(bytes[v]) << 8) | UInt16(bytes[v + 1]))
                    v += 2
                }

                let filtered = versions.filter { $0 != 0x0304 && !isGREASE($0) }
                guard !filtered.isEmpty else { return clientHello }

                var newPayload = Data()
                newPayload.append(UInt8(filtered.count * 2))
                for value in filtered {
                    newPayload.append(UInt8((value >> 8) & 0xFF))
                    newPayload.append(UInt8(value & 0xFF))
                }

                var result = Data()
                result.append(Data(bytes[0..<(current + 2)]))
                result.append(UInt8((newPayload.count >> 8) & 0xFF))
                result.append(UInt8(newPayload.count & 0xFF))
                result.append(newPayload)
                result.append(Data(bytes[dataEnd..<bytes.count]))

                let sizeDelta = newPayload.count - extDataLen
                let newExtsLen = extsLen + sizeDelta
                result[extsLenOffset] = UInt8((newExtsLen >> 8) & 0xFF)
                result[extsLenOffset + 1] = UInt8(newExtsLen & 0xFF)

                let origHsLen = (Int(bytes[1]) << 16) | (Int(bytes[2]) << 8) | Int(bytes[3])
                let newHsLen = origHsLen + sizeDelta
                result[1] = UInt8((newHsLen >> 16) & 0xFF)
                result[2] = UInt8((newHsLen >> 8) & 0xFF)
                result[3] = UInt8(newHsLen & 0xFF)

                return result
            }

            current = dataEnd
        }

        return clientHello
    }
}
