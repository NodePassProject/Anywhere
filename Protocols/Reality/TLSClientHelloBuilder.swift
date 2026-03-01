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
    /// Used for ECH GREASE enc/payload and P256 key derivation.
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

    /// Appends a UInt16 in big-endian to a Data buffer.
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
        // Server name list length
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

    /// 0x0022 — Delegated credentials (Firefox).
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

    /// 0x4469 (17513) — Application settings (ALPS).
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

    /// 0xFE0D — GREASE Encrypted Client Hello.
    ///
    /// Wire format: type(1) + kdf(2) + aead(2) + configId(1) + encLen(2) + enc + payloadLen(2) + payload
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
        let unpaddedLen = clientHelloLen // handshake type(1) + length(3) + body
        guard unpaddedLen > 0xFF && unpaddedLen < 0x200 else { return nil }
        let needed = 0x200 - unpaddedLen
        return needed >= 5 ? (needed - 4) : 1
    }

    // MARK: - Chrome Extension Shuffling

    /// Shuffles extension data blocks deterministically for the Chrome fingerprint.
    /// GREASE extensions and padding are kept at their original positions.
    private static func shuffleChromeExtensions(_ exts: inout [Data], random: Data) {
        // Identify fixed-position extensions (GREASE type or padding type 0x0015)
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
    /// Used only for Firefox fingerprint (which offers both X25519 and P256 key shares).
    private static func deriveP256PublicKey(from random: Data) -> Data {
        let seed = Data(SHA256.hash(data: random + Data("p256-fingerprint".utf8)))
        if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: seed) {
            return key.publicKey.x963Representation // 65 bytes (uncompressed)
        }
        // Astronomically unlikely fallback (~2^-128 probability)
        return Data(count: 65)
    }

    // MARK: - Fingerprinted ClientHello Builder

    /// Build a TLS ClientHello with browser-specific fingerprint emulation.
    ///
    /// Each fingerprint produces a ClientHello matching the corresponding browser's
    /// real TLS implementation (cipher suites, extensions, ordering) as defined by
    /// the uTLS library v1.8.2 used by Xray-core.
    ///
    /// - Parameters:
    ///   - fingerprint: Which browser to emulate.
    ///   - random: 32-byte TLS random (also seeds deterministic GREASE and shuffle).
    ///   - sessionId: 32-byte session ID (zero for AAD, encrypted for final).
    ///   - serverName: SNI hostname.
    ///   - publicKey: X25519 ephemeral public key for the key_share extension.
    ///   - alpn: Optional ALPN override. When nil, uses browser default (["h2", "http/1.1"]).
    static func buildRawClientHello(
        fingerprint: TLSFingerprint,
        random: Data,
        sessionId: Data,
        serverName: String,
        publicKey: Data,
        alpn: [String]? = nil
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
            alpn: alpn
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
            // BoringSSL pads if the total handshake message is 256–511 bytes to reach 512.
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
        alpn: [String]?
    ) -> (cipherSuites: Data, extensions: Data, needsPadding: Bool) {
        switch fingerprint {
        case .chrome120: return buildChrome120(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .firefox120: return buildFirefox120(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .safari16: return buildSafari16(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .ios14: return buildIOS14(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .edge106: return buildEdge106(random: random, serverName: serverName, publicKey: publicKey, alpn: alpn)
        case .random: fatalError("random fingerprint must be resolved before dispatch")
        }
    }

    // MARK: - Chrome 120

    private static func buildChrome120(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        // BoringSSL GREASE: g_cipher, g_ext1, g_group (shared between
        // supported_groups and key_share per RFC 8446 §4.2.8), g_version, g_ext2
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2    = grease(random[29])

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

        // BoringGREASEECH: KDF=HKDF-SHA256(0x0001), AEAD=AES-128-GCM(0x0001)
        // Payload length picked from [128,160,192,224] + 16 AEAD overhead
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
                0x0403, 0x0804, 0x0401,  // ECDSA-P256-SHA256, PSS-SHA256, PKCS1-SHA256
                0x0503, 0x0805, 0x0501,  // ECDSA-P384-SHA384, PSS-SHA384, PKCS1-SHA384
                0x0806, 0x0601           // PSS-SHA512, PKCS1-SHA512
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),      // GREASE key share (must match supported_groups)
                (group: 0x001D, keyData: publicKey)          // X25519
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),                        // Brotli
            applicationSettingsExt(["h2"]),
            greaseECHExt(random: random, kdfId: 0x0001, aeadId: 0x0001, payloadLen: echPayloadLen),
            greaseExt(gExt2),
        ]

        // Chrome 106+ shuffles non-GREASE, non-padding extensions
        shuffleChromeExtensions(&exts, random: random)

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - Firefox 120

    private static func buildFirefox120(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        // Firefox uses no GREASE values
        let suites = cipherSuitesData([
            0x1301, 0x1303, 0x1302,                           // TLS 1.3 (ChaCha20 before AES-256)
            0xC02B, 0xC02F,                                   // ECDHE AES-128-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC02C, 0xC030,                                   // ECDHE AES-256-GCM
            0xC00A, 0xC009,                                   // ECDHE AES-CBC (ECDSA)
            0xC013, 0xC014,                                   // ECDHE AES-CBC (RSA)
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ])

        let protocols = alpn ?? ["h2", "http/1.1"]

        // Firefox offers two key shares: X25519 + P256
        let p256PublicKey = deriveP256PublicKey(from: random)

        // Firefox ECH: pick AES-128-GCM or ChaCha20 deterministically
        let echAead: UInt16 = (random[30] % 2 == 0) ? 0x0001 : 0x0003

        let exts: [Data] = [
            buildSNIExtension(serverName: serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([
                0x001D, 0x0017, 0x0018, 0x0019,              // X25519, P256, P384, P521
                0x0100, 0x0101                                // ffdhe2048, ffdhe3072
            ]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            delegatedCredentialsExt([0x0403, 0x0503, 0x0603, 0x0203]),
            keyShareExt([
                (group: 0x001D, keyData: publicKey),          // X25519
                (group: 0x0017, keyData: p256PublicKey)        // P256
            ]),
            supportedVersionsExt([0x0304, 0x0303]),
            signatureAlgorithmsExt([
                0x0403, 0x0503, 0x0603,                       // ECDSA P256/P384/P521
                0x0804, 0x0805, 0x0806,                       // PSS SHA256/384/512
                0x0401, 0x0501, 0x0601,                       // PKCS1 SHA256/384/512
                0x0203, 0x0201                                // ECDSA-SHA1, PKCS1-SHA1
            ]),
            pskKeyExchangeModesExt(),
            recordSizeLimitExt(0x4001),
            greaseECHExt(random: random, kdfId: 0x0001, aeadId: echAead, payloadLen: 239),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, false) // No BoringSSL padding
    }

    // MARK: - Safari 16.0

    private static func buildSafari16(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2    = grease(random[29])

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,                         // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,                         // ECDHE RSA (GCM, ChaCha)
            0xC00A, 0xC009,                                   // ECDHE ECDSA CBC
            0xC014, 0xC013,                                   // ECDHE RSA CBC
            0x009D, 0x009C,                                   // RSA GCM
            0x0035, 0x002F,                                   // RSA CBC
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
                0x0805, 0x0805,                               // Intentional duplicate (real Safari)
                0x0501,
                0x0806, 0x0601,
                0x0201
            ]),
            sctExt(),
            keyShareExt([
                (group: gGroup, keyData: Data([0x00])),      // GREASE key share (must match supported_groups)
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0001]),                        // Zlib
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
    }

    // MARK: - iOS 14

    private static func buildIOS14(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2    = grease(random[29])

        let suites = cipherSuitesData([
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,                         // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,                         // ECDHE RSA (GCM, ChaCha)
            0xC024, 0xC023, 0xC00A, 0xC009,                 // ECDHE ECDSA CBC (SHA384, SHA256, SHA)
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
                (group: gGroup, keyData: Data([0x00])),      // GREASE key share (must match supported_groups)
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

    // MARK: - Edge 106

    private static func buildEdge106(
        random: Data, serverName: String, publicKey: Data, alpn: [String]?
    ) -> (Data, Data, Bool) {
        let gCipher  = grease(random[24])
        let gExt1    = grease(random[25])
        let gGroup   = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2    = grease(random[29])

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
                (group: gGroup, keyData: Data([0x00])),      // GREASE key share (must match supported_groups)
                (group: 0x001D, keyData: publicKey)
            ]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),                        // Brotli
            applicationSettingsExt(["h2"]),
            greaseExt(gExt2),
        ]

        var extensionsData = Data()
        for e in exts { extensionsData.append(e) }

        return (suites, extensionsData, true)
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
