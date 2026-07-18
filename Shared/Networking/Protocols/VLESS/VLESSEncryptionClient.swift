//
//  VLESSEncryptionClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/10/26.
//

import Foundation
import CryptoKit
import Synchronization

// MARK: - Errors

nonisolated enum VLESSEncryptionError: Error, LocalizedError {
    case unsupported(String)
    case invalidPublicKey
    case handshakeFailed(String)
    case framingError(String)
    case connectionClosed

    var errorDescription: String? {
        switch self {
        case .unsupported(let s):  return "VLESS encryption: \(s)"
        case .invalidPublicKey:    return "VLESS encryption: invalid public key"
        case .handshakeFailed(let s): return "VLESS encryption handshake: \(s)"
        case .framingError(let s):    return "VLESS encryption framing: \(s)"
        case .connectionClosed:    return "VLESS encryption: connection closed"
        }
    }
}

// MARK: - Wire constants

nonisolated private enum VLESSWire {
    /// TLS 1.3 record header byte 0 (`application_data`).
    static let recordTypeApplicationData: UInt8 = 23
    /// TLS 1.3 record header bytes 1-2 (legacy version `0x0303`).
    static let recordVersionMajor: UInt8 = 3
    static let recordVersionMinor: UInt8 = 3
    /// 1 type + 2 version + 2 length.
    static let headerLength = 5
    static let maxChunkPlaintext = 8192
    /// AEAD tag length (both AES-GCM and ChaCha20-Poly1305).
    static let aeadTagLength = 16
    /// Largest valid TLS 1.3 record payload (16384 + 256 per RFC 8446 §5.2).
    static let maxRecordPayload = 16640
    /// Smallest valid payload must contain at least the AEAD tag.
    static let minRecordPayload = 17
    /// Sealed 2-byte length prefix (2 plaintext + 16 tag).
    static let sealedLengthFrame = 18
    /// ML-KEM ciphertext + X25519 pub + AEAD tag.
    static let pfsServerHelloLength = 1088 + 32 + 16
    /// Encrypted ticket reply (16 plaintext + 16 tag).
    static let encryptedTicketLength = 32
    static let pfsClientHelloPayloadLength = 1184 + 32
    /// Sealed PFS client hello: length frame + payload + tag.
    static let pfsClientHelloLength = 18 + pfsClientHelloPayloadLength + 16
}

// MARK: - AEAD wrapper

/// 12-byte big-endian-incrementing nonce; each seal/open without an explicit nonce
/// advances the counter by one.
// MARK: Code quality violation
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated private final class VLESSEncryptionAEAD: @unchecked Sendable {
    let key: SymmetricKey
    let useAES: Bool
    private var nonce: [UInt8] = Array(repeating: 0, count: 12)

    /// BLAKE3 key derivation from `(ctx, key)`; context is hashed as raw bytes.
    init(context: Data, key: Data, useAES: Bool) {
        let derived = BLAKE3Hasher.deriveKey(
            contextBytes: context,
            input: key,
            count: 32
        )
        self.key = SymmetricKey(data: derived)
        self.useAES = useAES
    }

    /// True when the *next* seal/open will use the maximum nonce, triggering a rekey.
    var nonceIsAtMax: Bool {
        for byte in nonce where byte != 0xFF { return false }
        return true
    }

    func seal(_ plaintext: Data, additionalData: Data?) throws -> Data {
        // Increment before use, so nonce 0 is never used.
        advanceNonce()
        let nonceData = Data(nonce)
        if useAES {
            let aeadNonce = try AES.GCM.Nonce(data: nonceData)
            let sealed: AES.GCM.SealedBox
            if let aad = additionalData {
                sealed = try AES.GCM.seal(plaintext, using: key, nonce: aeadNonce, authenticating: aad)
            } else {
                sealed = try AES.GCM.seal(plaintext, using: key, nonce: aeadNonce)
            }
            return sealed.ciphertext + sealed.tag
        } else {
            let aeadNonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealed: ChaChaPoly.SealedBox
            if let aad = additionalData {
                sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: aeadNonce, authenticating: aad)
            } else {
                sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: aeadNonce)
            }
            return sealed.ciphertext + sealed.tag
        }
    }

    /// Open a sealed buffer (`ciphertext + tag`). Same increment-before-use nonce semantics as `seal`.
    func open(_ sealed: Data, additionalData: Data?) throws -> Data {
        advanceNonce()
        let nonceData = Data(nonce)
        return try open(sealed, nonce: nonceData, additionalData: additionalData)
    }

    /// Open with an explicit nonce (used for the "max nonce" rekey marker).
    func open(_ sealed: Data, nonce: Data, additionalData: Data?) throws -> Data {
        guard sealed.count >= VLESSWire.aeadTagLength else {
            throw VLESSEncryptionError.framingError("sealed buffer shorter than tag")
        }
        let ciphertext = sealed.prefix(sealed.count - VLESSWire.aeadTagLength)
        let tag = sealed.suffix(VLESSWire.aeadTagLength)
        if useAES {
            let n = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: n, ciphertext: ciphertext, tag: tag)
            if let aad = additionalData {
                return try AES.GCM.open(box, using: key, authenticating: aad)
            } else {
                return try AES.GCM.open(box, using: key)
            }
        } else {
            let n = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ciphertext, tag: tag)
            if let aad = additionalData {
                return try ChaChaPoly.open(box, using: key, authenticating: aad)
            } else {
                return try ChaChaPoly.open(box, using: key)
            }
        }
    }

    /// Big-endian increment.
    private func advanceNonce() {
        for i in stride(from: 11, through: 0, by: -1) {
            nonce[i] &+= 1
            if nonce[i] != 0 { return }
        }
    }
}

// MARK: - Header codec

nonisolated private enum VLESSHeader {
    static func encode(into buffer: inout Data, payloadLength: Int) {
        buffer.append(VLESSWire.recordTypeApplicationData)
        buffer.append(VLESSWire.recordVersionMajor)
        buffer.append(VLESSWire.recordVersionMinor)
        buffer.append(UInt8(payloadLength >> 8))
        buffer.append(UInt8(payloadLength & 0xFF))
    }

    static func decode(_ header: [UInt8]) throws -> Int {
        guard header.count == VLESSWire.headerLength else {
            throw VLESSEncryptionError.framingError("header is not 5 bytes")
        }
        let length = (Int(header[3]) << 8) | Int(header[4])
        guard header[0] == VLESSWire.recordTypeApplicationData,
              header[1] == VLESSWire.recordVersionMajor,
              header[2] == VLESSWire.recordVersionMinor else {
            throw VLESSEncryptionError.framingError("unexpected record prefix \(header[0..<3])")
        }
        guard length >= VLESSWire.minRecordPayload, length <= VLESSWire.maxRecordPayload else {
            throw VLESSEncryptionError.framingError("record length \(length) out of range")
        }
        return length
    }
}

/// Two-byte big-endian length helpers.
nonisolated private enum VLESSLength {
    static func encode(_ value: Int) -> Data {
        Data([UInt8(value >> 8), UInt8(value & 0xFF)])
    }
    static func decode(_ bytes: Data) -> Int {
        return (Int(bytes[bytes.startIndex]) << 8) | Int(bytes[bytes.startIndex + 1])
    }
}

// MARK: - Padding scheduler

/// Padding length/gap spec parser; each segment is `prob-min-max`.
nonisolated struct VLESSEncryptionPadding {
    /// (probability, min, max).
    let lengths: [(Int, Int, Int)]
    /// (probability, min ms, max ms). Sleeps between fragments.
    let gaps: [(Int, Int, Int)]

    static let `default` = VLESSEncryptionPadding(
        lengths: [(100, 111, 1111), (50, 0, 3333)],
        gaps: [(75, 0, 111)]
    )

    static func parse(_ raw: String) throws -> VLESSEncryptionPadding {
        if raw.isEmpty { return .default }
        var lengths: [(Int, Int, Int)] = []
        var gaps: [(Int, Int, Int)] = []
        var totalMaxLen = 0
        for (i, segment) in raw.split(separator: ".", omittingEmptySubsequences: false).enumerated() {
            let parts = segment.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count >= 3,
                  let prob = Int(parts[0]),
                  let lo = Int(parts[1]),
                  let hi = Int(parts[2]) else {
                throw VLESSEncryptionError.unsupported("invalid padding segment \"\(segment)\"")
            }
            if i == 0, prob < 100 || lo < 35 || hi < 35 {
                throw VLESSEncryptionError.unsupported("first padding length must be at least 35")
            }
            if i % 2 == 0 {
                lengths.append((prob, lo, hi))
                totalMaxLen += max(lo, hi)
            } else {
                gaps.append((prob, lo, hi))
            }
        }
        guard totalMaxLen <= 18 + 65535 else {
            throw VLESSEncryptionError.unsupported("total padding length must not exceed 65553")
        }
        return VLESSEncryptionPadding(lengths: lengths, gaps: gaps)
    }

    func materialize() -> (totalLength: Int, lengths: [Int], gaps: [TimeInterval]) {
        var lens: [Int] = []
        var gapList: [TimeInterval] = []
        var total = 0
        for (prob, lo, hi) in lengths {
            let length: Int
            if prob >= Int.random(in: 0..<100) {
                length = Int.random(in: lo...max(lo, hi))
            } else {
                length = 0
            }
            lens.append(length)
            total += length
        }
        for (prob, lo, hi) in gaps {
            let g: Int
            if prob >= Int.random(in: 0..<100) {
                g = Int.random(in: lo...max(lo, hi))
            } else {
                g = 0
            }
            gapList.append(TimeInterval(g) / 1000.0)
        }
        return (total, lens, gapList)
    }
}

// MARK: - NFS public key (parsed)

@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated private enum VLESSNfsPublicKey {
    case x25519(Curve25519.KeyAgreement.PublicKey, raw: Data)
    case mlkem768(MLKEM768.PublicKey, raw: Data)

    var relayBlockBytes: Int {
        switch self {
        case .x25519:    return 32
        case .mlkem768:  return 1088
        }
    }

    var rawBytes: Data {
        switch self {
        case .x25519(_, let raw):    return raw
        case .mlkem768(_, let raw):  return raw
        }
    }

    static func parse(_ raw: Data) throws -> VLESSNfsPublicKey {
        switch raw.count {
        case 32:
            return .x25519(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw), raw: raw)
        case 1184:
            return .mlkem768(try MLKEM768.PublicKey(rawRepresentation: raw), raw: raw)
        default:
            throw VLESSEncryptionError.invalidPublicKey
        }
    }
}

// MARK: - VLESSEncryptionClient

@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated final class VLESSEncryptionClient {
    private let nfsKeys: [VLESSNfsPublicKey]
    /// Raw pubkey bytes per relay, in chain order; keys the `xorpub`/`random` CTR streams.
    private let nfsKeysRaw: [Data]
    /// BLAKE3-256 hash of each relay's raw pubkey.
    private let nfsKeysHash32: [Data]
    private let padding: VLESSEncryptionPadding
    private let xorMode: VLESSEncryptionConfig.XORMode
    private let seconds: UInt32
    private let cacheKey: String
    /// Always true on Apple platforms — every iOS 26 device has hardware AES-GCM.
    private let useAES = true

    init(config: VLESSEncryptionConfig, host: String, port: UInt16) throws {
        var keys: [VLESSNfsPublicKey] = []
        var raw: [Data] = []
        var hashes: [Data] = []
        for publicKeyBytes in config.publicKeys {
            keys.append(try VLESSNfsPublicKey.parse(publicKeyBytes))
            raw.append(publicKeyBytes)
            hashes.append(BLAKE3Hasher.hash(publicKeyBytes))
        }
        self.nfsKeys = keys
        self.nfsKeysRaw = raw
        self.nfsKeysHash32 = hashes
        self.padding = try VLESSEncryptionPadding.parse(config.padding)
        self.xorMode = config.xorMode
        self.seconds = config.seconds
        self.cacheKey = VLESSEncryption0RTTCache.cacheKey(host: host, port: port, config: config)
    }

    /// Perform the handshake over `connection`, choosing 0-RTT when a valid cached ticket exists.
    func handshake(over connection: ProxyConnection) async throws -> VLESSEncryptedConnection {
        let cached: VLESSEncryption0RTTCache.Entry?
        if seconds > 0 {
            cached = VLESSEncryption0RTTCache.shared.lookup(key: cacheKey)
        } else {
            cached = nil
        }

        if let cached {
            return try await sendClientHello0RTT(over: connection, cached: cached)
        }
        let state = try await sendClientHello1RTT(over: connection)
        return try await readServerHello(over: connection, state: state)
    }

    // MARK: - Shared helpers

    private func generateIV() throws -> Data {
        var iv = Data(count: 16)
        let status = iv.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, 16, pointer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw VLESSEncryptionError.handshakeFailed("rng failure")
        }
        return iv
    }

    /// Build the wire relay block and return the final relay's shared secret as `nfsKey`.
    private func buildRelayBlock(iv: Data) throws -> (relayBlock: Data, nfsKey: Data) {
        var relayBlock = Data()
        var nfsKey = Data()
        var lastCTR: VLESSEncryptionCTR? = nil
        for j in 0..<nfsKeys.count {
            var publicKeyOrCiphertext = Data()
            switch nfsKeys[j] {
            case .x25519(let serverPub, _):
                let priv = Curve25519.KeyAgreement.PrivateKey()
                let shared = try priv.sharedSecretFromKeyAgreement(with: serverPub)
                nfsKey = shared.withUnsafeBytes { Data($0) }
                publicKeyOrCiphertext = priv.publicKey.rawRepresentation
            case .mlkem768(let serverPub, _):
                let result = try serverPub.encapsulate()
                nfsKey = result.sharedSecret.withUnsafeBytes { Data($0) }
                publicKeyOrCiphertext = result.encapsulated
            }
            if xorMode != .native {
                let ctr = try VLESSEncryptionCTR(key: nfsKeysRaw[j], iv: iv)
                publicKeyOrCiphertext = ctr.process(publicKeyOrCiphertext)
            }
            if let lastCTR {
                // XOR only the leading 32 bytes with the previous relay's keystream;
                // the chain-hash XOR continues that same stream.
                let bytes = [UInt8](publicKeyOrCiphertext)
                let xoredHead = lastCTR.process(Data(bytes[0..<32]))
                var combined = xoredHead
                combined.append(contentsOf: bytes[32..<bytes.count])
                publicKeyOrCiphertext = combined
            }
            relayBlock.append(publicKeyOrCiphertext)
            if j < nfsKeys.count - 1 {
                // Next relay's pubkey hash, XOR'd with a CTR keyed on this relay's
                // nfsKey — binds the chain order so the server can verify it.
                let newCTR = try VLESSEncryptionCTR(key: nfsKey, iv: iv)
                relayBlock.append(newCTR.process(nfsKeysHash32[j + 1]))
                lastCTR = newCTR
            }
        }
        return (relayBlock, nfsKey)
    }

    // MARK: - 0-RTT client hello

    /// 0-RTT client hello: `iv || relays || seal(EncodeLength(32)) || seal(ticket)`;
    /// the hello bytes are prepended to the first application record via `preludeBytes`.
    private func sendClientHello0RTT(
        over connection: ProxyConnection,
        cached: VLESSEncryption0RTTCache.Entry
    ) async throws -> VLESSEncryptedConnection {
        let iv = try generateIV()
        let (relayBlock, nfsKey) = try buildRelayBlock(iv: iv)

        let nfsAEAD = VLESSEncryptionAEAD(context: iv, key: nfsKey, useAES: useAES)
        let sealedLength = try nfsAEAD.seal(VLESSLength.encode(32), additionalData: nil) // 18 bytes
        let sealedTicket = try nfsAEAD.seal(cached.ticket, additionalData: nil)          // 32 bytes

        var clientHello = Data()
        clientHello.append(iv)
        clientHello.append(relayBlock)
        clientHello.append(sealedLength)
        clientHello.append(sealedTicket)

        var unitedKey = cached.pfsKey
        unitedKey.append(nfsKey)
        let writeAEAD = VLESSEncryptionAEAD(context: sealedTicket, key: unitedKey, useAES: useAES)

        let xorConnection: VLESSXORConnection?
        let transport: ProxyConnection
        if xorMode == .random {
            // outSkip skips XOR over the unmasked prelude; inSkip=16 skips
            // the server's 16-byte server-random that precedes masked records.
            let xor = VLESSXORConnection(
                inner: connection,
                outCTR: try VLESSEncryptionCTR(key: unitedKey, iv: iv),
                inCTR: nil,
                outSkip: clientHello.count,
                inSkip: 16
            )
            xorConnection = xor
            transport = xor
        } else {
            xorConnection = nil
            transport = connection
        }

        let zeroRTT = VLESSEncryptedConnection.ZeroRTTState(
            unitedKey: unitedKey,
            pfsKey: cached.pfsKey,
            cacheKey: cacheKey
        )
        let encryptedConnection = VLESSEncryptedConnection(
            inner: transport,
            writeAEAD: writeAEAD,
            readAEAD: nil,
            unitedKey: unitedKey,
            useAES: useAES,
            preludeBytes: clientHello,
            pendingServerPaddingLength: 0,
            carryOverBytes: Data(),
            xorConnection: xorConnection,
            zeroRTTState: zeroRTT
        )
        return encryptedConnection
    }

    // MARK: - 1-RTT client hello

    private struct InFlightHandshake {
        let iv: Data
        let nfsKey: Data
        let mlkemPriv: MLKEM768.PrivateKey
        let x25519Priv: Curve25519.KeyAgreement.PrivateKey
        let pfsClientPublicKey: Data  // 1184 + 32 bytes (the AAD/ctx for AEAD setup)
        let nfsAEAD: VLESSEncryptionAEAD
    }

    /// Build the 1-RTT client hello, send it in padded fragments, and return the mid-handshake state.
    private func sendClientHello1RTT(
        over connection: ProxyConnection
    ) async throws -> InFlightHandshake {
        let iv = try generateIV()
        let (relayBlock, nfsKey) = try buildRelayBlock(iv: iv)
        let nfsAEAD = VLESSEncryptionAEAD(context: iv, key: nfsKey, useAES: useAES)

        let mlkemPriv = try MLKEM768.PrivateKey()
        let x25519Priv = Curve25519.KeyAgreement.PrivateKey()
        var pfsPublic = Data()
        pfsPublic.append(mlkemPriv.publicKey.rawRepresentation)        // 1184 bytes
        pfsPublic.append(x25519Priv.publicKey.rawRepresentation)       // 32 bytes

        // Length frame encodes the SEALED body size (plaintext + AEAD tag), not the
        // plaintext size — the server reads exactly that many bytes as ciphertext+tag.
        let sealedLengthFrame = try nfsAEAD.seal(
            VLESSLength.encode(VLESSWire.pfsClientHelloPayloadLength + VLESSWire.aeadTagLength),
            additionalData: nil
        )
        let sealedPfsPublic = try nfsAEAD.seal(pfsPublic, additionalData: nil)

        let (paddingTotal, paddingLens, paddingGaps) = padding.materialize()
        let paddingPayloadLength = max(paddingTotal - 18 - 16, 0)
        let paddingPayload = Data(count: paddingPayloadLength)
        let sealedPaddingLength = try nfsAEAD.seal(
            VLESSLength.encode(paddingPayloadLength + VLESSWire.aeadTagLength),
            additionalData: nil
        )
        let sealedPaddingBody = try nfsAEAD.seal(paddingPayload, additionalData: nil)

        var clientHello = Data()
        clientHello.append(iv)                  // 16 bytes
        clientHello.append(relayBlock)          // 32 (1× X25519) up to 1088+32+1088 (etc.)
        clientHello.append(sealedLengthFrame)   // 18 bytes
        clientHello.append(sealedPfsPublic)     // 1184 + 32 + 16 = 1232 bytes
        clientHello.append(sealedPaddingLength) // 18 bytes
        clientHello.append(sealedPaddingBody)   // paddingPayloadLength + 16 bytes

        // First fragment absorbs the pre-padding prefix so the leading wire bytes look plausible.
        var fragmentLengths = paddingLens
        if !fragmentLengths.isEmpty {
            let prePadding = clientHello.count - paddingTotal
            fragmentLengths[0] = prePadding + fragmentLengths[0]
        } else {
            fragmentLengths = [clientHello.count]
        }

        let state = InFlightHandshake(
            iv: iv,
            nfsKey: nfsKey,
            mlkemPriv: mlkemPriv,
            x25519Priv: x25519Priv,
            pfsClientPublicKey: pfsPublic,
            nfsAEAD: nfsAEAD
        )
        try await sendFragments(
            over: connection,
            buffer: clientHello,
            lengths: fragmentLengths,
            gaps: paddingGaps,
            index: 0
        )
        return state
    }

    /// Recursively send `buffer` in `lengths`-sized chunks, sleeping `gaps` between them.
    private func sendFragments(
        over connection: ProxyConnection,
        buffer: Data,
        lengths: [Int],
        gaps: [TimeInterval],
        index: Int
    ) async throws {
        if index >= lengths.count {
            if !buffer.isEmpty {
                try await connection.sendRaw(buffer)
            }
            return
        }
        let length = min(lengths[index], buffer.count)
        let head = buffer.prefix(length)
        let tail = buffer.suffix(from: buffer.startIndex + length)

        if !head.isEmpty {
            try await connection.sendRaw(Data(head))
        }

        let gap = index < gaps.count ? gaps[index] : 0
        if gap > 0 {
            try await Task.sleep(for: .seconds(gap))
        }
        try await sendFragments(
            over: connection,
            buffer: Data(tail),
            lengths: lengths,
            gaps: gaps,
            index: index + 1
        )
    }

    // MARK: - Server hello

    /// Read server PFS hello + ticket + padding, derive session keys, return a ready connection.
    private func readServerHello(
        over connection: ProxyConnection,
        state: InFlightHandshake
    ) async throws -> VLESSEncryptedConnection {
        let reader = VLESSEncryptionByteReader(connection: connection)
        let sealedServerPfs = try await reader.readExact(VLESSWire.pfsServerHelloLength)
        let serverPfsPublic = try state.nfsAEAD.open(
            sealedServerPfs,
            nonce: Data(repeating: 0xFF, count: 12),
            additionalData: nil
        )
        guard serverPfsPublic.count == 1088 + 32 else {
            throw VLESSEncryptionError.handshakeFailed("PFS server hello has wrong length")
        }
        let mlkemCiphertext = serverPfsPublic.prefix(1088)
        let x25519PubBytes = serverPfsPublic.suffix(32)

        let mlkemSecret = try state.mlkemPriv.decapsulate(mlkemCiphertext)
        let serverX25519 = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: x25519PubBytes
        )
        let x25519Secret = try state.x25519Priv.sharedSecretFromKeyAgreement(with: serverX25519)

        var pfsKey = Data()
        pfsKey.append(mlkemSecret.withUnsafeBytes { Data($0) })   // 32 bytes
        pfsKey.append(x25519Secret.withUnsafeBytes { Data($0) })  // 32 bytes
        var unitedKey = pfsKey
        unitedKey.append(state.nfsKey)

        // Both AEADs are keyed on *plaintext* PFS public bytes.
        let writeAEAD = VLESSEncryptionAEAD(
            context: state.pfsClientPublicKey, key: unitedKey, useAES: useAES
        )
        let readAEAD = VLESSEncryptionAEAD(
            context: serverPfsPublic, key: unitedKey, useAES: useAES
        )

        return try await readTicketAndPadding(
            reader: reader,
            connection: connection,
            state: state,
            pfsKey: pfsKey,
            unitedKey: unitedKey,
            writeAEAD: writeAEAD,
            readAEAD: readAEAD
        )
    }

    private func readTicketAndPadding(
        reader: VLESSEncryptionByteReader,
        connection: ProxyConnection,
        state: InFlightHandshake,
        pfsKey: Data,
        unitedKey: Data,
        writeAEAD: VLESSEncryptionAEAD,
        readAEAD: VLESSEncryptionAEAD
    ) async throws -> VLESSEncryptedConnection {
        let sealedTicket = try await reader.readExact(VLESSWire.encryptedTicketLength)
        let ticketPayload = try readAEAD.open(sealedTicket, additionalData: nil)
        // First two bytes are a big-endian seconds TTL from the server; zero
        // means no resumption. The cached ticket is the 16-byte plaintext body.
        if seconds > 0, ticketPayload.count >= 16 {
            let serverSeconds = VLESSLength.decode(ticketPayload)
            if serverSeconds > 0 {
                let expire = CFAbsoluteTimeGetCurrent() + TimeInterval(serverSeconds)
                VLESSEncryption0RTTCache.shared.store(
                    key: cacheKey,
                    pfsKey: pfsKey,
                    ticket: Data(ticketPayload.prefix(16)),
                    expire: expire
                )
            }
        }
        let sealedLength = try await reader.readExact(VLESSWire.sealedLengthFrame)
        let lenBytes = try readAEAD.open(sealedLength, additionalData: nil)
        // Decoded value is the SEALED body size (plaintext + tag).
        guard lenBytes.count >= 2 else {
            throw VLESSEncryptionError.framingError("server sealed length frame too short: \(lenBytes.count) bytes")
        }
        let sealedPaddingBodySize = VLESSLength.decode(lenBytes)
        // Over-read bytes are padding tail, always unmasked (sent
        // before the server enables XOR masking); carry them over.
        let leftover = reader.drain()

        // inSkip covers padding tail still on the wire; leftover bytes
        // bypass the XOR wrapper via carryOverBytes, so don't skip them again.
        let xorConnection: VLESSXORConnection?
        let transport: ProxyConnection
        if xorMode == .random {
            let xor = VLESSXORConnection(
                inner: connection,
                outCTR: try VLESSEncryptionCTR(key: unitedKey, iv: state.iv),
                inCTR: try VLESSEncryptionCTR(key: unitedKey, iv: Data(ticketPayload.prefix(16))),
                outSkip: 0,
                inSkip: max(0, sealedPaddingBodySize - leftover.count)
            )
            xorConnection = xor
            transport = xor
        } else {
            xorConnection = nil
            transport = connection
        }
        let encryptedConnection = VLESSEncryptedConnection(
            inner: transport,
            writeAEAD: writeAEAD,
            readAEAD: readAEAD,
            unitedKey: unitedKey,
            useAES: useAES,
            preludeBytes: nil,
            pendingServerPaddingLength: sealedPaddingBodySize,
            carryOverBytes: leftover,
            xorConnection: xorConnection,
            zeroRTTState: nil
        )
        return encryptedConnection
    }
}

// MARK: - Byte reader (buffered fixed-size receive helper)

@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated private final class VLESSEncryptionByteReader {
    let connection: ProxyConnection
    private let buffer = Mutex(Data())

    init(connection: ProxyConnection) {
        self.connection = connection
    }

    func readExact(_ count: Int) async throws -> Data {
        while true {
            let head: Data? = buffer.withLock { buffer in
                guard buffer.count >= count else { return nil }
                let head = Data(buffer.prefix(count))
                buffer.removeFirst(count)
                return head
            }
            if let head {
                return head
            }
            guard let data = try await connection.receiveRaw(), !data.isEmpty else {
                throw VLESSEncryptionError.connectionClosed
            }
            buffer.withLock { $0.append(data) }
        }
    }

    func drain() -> Data {
        buffer.withLock { buffer in
            let snapshot = buffer
            buffer.removeAll(keepingCapacity: true)
            return snapshot
        }
    }
}

// MARK: - VLESSEncryptedConnection

/// AEAD-framed wrapper: application bytes travel as TLS-1.3-style records
/// (5-byte header + sealed payload), with a BLAKE3 rekey when the nonce wraps.
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated final class VLESSEncryptedConnection: ProxyConnection {
    /// Snapshot of the cache entry behind a 0-RTT attempt, so first-record decode
    /// failure invalidates exactly that entry and not a newer ticket that raced in.
    struct ZeroRTTState {
        let unitedKey: Data
        let pfsKey: Data
        let cacheKey: String
    }

    private let inner: ProxyConnection
    /// Weak back-reference to the XOR leg, boxed so the connection stays `Sendable`; set once at init.
    private struct WeakXOR { weak var value: VLESSXORConnection? }
    private let xorConnectionBox: Mutex<WeakXOR>
    private let unitedKey: Data
    private let useAES: Bool

    private let zeroRTTState: ZeroRTTState?

    private struct SendState {
        var writeAEAD: VLESSEncryptionAEAD
        /// 0-RTT hello blob prepended to the first outbound record, then cleared.
        var preludeBytes: Data?
    }

    private struct RecvState {
        var readAEAD: VLESSEncryptionAEAD?
        /// Partial-record buffer; seeded with the handshake reader's leftover bytes.
        var inboundBuffer: Data
        /// Server handshake-tail padding to drain before app data (1-RTT only).
        var pendingServerPaddingLength: Int
        /// The 0-RTT-rejection signal only counts on the *first* record; once any
        /// record opens cleanly, the ticket was accepted.
        var firstRecordSeen = false
    }

    private let sendState: Mutex<SendState>
    private let recvState: Mutex<RecvState>

    fileprivate init(
        inner: ProxyConnection,
        writeAEAD: VLESSEncryptionAEAD,
        readAEAD: VLESSEncryptionAEAD?,
        unitedKey: Data,
        useAES: Bool,
        preludeBytes: Data?,
        pendingServerPaddingLength: Int,
        carryOverBytes: Data,
        xorConnection: VLESSXORConnection?,
        zeroRTTState: ZeroRTTState?
    ) {
        self.inner = inner
        self.xorConnectionBox = Mutex(WeakXOR(value: xorConnection))
        self.useAES = useAES
        self.unitedKey = unitedKey
        self.sendState = Mutex(SendState(writeAEAD: writeAEAD, preludeBytes: preludeBytes))
        self.recvState = Mutex(RecvState(
            readAEAD: readAEAD,
            inboundBuffer: carryOverBytes,
            pendingServerPaddingLength: pendingServerPaddingLength
        ))
        self.zeroRTTState = zeroRTTState
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    // MARK: - Send

    func sendRaw(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        let frames = try buildOutboundFrames(plaintext: data)
        try await inner.sendRaw(frames)
    }

    private func buildOutboundFrames(plaintext: Data) throws -> Data {
        return try sendState.withLock { state in
            var output = Data()
            if let prelude = state.preludeBytes {
                output.append(prelude)
                state.preludeBytes = nil
            }
            var offset = 0
            while offset < plaintext.count {
                let chunkSize = min(plaintext.count - offset, VLESSWire.maxChunkPlaintext)
                let chunk = plaintext.subdata(
                    in: plaintext.startIndex.advanced(by: offset)
                        ..< plaintext.startIndex.advanced(by: offset + chunkSize)
                )
                // Header encodes (chunkSize + tag); header bytes are the AAD for this record.
                var header = Data()
                VLESSHeader.encode(into: &header, payloadLength: chunkSize + VLESSWire.aeadTagLength)
                let willRekey = state.writeAEAD.nonceIsAtMax
                let sealed = try state.writeAEAD.seal(chunk, additionalData: header)
                output.append(header)
                output.append(sealed)
                if willRekey {
                    var context = header
                    context.append(sealed)
                    state.writeAEAD = VLESSEncryptionAEAD(context: context, key: self.unitedKey, useAES: self.useAES)
                }
                offset += chunkSize
            }
            return output
        }
    }

    // MARK: - Receive

    func receiveRaw() async throws -> Data? {
        // 0-RTT: readAEAD is unknown until the server random arrives.
        if recvState.withLock({ $0.readAEAD == nil }) {
            try await establishReadAEAD()
        }
        try await drainServerPadding()
        return try await readOneRecord()
    }

    /// Read 16-byte server random, derive the read AEAD, and install the inbound XOR CTR for random mode.
    private func establishReadAEAD() async throws {
        let needed = 16
        while true {
            let serverRandom: Data? = recvState.withLock { state in
                guard state.inboundBuffer.count >= needed else { return nil }
                let serverRandom = Data(state.inboundBuffer.prefix(needed))
                state.inboundBuffer.removeFirst(needed)
                return serverRandom
            }
            if let serverRandom {
                try installReadAEAD(serverRandom: serverRandom)
                return
            }
            guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                throw VLESSEncryptionError.connectionClosed
            }
            recvState.withLock { $0.inboundBuffer.appendCompacting(data) }
        }
    }

    private func installReadAEAD(serverRandom: Data) throws {
        let aead = VLESSEncryptionAEAD(context: serverRandom, key: unitedKey, useAES: useAES)
        recvState.withLock { $0.readAEAD = aead }
        if let xor = xorConnectionBox.withLock({ $0.value }) {
            xor.installInboundCTR(try VLESSEncryptionCTR(key: unitedKey, iv: serverRandom))
        }
    }

    /// Drains the server handshake-tail padding (one-shot per connection) before app data.
    private func drainServerPadding() async throws {
        enum PaddingStep {
            case done
            case needMore
        }
        while true {
            // The AEAD `open` (which advances the read nonce) runs inside the lock that guards
            // `readAEAD`/`inboundBuffer`, mirroring the send path — receive is single-consumer,
            // so there's no contention to hold the crypto across.
            let paddingStep: PaddingStep = try recvState.withLock { state in
                guard state.pendingServerPaddingLength > 0 else { return .done }
                let needed = state.pendingServerPaddingLength
                guard state.inboundBuffer.count >= needed else { return .needMore }
                let sealedPadding = Data(state.inboundBuffer.prefix(needed))
                state.inboundBuffer.removeFirst(needed)
                _ = try state.readAEAD!.open(sealedPadding, additionalData: nil)
                state.pendingServerPaddingLength = 0
                return .done
            }
            switch paddingStep {
            case .done:
                return
            case .needMore:
                guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                    return   // EOF mid-padding surfaces as a clean close on the next read
                }
                recvState.withLock { $0.inboundBuffer.appendCompacting(data) }
            }
        }
    }

    /// Reads and decrypts one AEAD record; `nil` signals a clean close.
    private func readOneRecord() async throws -> Data? {
        enum RecordStep {
            case needMore
            case decodeFailed(Error, firstRecordSeen: Bool)
            case record(Data)
        }
        while true {
            // Header decode, AEAD `open` (nonce advance), and any rekey all run under the one
            // lock that guards `readAEAD`/`inboundBuffer`/`firstRecordSeen` — the whole record is
            // consumed atomically, mirroring the send path. `receiveRaw` stays outside the lock.
            let recordStep: RecordStep = try recvState.withLock { state -> RecordStep in
                guard state.inboundBuffer.count >= VLESSWire.headerLength else { return .needMore }
                let headerBytes = Array(state.inboundBuffer.prefix(VLESSWire.headerLength))
                let payloadLength: Int
                do {
                    payloadLength = try VLESSHeader.decode(headerBytes)
                } catch {
                    return .decodeFailed(error, firstRecordSeen: state.firstRecordSeen)
                }
                let recordTotal = VLESSWire.headerLength + payloadLength
                guard state.inboundBuffer.count >= recordTotal else { return .needMore }
                let recordBytes = Data(state.inboundBuffer.prefix(recordTotal))
                state.inboundBuffer.removeFirst(recordTotal)
                let header = Data(recordBytes.prefix(VLESSWire.headerLength))
                let sealedPayload = recordBytes.suffix(payloadLength)
                let willRekey = state.readAEAD!.nonceIsAtMax
                // Header bytes are the AAD for this record.
                let plaintext = try state.readAEAD!.open(Data(sealedPayload), additionalData: header)
                state.firstRecordSeen = true
                if willRekey {
                    var context = Data(header)
                    context.append(Data(sealedPayload))
                    state.readAEAD = VLESSEncryptionAEAD(context: context, key: unitedKey, useAES: useAES)
                }
                return .record(plaintext)
            }

            switch recordStep {
            case .needMore:
                guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                    return nil
                }
                recvState.withLock { $0.inboundBuffer.appendCompacting(data) }
            case .decodeFailed(let error, let firstRecordSeen):
                // 0-RTT rejection: the server wrote noise instead of a valid record;
                // invalidate this ticket so a future dial re-handshakes.
                if !firstRecordSeen, let zeroRTT = zeroRTTState {
                    VLESSEncryption0RTTCache.shared.invalidate(key: zeroRTT.cacheKey, matching: zeroRTT.pfsKey)
                    throw VLESSEncryptionError.handshakeFailed("new handshake needed")
                }
                throw error
            case .record(let plaintext):
                return plaintext
            }
        }
    }

    // MARK: - Vision direct-copy (bypass AEAD)

    // Vision direct copy peels only our AEAD layer (unwrapping to the raw conn);
    // delegating to `inner` keeps random-mode XOR masking and outer TLS intact.

    func sendDirectRaw(_ data: Data) async throws {
        try await inner.sendRaw(data)
    }

    func receiveDirectRaw() async throws -> Data? {
        // Flush bytes over-read past the last AEAD record; `inner.receiveRaw` would not replay them.
        let leftover: Data? = recvState.withLock { state in
            guard !state.inboundBuffer.isEmpty else { return nil }
            let leftover = state.inboundBuffer
            state.inboundBuffer = Data()
            return leftover
        }
        if let leftover {
            return leftover
        }
        return try await inner.receiveRaw()
    }

    func cancel() {
        inner.cancel()
    }
}
