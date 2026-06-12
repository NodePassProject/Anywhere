//
//  VLESSEncryptionClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/10/26.
//

import Foundation
import CryptoKit

// MARK: - Errors

enum VLESSEncryptionError: Error, LocalizedError {
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

/// AEAD framing constants (must match Xray-core's `proxy/vless/encryption/common.go`).
private enum VLESSWire {
    /// TLS 1.3 record header byte 0 (`application_data`).
    static let recordTypeApplicationData: UInt8 = 23
    /// TLS 1.3 record header bytes 1-2 (legacy version `0x0303`).
    static let recordVersionMajor: UInt8 = 3
    static let recordVersionMinor: UInt8 = 3
    /// Header length in bytes: 1 type + 2 version + 2 length.
    static let headerLength = 5
    /// Plaintext chunk size used by the writer (matches Go's 8192 cap).
    static let maxChunkPlaintext = 8192
    /// AEAD authentication tag length (both AES-GCM and ChaCha20-Poly1305).
    static let aeadTagLength = 16
    /// Largest valid TLS 1.3 record payload (16384 + 256 per RFC 8446 §5.2).
    static let maxRecordPayload = 16640
    /// Smallest valid TLS 1.3 record payload (must contain at least the AEAD tag).
    static let minRecordPayload = 17
    /// Length in bytes of a sealed 2-byte length prefix (2 plaintext + 16 tag).
    static let sealedLengthFrame = 18
    /// Length in bytes of the PFS server hello: ML-KEM ciphertext + X25519 pub + AEAD tag.
    static let pfsServerHelloLength = 1088 + 32 + 16
    /// Length in bytes of the encrypted ticket reply (16 plaintext + 16 tag).
    static let encryptedTicketLength = 32
    /// Length in bytes of the unsealed PFS client hello payload.
    static let pfsClientHelloPayloadLength = 1184 + 32
    /// Length in bytes of the sealed PFS client hello (length frame + payload + tag).
    static let pfsClientHelloLength = 18 + pfsClientHelloPayloadLength + 16
}

// MARK: - AEAD wrapper (matches Go's AEAD struct in common.go)

/// CryptoKit AEAD with a 12-byte big-endian-incrementing nonce; each seal/open
/// without an explicit nonce advances the counter by one (matches Go's AEAD struct).
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
private final class VLESSEncryptionAEAD {
    let key: SymmetricKey
    let useAES: Bool
    private var nonce: [UInt8] = Array(repeating: 0, count: 12)

    /// BLAKE3 key derivation from `(ctx, key)`; context is hashed as raw bytes to match Go's `NewAEAD`.
    init(context: Data, key: Data, useAES: Bool) {
        let derived = Blake3Hasher.deriveKey(
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
        // Go's `IncreaseNonce` semantics: increment before use, so nonce 0 is never used.
        advanceNonce()
        let nonceData = Data(nonce)
        if useAES {
            let n = try AES.GCM.Nonce(data: nonceData)
            let sealed: AES.GCM.SealedBox
            if let aad = additionalData {
                sealed = try AES.GCM.seal(plaintext, using: key, nonce: n, authenticating: aad)
            } else {
                sealed = try AES.GCM.seal(plaintext, using: key, nonce: n)
            }
            return sealed.ciphertext + sealed.tag
        } else {
            let n = try ChaChaPoly.Nonce(data: nonceData)
            let sealed: ChaChaPoly.SealedBox
            if let aad = additionalData {
                sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: n, authenticating: aad)
            } else {
                sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: n)
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
        let ct = sealed.prefix(sealed.count - VLESSWire.aeadTagLength)
        let tag = sealed.suffix(VLESSWire.aeadTagLength)
        if useAES {
            let n = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: n, ciphertext: ct, tag: tag)
            if let aad = additionalData {
                return try AES.GCM.open(box, using: key, authenticating: aad)
            } else {
                return try AES.GCM.open(box, using: key)
            }
        } else {
            let n = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ct, tag: tag)
            if let aad = additionalData {
                return try ChaChaPoly.open(box, using: key, authenticating: aad)
            } else {
                return try ChaChaPoly.open(box, using: key)
            }
        }
    }

    /// Big-endian increment, matching Go's `IncreaseNonce`.
    private func advanceNonce() {
        for i in stride(from: 11, through: 0, by: -1) {
            nonce[i] &+= 1
            if nonce[i] != 0 { return }
        }
    }
}

// MARK: - Header codec

/// Encodes/decodes the 5-byte TLS-record-style framing header.
private enum VLESSHeader {
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

/// Two-byte big-endian length helpers (Go's `EncodeLength`/`DecodeLength`).
private enum VLESSLength {
    static func encode(_ value: Int) -> Data {
        Data([UInt8(value >> 8), UInt8(value & 0xFF)])
    }
    static func decode(_ bytes: Data) -> Int {
        return (Int(bytes[bytes.startIndex]) << 8) | Int(bytes[bytes.startIndex + 1])
    }
}

// MARK: - Padding scheduler

/// Padding length/gap spec parser; each segment is `prob-min-max` (matches Go's `ParsePadding`).
struct VLESSEncryptionPadding {
    /// Length specs (probability, min, max).
    let lengths: [(Int, Int, Int)]
    /// Gap specs (probability, min ms, max ms). Sleeps between fragments.
    let gaps: [(Int, Int, Int)]

    /// Default schedule when no spec is supplied (matches Go's `CreatPadding` fallback).
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
private enum VLESSNfsPublicKey {
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

// MARK: - VLESSEncryptionClient (matches Go's ClientInstance)

/// Per-dial state for VLESS encryption; produces a `VLESSEncryptedConnection` per dial.
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
    /// 0-RTT cache key for this `(host, port, config)`.
    private let cacheKey: String
    /// Always true on Apple platforms — every iOS 26 device has hardware AES-GCM.
    private let useAES = true

    init(config: VLESSEncryptionConfig, host: String, port: UInt16) throws {
        var keys: [VLESSNfsPublicKey] = []
        var raw: [Data] = []
        var hashes: [Data] = []
        for k in config.publicKeys {
            keys.append(try VLESSNfsPublicKey.parse(k))
            raw.append(k)
            hashes.append(Blake3Hasher.hash(k))
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
    func handshake(
        over connection: ProxyConnection,
        completion: @escaping (Result<VLESSEncryptedConnection, Error>) -> Void
    ) {
        let cached: VLESSEncryption0RTTCache.Entry?
        if seconds > 0 {
            cached = VLESSEncryption0RTTCache.shared.lookup(key: cacheKey)
        } else {
            cached = nil
        }

        if let cached {
            do {
                try sendClientHello0RTT(over: connection, cached: cached, completion: completion)
            } catch {
                completion(.failure(error))
            }
            return
        }
        do {
            try sendClientHello1RTT(over: connection) { [self] result in
                switch result {
                case .failure(let error):
                    completion(.failure(error))
                case .success(let state):
                    self.readServerHello(over: connection, state: state, completion: completion)
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - Shared helpers

    private func generateIV() throws -> Data {
        var iv = Data(count: 16)
        let status = iv.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
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
            var pubOrCt = Data()
            switch nfsKeys[j] {
            case .x25519(let serverPub, _):
                let priv = Curve25519.KeyAgreement.PrivateKey()
                let shared = try priv.sharedSecretFromKeyAgreement(with: serverPub)
                nfsKey = shared.withUnsafeBytes { Data($0) }
                pubOrCt = priv.publicKey.rawRepresentation
            case .mlkem768(let serverPub, _):
                let result = try serverPub.encapsulate()
                nfsKey = result.sharedSecret.withUnsafeBytes { Data($0) }
                pubOrCt = result.encapsulated
            }
            if xorMode != .native {
                let ctr = try VLESSEncryptionCTR(key: nfsKeysRaw[j], iv: iv)
                pubOrCt = ctr.process(pubOrCt)
            }
            if let lastCTR {
                // XOR only the leading 32 bytes with the previous relay's keystream;
                // the chain-hash XOR continues that same stream.
                let bytes = [UInt8](pubOrCt)
                let xoredHead = lastCTR.process(Data(bytes[0..<32]))
                var combined = xoredHead
                combined.append(contentsOf: bytes[32..<bytes.count])
                pubOrCt = combined
            }
            relayBlock.append(pubOrCt)
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
        cached: VLESSEncryption0RTTCache.Entry,
        completion: @escaping (Result<VLESSEncryptedConnection, Error>) -> Void
    ) throws {
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
        let conn = VLESSEncryptedConnection(
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
        completion(.success(conn))
    }

    // MARK: - 1-RTT client hello

    /// Mid-handshake state passed from `sendClientHello1RTT` to `readServerHello`.
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
        over connection: ProxyConnection,
        completion: @escaping (Result<InFlightHandshake, Error>) -> Void
    ) throws {
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
        sendFragments(
            over: connection,
            buffer: clientHello,
            lengths: fragmentLengths,
            gaps: paddingGaps,
            index: 0
        ) { error in
            if let error {
                completion(.failure(error))
            } else {
                completion(.success(state))
            }
        }
    }

    /// Recursively send `buffer` in `lengths`-sized chunks, sleeping `gaps` between them.
    private func sendFragments(
        over connection: ProxyConnection,
        buffer: Data,
        lengths: [Int],
        gaps: [TimeInterval],
        index: Int,
        completion: @escaping (Error?) -> Void
    ) {
        if index >= lengths.count {
            if !buffer.isEmpty {
                connection.sendRaw(data: buffer, completion: completion)
            } else {
                completion(nil)
            }
            return
        }
        let length = min(lengths[index], buffer.count)
        let head = buffer.prefix(length)
        let tail = buffer.suffix(from: buffer.startIndex + length)

        let proceed: () -> Void = { [self] in
            let gap = index < gaps.count ? gaps[index] : 0
            if gap > 0 {
                DispatchQueue.global().asyncAfter(deadline: .now() + gap) {
                    self.sendFragments(
                        over: connection,
                        buffer: Data(tail),
                        lengths: lengths,
                        gaps: gaps,
                        index: index + 1,
                        completion: completion
                    )
                }
            } else {
                self.sendFragments(
                    over: connection,
                    buffer: Data(tail),
                    lengths: lengths,
                    gaps: gaps,
                    index: index + 1,
                    completion: completion
                )
            }
        }

        if !head.isEmpty {
            connection.sendRaw(data: Data(head)) { error in
                if let error { completion(error); return }
                proceed()
            }
        } else {
            proceed()
        }
    }

    // MARK: - Server hello

    /// Read server PFS hello + ticket + padding, derive session keys, return a ready connection.
    private func readServerHello(
        over connection: ProxyConnection,
        state: InFlightHandshake,
        completion: @escaping (Result<VLESSEncryptedConnection, Error>) -> Void
    ) {
        let reader = VLESSEncryptionByteReader(connection: connection)
        reader.readExact(VLESSWire.pfsServerHelloLength) { [self] result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let sealedServerPfs):
                do {
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

                    // Both AEADs are keyed on *plaintext* PFS public bytes (Go's
                    // `encryptedPfsPublicKey` is already decrypted in place when used).
                    let writeAEAD = VLESSEncryptionAEAD(
                        context: state.pfsClientPublicKey, key: unitedKey, useAES: useAES
                    )
                    let readAEAD = VLESSEncryptionAEAD(
                        context: serverPfsPublic, key: unitedKey, useAES: useAES
                    )

                    self.readTicketAndPadding(
                        reader: reader,
                        connection: connection,
                        state: state,
                        pfsKey: pfsKey,
                        unitedKey: unitedKey,
                        writeAEAD: writeAEAD,
                        readAEAD: readAEAD,
                        completion: completion
                    )
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    private func readTicketAndPadding(
        reader: VLESSEncryptionByteReader,
        connection: ProxyConnection,
        state: InFlightHandshake,
        pfsKey: Data,
        unitedKey: Data,
        writeAEAD: VLESSEncryptionAEAD,
        readAEAD: VLESSEncryptionAEAD,
        completion: @escaping (Result<VLESSEncryptedConnection, Error>) -> Void
    ) {
        reader.readExact(VLESSWire.encryptedTicketLength) { [self] result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let sealedTicket):
                let ticketPayload: Data
                do {
                    ticketPayload = try readAEAD.open(sealedTicket, additionalData: nil)
                } catch {
                    completion(.failure(error))
                    return
                }
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
                reader.readExact(VLESSWire.sealedLengthFrame) { result in
                    switch result {
                    case .failure(let error):
                        completion(.failure(error))
                    case .success(let sealedLength):
                        do {
                            let lenBytes = try readAEAD.open(sealedLength, additionalData: nil)
                            // Decoded value is the SEALED body size (plaintext + tag).
                            guard lenBytes.count >= 2 else {
                                throw VLESSEncryptionError.framingError("server sealed length frame too short: \(lenBytes.count) bytes")
                            }
                            let sealedPaddingBodySize = VLESSLength.decode(lenBytes)
                            // Over-read bytes are padding tail, always unmasked (written
                            // before the server wrapped with XorConn); carry them over.
                            let leftover = reader.drain()

                            // inSkip covers padding tail still on the wire; leftover bytes
                            // bypass XorConn via carryOverBytes, so don't skip them again.
                            let xorConnection: VLESSXORConnection?
                            let transport: ProxyConnection
                            if self.xorMode == .random {
                                let xor = VLESSXORConnection(
                                    inner: connection,
                                    outCTR: try VLESSEncryptionCTR(key: unitedKey, iv: state.iv),
                                    inCTR: try VLESSEncryptionCTR(key: unitedKey, iv: Data(sealedTicket.prefix(16))),
                                    outSkip: 0,
                                    inSkip: max(0, sealedPaddingBodySize - leftover.count)
                                )
                                xorConnection = xor
                                transport = xor
                            } else {
                                xorConnection = nil
                                transport = connection
                            }
                            let conn = VLESSEncryptedConnection(
                                inner: transport,
                                writeAEAD: writeAEAD,
                                readAEAD: readAEAD,
                                unitedKey: unitedKey,
                                useAES: self.useAES,
                                preludeBytes: nil,
                                pendingServerPaddingLength: sealedPaddingBodySize,
                                carryOverBytes: leftover,
                                xorConnection: xorConnection,
                                zeroRTTState: nil
                            )
                            completion(.success(conn))
                        } catch {
                            completion(.failure(error))
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Byte reader (buffered fixed-size receive helper)

/// Buffers a ProxyConnection's chunked `receiveRaw` behind a fixed-size `readExact(N)` API.
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
private final class VLESSEncryptionByteReader {
    let connection: ProxyConnection
    private var buffer = Data()
    private let lock = UnfairLock()

    init(connection: ProxyConnection) {
        self.connection = connection
    }

    func readExact(_ count: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        lock.lock()
        if buffer.count >= count {
            let head = buffer.prefix(count)
            buffer.removeFirst(count)
            lock.unlock()
            completion(.success(Data(head)))
            return
        }
        lock.unlock()
        connection.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(.failure(VLESSEncryptionError.connectionClosed))
                return
            }
            if let error { completion(.failure(error)); return }
            guard let data, !data.isEmpty else {
                completion(.failure(VLESSEncryptionError.connectionClosed))
                return
            }
            self.lock.lock()
            self.buffer.append(data)
            self.lock.unlock()
            self.readExact(count, completion: completion)
        }
    }

    func drain() -> Data {
        lock.withLock {
            let snapshot = buffer
            buffer.removeAll(keepingCapacity: true)
            return snapshot
        }
    }
}

// MARK: - VLESSEncryptedConnection (matches Go's CommonConn)

/// AEAD-framed wrapper around an inner ProxyConnection: application bytes travel
/// as TLS-1.3-style records (5-byte header + sealed payload), with a BLAKE3 rekey
/// when the nonce wraps.
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
    private weak var xorConnection: VLESSXORConnection?
    private var writeAEAD: VLESSEncryptionAEAD
    private var readAEAD: VLESSEncryptionAEAD?
    private let unitedKey: Data
    private let useAES: Bool

    /// 0-RTT hello blob prepended to the first outbound record, then cleared.
    private var preludeBytes: Data?

    /// Server handshake-tail padding to drain before app data (1-RTT only).
    private var pendingServerPaddingLength: Int

    /// nil for 1-RTT.
    private let zeroRTTState: ZeroRTTState?
    /// The 0-RTT-rejection signal only counts on the *first* record; once any
    /// record opens cleanly, the ticket was accepted.
    private var firstRecordSeen = false

    /// Plaintext left over from a record larger than the caller's chunk; drained first.
    private var plaintextBuffer = Data()
    private let recvLock = UnfairLock()
    private let sendLock = UnfairLock()
    /// Partial-record buffer; seeded with the handshake reader's leftover bytes.
    private var inboundBuffer: Data

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
        self.xorConnection = xorConnection
        self.writeAEAD = writeAEAD
        self.readAEAD = readAEAD
        self.useAES = useAES
        self.unitedKey = unitedKey
        self.preludeBytes = preludeBytes
        self.inboundBuffer = carryOverBytes
        self.pendingServerPaddingLength = pendingServerPaddingLength
        self.zeroRTTState = zeroRTTState
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    // MARK: Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        if data.isEmpty { completion(nil); return }
        do {
            let frames = try buildOutboundFrames(plaintext: data)
            inner.sendRaw(data: frames, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    private func buildOutboundFrames(plaintext: Data) throws -> Data {
        return try sendLock.withLock {
            var output = Data()
            if let prelude = self.preludeBytes {
                output.append(prelude)
                self.preludeBytes = nil
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
                let willRekey = self.writeAEAD.nonceIsAtMax
                let sealed = try self.writeAEAD.seal(chunk, additionalData: header)
                output.append(header)
                output.append(sealed)
                if willRekey {
                    var ctx = header
                    ctx.append(sealed)
                    self.writeAEAD = VLESSEncryptionAEAD(context: ctx, key: self.unitedKey, useAES: self.useAES)
                }
                offset += chunkSize
            }
            return output
        }
    }

    // MARK: Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        // 0-RTT: readAEAD is unknown until the server random arrives.
        if readAEAD == nil {
            establishReadAEAD { [weak self] error in
                guard let self else {
                    completion(nil, VLESSEncryptionError.connectionClosed); return
                }
                if let error { completion(nil, error); return }
                self.receiveAfterReadAEAD(completion: completion)
            }
            return
        }
        receiveAfterReadAEAD(completion: completion)
    }

    private func receiveAfterReadAEAD(completion: @escaping (Data?, Error?) -> Void) {
        recvLock.lock()
        if !plaintextBuffer.isEmpty {
            let snapshot = plaintextBuffer
            plaintextBuffer.removeAll(keepingCapacity: true)
            recvLock.unlock()
            completion(snapshot, nil)
            return
        }
        recvLock.unlock()
        pumpRecord(completion: completion)
    }

    /// Read 16-byte server random, derive the read AEAD, and install the inbound XOR CTR for random mode.
    private func establishReadAEAD(completion: @escaping (Error?) -> Void) {
        let needed = 16
        recvLock.lock()
        if inboundBuffer.count >= needed {
            let serverRandom = Data(inboundBuffer.prefix(needed))
            inboundBuffer.removeFirst(needed)
            recvLock.unlock()
            do {
                try installReadAEAD(serverRandom: serverRandom)
                completion(nil)
            } catch {
                completion(error)
            }
            return
        }
        recvLock.unlock()
        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(VLESSEncryptionError.connectionClosed); return
            }
            if let error { completion(error); return }
            guard let data, !data.isEmpty else {
                completion(VLESSEncryptionError.connectionClosed); return
            }
            self.recvLock.withLock { self.inboundBuffer.appendCompacting(data) }
            self.establishReadAEAD(completion: completion)
        }
    }

    private func installReadAEAD(serverRandom: Data) throws {
        let aead = VLESSEncryptionAEAD(context: serverRandom, key: unitedKey, useAES: useAES)
        recvLock.withLock { self.readAEAD = aead }
        if let xor = xorConnection {
            xor.installInboundCTR(try VLESSEncryptionCTR(key: unitedKey, iv: serverRandom))
        }
    }

    private func pumpRecord(completion: @escaping (Data?, Error?) -> Void) {
        // Drain server handshake-tail padding first (one-shot per connection).
        if pendingServerPaddingLength > 0 {
            let needed = pendingServerPaddingLength
            recvLock.lock()
            if inboundBuffer.count >= needed {
                let blob = Data(inboundBuffer.prefix(needed))
                inboundBuffer.removeFirst(needed)
                let aead = readAEAD
                recvLock.unlock()
                do {
                    _ = try aead!.open(blob, additionalData: nil)
                    recvLock.withLock { self.pendingServerPaddingLength = 0 }
                    pumpRecord(completion: completion)
                } catch {
                    completion(nil, error)
                }
                return
            }
            recvLock.unlock()
            inner.receiveRaw { [weak self] data, error in
                guard let self else {
                    completion(nil, VLESSEncryptionError.connectionClosed); return
                }
                if let error { completion(nil, error); return }
                guard let data, !data.isEmpty else {
                    completion(nil, error); return
                }
                self.recvLock.withLock { self.inboundBuffer.appendCompacting(data) }
                self.pumpRecord(completion: completion)
            }
            return
        }

        recvLock.lock()
        if inboundBuffer.count < VLESSWire.headerLength {
            recvLock.unlock()
            inner.receiveRaw { [weak self] data, error in
                guard let self else {
                    completion(nil, VLESSEncryptionError.connectionClosed); return
                }
                if let error { completion(nil, error); return }
                guard let data, !data.isEmpty else {
                    completion(nil, error); return
                }
                self.recvLock.withLock { self.inboundBuffer.appendCompacting(data) }
                self.pumpRecord(completion: completion)
            }
            return
        }

        let headerBytes = Array(inboundBuffer.prefix(VLESSWire.headerLength))
        let payloadLength: Int
        do {
            payloadLength = try VLESSHeader.decode(headerBytes)
        } catch {
            recvLock.unlock()
            // 0-RTT rejection: the server wrote noise instead of a valid record;
            // invalidate this ticket so a future dial re-handshakes.
            if !firstRecordSeen, let z = zeroRTTState {
                VLESSEncryption0RTTCache.shared.invalidate(key: z.cacheKey, matching: z.pfsKey)
                completion(nil, VLESSEncryptionError.handshakeFailed("new handshake needed"))
                return
            }
            completion(nil, error)
            return
        }
        let recordTotal = VLESSWire.headerLength + payloadLength
        if inboundBuffer.count < recordTotal {
            recvLock.unlock()
            inner.receiveRaw { [weak self] data, error in
                guard let self else {
                    completion(nil, VLESSEncryptionError.connectionClosed); return
                }
                if let error { completion(nil, error); return }
                guard let data, !data.isEmpty else {
                    completion(nil, error); return
                }
                self.recvLock.withLock { self.inboundBuffer.appendCompacting(data) }
                self.pumpRecord(completion: completion)
            }
            return
        }

        let recordBytes = Data(inboundBuffer.prefix(recordTotal))
        inboundBuffer.removeFirst(recordTotal)
        let aead = readAEAD
        recvLock.unlock()

        do {
            let header = Data(recordBytes.prefix(VLESSWire.headerLength))
            let sealedPayload = recordBytes.suffix(payloadLength)
            let willRekey = aead!.nonceIsAtMax
            // Header bytes are the AAD for this record.
            let plaintext = try aead!.open(Data(sealedPayload), additionalData: header)
            firstRecordSeen = true
            if willRekey {
                var ctx = Data(header)
                ctx.append(Data(sealedPayload))
                let newAEAD = VLESSEncryptionAEAD(context: ctx, key: unitedKey, useAES: useAES)
                recvLock.withLock { self.readAEAD = newAEAD }
            }
            completion(plaintext, nil)
        } catch {
            completion(nil, error)
        }
    }

    // MARK: Vision direct-copy (bypass AEAD)

    // Vision direct copy peels only our AEAD layer (Xray-core's `UnwrapRawConn`);
    // delegating to `inner` keeps random-mode XOR masking and outer TLS intact.

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        inner.sendRaw(data: data)
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        // Flush bytes over-read past the last AEAD record; `inner.receiveRaw` would not replay them.
        recvLock.lock()
        if !inboundBuffer.isEmpty {
            let leftover = inboundBuffer
            inboundBuffer = Data()
            recvLock.unlock()
            completion(leftover, nil)
            return
        }
        recvLock.unlock()
        inner.receiveRaw(completion: completion)
    }

    override func cancel() {
        inner.cancel()
    }
}
