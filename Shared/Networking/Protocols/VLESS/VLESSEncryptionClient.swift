//
//  VLESSEncryptionClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/10/26.
//

import Foundation
import CryptoKit

// MARK: - Errors

enum VLESSEncryptionError: Error, LocalizedError {
    /// The config asked for a feature this build doesn't implement yet
    /// (multi-key relays, xorpub/random XOR modes, 0-RTT cache, etc.).
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

/// AEAD framing constants (matches `proxy/vless/encryption/common.go`).
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

/// Wraps a CryptoKit AEAD with a 12-byte big-endian-incrementing nonce, mirroring
/// the Go `AEAD` struct in `proxy/vless/encryption/common.go`. Each `seal`/`open`
/// without an explicit nonce advances the internal counter by one.
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
private final class VLESSEncryptionAEAD {
    let key: SymmetricKey
    let useAES: Bool
    private var nonce: [UInt8] = Array(repeating: 0, count: 12)

    /// Derive a fresh AEAD from `(ctx, key)` using BLAKE3 key derivation,
    /// matching Go's `NewAEAD(ctx, key, useAES)`. The context bytes are
    /// hashed verbatim — they're typically a random IV or a previous record's
    /// raw bytes, so we cannot route them through a String.
    init(context: Data, key: Data, useAES: Bool) {
        let derived = Blake3Hasher.deriveKey(
            contextBytes: context,
            input: key,
            count: 32
        )
        self.key = SymmetricKey(data: derived)
        self.useAES = useAES
    }

    /// Whether the *next* seal/open will use the maximum nonce, which
    /// triggers an AEAD rekey on the call after that.
    var nonceIsAtMax: Bool {
        for byte in nonce where byte != 0xFF { return false }
        return true
    }

    func seal(_ plaintext: Data, additionalData: Data?) throws -> Data {
        // Match Go's `IncreaseNonce(a.Nonce[:])` semantics: increment first,
        // then use. The very first sealed message uses nonce 1, not 0.
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

    /// Open a sealed buffer (`ciphertext + tag`). Same nonce semantics as
    /// `seal` — increments before use so the first opened message uses 1.
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

/// Encode/decode the 5-byte TLS-record-style framing header used by CommonConn.
private enum VLESSHeader {
    static func encode(into buffer: inout Data, payloadLength: Int) {
        buffer.append(VLESSWire.recordTypeApplicationData)
        buffer.append(VLESSWire.recordVersionMajor)
        buffer.append(VLESSWire.recordVersionMinor)
        buffer.append(UInt8(payloadLength >> 8))
        buffer.append(UInt8(payloadLength & 0xFF))
    }

    /// Returns the declared payload length, or throws if the header is malformed.
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

/// Two-byte big-endian length helpers used by the handshake's sealed length
/// prefixes (matches Go's `EncodeLength`/`DecodeLength`).
private enum VLESSLength {
    static func encode(_ value: Int) -> Data {
        Data([UInt8(value >> 8), UInt8(value & 0xFF)])
    }
    static func decode(_ bytes: Data) -> Int {
        precondition(bytes.count >= 2)
        return (Int(bytes[bytes.startIndex]) << 8) | Int(bytes[bytes.startIndex + 1])
    }
}

// MARK: - Padding scheduler

/// Padding length/gap spec parser, matches `ParsePadding`/`CreatPadding` in
/// `proxy/vless/encryption/common.go`. Each segment is `prob-min-max`.
struct VLESSEncryptionPadding {
    /// Length specs (probability, min, max).
    let lengths: [(Int, Int, Int)]
    /// Gap specs (probability, min ms, max ms). Sleeps between fragments.
    let gaps: [(Int, Int, Int)]

    /// Built-in default schedule fired when the user supplies no padding spec.
    /// Matches Go's `CreatPadding` fallback.
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

    /// Materialize a concrete padding schedule for one handshake.
    /// Returns `(totalLength, perFragmentLengths, perFragmentGaps)`.
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

    /// Number of bytes contributed to the relay block by this key.
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

/// Per-dial state for VLESS encryption. Owns the parsed NFS keys, the
/// padding schedule, and the (host, port)-scoped 0-RTT cache key; produces
/// a fresh ``VLESSEncryptedConnection`` per dial via ``handshake(over:completion:)``.
///
/// Supports the full Go feature set:
/// - Multi-key NFS relay chains (each relay's pubkey or KEM ciphertext is
///   followed by the BLAKE3 hash of the next relay's pubkey, XOR'd with a
///   CTR keyed on the current relay's nfsKey so an MITM can't swap relays).
/// - `xorpub` / `random` XOR modes (`xorpub` masks the relay public keys;
///   `random` adds a post-handshake XorConn that masks TLS record headers).
/// - 0-RTT ticket cache (process-wide; see ``VLESSEncryption0RTTCache``).
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated final class VLESSEncryptionClient {
    private let nfsKeys: [VLESSNfsPublicKey]
    /// Raw public-key bytes for each relay, in chain order. Used as the
    /// keying material for `xorpub`/`random` CTR streams over the relay's
    /// own pubkey, and as the BLAKE3 input for chain-hashes.
    private let nfsKeysRaw: [Data]
    /// BLAKE3-256 hash of each relay's raw pubkey. The j-th relay's slot
    /// in the chain ends with `hash32[j+1]` XOR'd by the j-th `nfsKey`'s
    /// CTR — that's what lets the server verify the chain order.
    private let nfsKeysHash32: [Data]
    private let padding: VLESSEncryptionPadding
    private let xorMode: VLESSEncryptionConfig.XORMode
    private let seconds: UInt32
    /// Composite key used to look up / store / invalidate the 0-RTT cache
    /// entry for this `(host, port, config)`. Stable for the lifetime of
    /// the client.
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

    /// Perform the handshake over `connection`. Decides 0-RTT vs 1-RTT
    /// based on whether the config opted into 0-RTT *and* a valid cached
    /// ticket is available.
    func handshake(
        over connection: ProxyConnection,
        completion: @escaping (Result<VLESSEncryptedConnection, Error>) -> Void
    ) {
        // Total relay block size: each non-last relay contributes pubkey +
        // 32 bytes of next-relay hash; the last contributes just pubkey.
        // Matches `i.RelaysLength` in client.go (which is added to 16 to
        // form `ivAndRealysLength`).
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

    /// Generate a 16-byte random IV. Throws on RNG failure.
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

    /// Run the multi-relay NFS key-exchange loop and return both the
    /// concatenated relay block (which goes on the wire after the IV) and
    /// the final `nfsKey` (the shared secret of the *last* relay, used as
    /// the AEAD key downstream).
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
                let ctr = VLESSEncryptionCTR(key: nfsKeysRaw[j], iv: iv)
                pubOrCt = ctr.process(pubOrCt)
            }
            if let lastCTR {
                // XOR only the first 32 bytes of this relay's pubkey/CT
                // with the previous nfsKey's keystream (continuing from
                // where the chain-hash XOR left off).
                let bytes = [UInt8](pubOrCt)
                let xoredHead = lastCTR.process(Data(bytes[0..<32]))
                var combined = xoredHead
                combined.append(contentsOf: bytes[32..<bytes.count])
                pubOrCt = combined
            }
            relayBlock.append(pubOrCt)
            if j < nfsKeys.count - 1 {
                // Append BLAKE3 hash of next relay's pubkey, XOR'd with a
                // fresh CTR keyed on the current relay's nfsKey. This is
                // what lets the *next* server in the chain verify it was
                // actually expected (the hash binds the chain).
                let newCTR = VLESSEncryptionCTR(key: nfsKey, iv: iv)
                relayBlock.append(newCTR.process(nfsKeysHash32[j + 1]))
                lastCTR = newCTR
            }
        }
        return (relayBlock, nfsKey)
    }

    // MARK: - 0-RTT client hello

    /// Build and dispatch a 0-RTT client hello using a cached ticket.
    ///
    /// The wire layout is:
    /// `iv || relays || seal(EncodeLength(32)) || seal(ticket)`
    /// — only 18 + 32 = 50 bytes more than 1-RTT's prefix, with no PFS
    /// exchange. The cached `pfsKey` plus the freshly-derived `nfsKey`
    /// form the new connection's united key. The first application
    /// record gets prepended with the full hello via ``preludeBytes``.
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
            // outSkip = preludeBytes length: skip XOR across the unmasked
            // pre-write blob, then mask each subsequent 5-byte record
            // header. inSkip = 16: server sends 16 random bytes first
            // (its "server random") before any masked record.
            let xor = VLESSXORConnection(
                inner: connection,
                outCTR: VLESSEncryptionCTR(key: unitedKey, iv: iv),
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

    /// Build a full 1-RTT client hello, send it (in padded fragments per
    /// the schedule), and pass the partially-set-up state to `completion`.
    private func sendClientHello1RTT(
        over connection: ProxyConnection,
        completion: @escaping (Result<InFlightHandshake, Error>) -> Void
    ) throws {
        let iv = try generateIV()
        let (relayBlock, nfsKey) = try buildRelayBlock(iv: iv)
        let nfsAEAD = VLESSEncryptionAEAD(context: iv, key: nfsKey, useAES: useAES)

        // PFS client hello: ML-KEM-768 encap key + X25519 public key, sealed.
        let mlkemPriv = try MLKEM768.PrivateKey()
        let x25519Priv = Curve25519.KeyAgreement.PrivateKey()
        var pfsPublic = Data()
        pfsPublic.append(mlkemPriv.publicKey.rawRepresentation)        // 1184 bytes
        pfsPublic.append(x25519Priv.publicKey.rawRepresentation)       // 32 bytes
        precondition(pfsPublic.count == VLESSWire.pfsClientHelloPayloadLength)

        // Length frames encode the SEALED body size (plaintext + AEAD tag),
        // matching `EncodeLength(pfsKeyExchangeLength - 18)` in Go's client.go.
        // The server reads exactly that many bytes off the wire and opens the
        // whole buffer as ciphertext+tag — encoding the plaintext size leaves
        // the tag bytes unread and triggers an AEAD failure / connection reset.
        let sealedLengthFrame = try nfsAEAD.seal(
            VLESSLength.encode(VLESSWire.pfsClientHelloPayloadLength + VLESSWire.aeadTagLength),
            additionalData: nil
        )
        let sealedPfsPublic = try nfsAEAD.seal(pfsPublic, additionalData: nil)

        // Padding section (defaults if no spec).
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

        // Send the bytes in fragments per the padding schedule, sleeping
        // between fragments. The first fragment is grown by paddingLens[0]
        // so the very first bytes on the wire still make plausible sense
        // on capture (matches Go's loop in client.go:142-153).
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

    /// Recursively send `buffer` in chunks driven by `lengths` (interleaved with
    /// `gaps` sleeps). All work happens on the connection's send callback chain.
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

    /// Read the server's PFS public key + ticket + padding, derive PFS keys,
    /// and hand back a ready-to-use ``VLESSEncryptedConnection``.
    private func readServerHello(
        over connection: ProxyConnection,
        state: InFlightHandshake,
        completion: @escaping (Result<VLESSEncryptedConnection, Error>) -> Void
    ) {
        let reader = VLESSEncryptionByteReader(connection: connection)
        // 1. Sealed PFS server hello: 1088 (ML-KEM ct) + 32 (X25519 pub) + 16 tag.
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

                    // Both sides key the AEAD with the *plaintext* PFS pub
                    // bytes. Go's variable name `encryptedPfsPublicKey` is
                    // misleading: `nfsAEAD.Open(buf[:0], ..., buf, nil)` writes
                    // the plaintext back into the same buffer, so by the time
                    // it's used as the AEAD context it's already decrypted.
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
                // Cache the new ticket if both sides opted in. The first
                // two bytes of the ticket plaintext are a big-endian
                // seconds value picked by the server (see server.go's
                // `EncodeLength(int(seconds))`); zero means "no resumption".
                //
                // Go's `i.Ticket = encryptedTicket[:16]` is misleading:
                // by that point the buffer has been overwritten with the
                // decrypted plaintext (Open writes into `encryptedTicket[:0]`),
                // so the cached value is the *plaintext* 16-byte ticket
                // body that gets re-sealed on the 0-RTT replay.
                if seconds > 0, ticketPayload.count >= 16 {
                    let serverSeconds = VLESSLength.decode(ticketPayload)
                    if serverSeconds > 0 {
                        let expire = Date().addingTimeInterval(TimeInterval(serverSeconds))
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
                            // The decoded value is the SEALED body size (matches
                            // Go's `EncodeLength(paddingLength - 18)`), so it
                            // already accounts for the 16-byte AEAD tag.
                            let sealedPaddingBodySize = VLESSLength.decode(lenBytes)
                            // Anything the reader buffered past the last
                            // readExact() must carry over to the encrypted
                            // connection. Since the server doesn't send
                            // any post-handshake bytes until it has read
                            // the client's first request, the leftover is
                            // always a prefix of the padding tail (never
                            // app data). It's also unmasked — the server
                            // wrote padding to the raw conn *before* it
                            // wrapped its end with XorConn.
                            let leftover = reader.drain()

                            // For random mode, wrap the inner connection
                            // with XorConn now that the handshake is done.
                            // inSkip accounts for the padding tail bytes
                            // *still on the wire* — we already siphoned
                            // `leftover.count` of them into carryOverBytes,
                            // which bypasses XorConn entirely, so the
                            // XorConn must not skip those again.
                            let xorConnection: VLESSXORConnection?
                            let transport: ProxyConnection
                            if self.xorMode == .random {
                                let xor = VLESSXORConnection(
                                    inner: connection,
                                    outCTR: VLESSEncryptionCTR(key: unitedKey, iv: state.iv),
                                    inCTR: VLESSEncryptionCTR(key: unitedKey, iv: Data(sealedTicket.prefix(16))),
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

/// Wraps a ProxyConnection's chunked `receiveRaw` into a fixed-size
/// `readExact(N) -> Data` API. Buffers between calls so leftover bytes from
/// one read don't get dropped.
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

    /// Drain whatever bytes have been buffered but not yet handed out.
    func drain() -> Data {
        lock.withLock {
            let snapshot = buffer
            buffer.removeAll(keepingCapacity: true)
            return snapshot
        }
    }
}

// MARK: - VLESSEncryptedConnection (matches Go's CommonConn)

/// AEAD-framed wrapper around an inner ``ProxyConnection``. Application bytes
/// pass through TLS-1.3-style records (5-byte header + sealed payload), with
/// a BLAKE3 rekey when the AEAD nonce hits its maximum value.
///
/// Supports two construction modes:
/// - 1-RTT: `readAEAD` is set, `preludeBytes` is nil, `pendingServerPaddingLength`
///   carries the server's handshake-tail padding length.
/// - 0-RTT: `readAEAD` is nil at first — the client doesn't know the server
///   random yet. The first ``receiveRaw`` reads 16 bytes from `inner`,
///   derives the read AEAD (and the inbound XOR CTR for `random` mode), then
///   proceeds. `preludeBytes` holds the full handshake hello and gets
///   prepended to the very first outbound record by ``buildOutboundFrames``.
@available(iOS 26.0, macOS 26.0, tvOS 26.0, *)
nonisolated final class VLESSEncryptedConnection: ProxyConnection {
    /// Snapshot of the cache entry used to mount a 0-RTT handshake. Stored
    /// so that on first-record decode failure (i.e., the server rejected
    /// the ticket and wrote noise) we can invalidate the exact entry we
    /// took — and not stomp on a newer ticket that raced us.
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

    /// Bytes prepended to the very first outbound record (0-RTT pre-write
    /// blob). Cleared as soon as it's been emitted.
    private var preludeBytes: Data?

    /// Bytes the server promised in its handshake-tail padding; consumed and
    /// discarded on the first application read. Only set for 1-RTT.
    private var pendingServerPaddingLength: Int

    /// 0-RTT cache reference for invalidation on the first-record header
    /// failure path. nil for 1-RTT.
    private let zeroRTTState: ZeroRTTState?
    /// Tracks whether we've decrypted any inbound application record yet.
    /// The 0-RTT-rejection signal only counts on the *first* record; once
    /// any record opens cleanly, the ticket was accepted.
    private var firstRecordSeen = false

    /// Buffered plaintext from a previous receiveRaw whose record was larger
    /// than the caller's requested chunk. Drained before pulling new records.
    private var plaintextBuffer = Data()
    private let recvLock = UnfairLock()
    private let sendLock = UnfairLock()
    /// Buffer for partial records read from the inner transport. Seeded at
    /// construction with any bytes the handshake reader had left over.
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
                // Header carries (chunkSize + tag) length per Go's EncodeHeader.
                var header = Data()
                VLESSHeader.encode(into: &header, payloadLength: chunkSize + VLESSWire.aeadTagLength)
                let willRekey = self.writeAEAD.nonceIsAtMax
                // The header is the AAD for this record (matches Go's
                // `c.AEAD.Seal(headerAndData[:5], nil, b, headerAndData[:5])`).
                let sealed = try self.writeAEAD.seal(chunk, additionalData: header)
                output.append(header)
                output.append(sealed)
                if willRekey {
                    // Rekey: derive a fresh AEAD with context = (header || sealed payload).
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
        // 0-RTT path: derive readAEAD from the 16-byte server random
        // before pumping any record. The server random is also wired into
        // the inbound XOR CTR for `random` mode.
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

    /// Read 16 bytes of server random from the inner connection, derive the
    /// peer AEAD, and (for random mode) install the inbound XOR CTR. Called
    /// once per 0-RTT connection on the first receive.
    private func establishReadAEAD(completion: @escaping (Error?) -> Void) {
        let needed = 16
        recvLock.lock()
        if inboundBuffer.count >= needed {
            let serverRandom = Data(inboundBuffer.prefix(needed))
            inboundBuffer.removeFirst(needed)
            recvLock.unlock()
            installReadAEAD(serverRandom: serverRandom)
            completion(nil)
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
            self.recvLock.withLock { self.inboundBuffer.append(data) }
            self.establishReadAEAD(completion: completion)
        }
    }

    private func installReadAEAD(serverRandom: Data) {
        let aead = VLESSEncryptionAEAD(context: serverRandom, key: unitedKey, useAES: useAES)
        recvLock.withLock { self.readAEAD = aead }
        if let xor = xorConnection {
            xor.installInboundCTR(VLESSEncryptionCTR(key: unitedKey, iv: serverRandom))
        }
    }

    /// Pull bytes from `inner` until we have a full record (or the server
    /// padding tail), decrypt, and deliver the plaintext.
    private func pumpRecord(completion: @escaping (Data?, Error?) -> Void) {
        // Step 1: drain server-side handshake-tail padding (one-shot per conn).
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
                self.recvLock.withLock { self.inboundBuffer.append(data) }
                self.pumpRecord(completion: completion)
            }
            return
        }

        // Step 2: ensure we have at least 5 bytes for the record header.
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
                self.recvLock.withLock { self.inboundBuffer.append(data) }
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
            // 0-RTT rejection path: server wrote noise instead of an
            // application record. Invalidate the cached ticket and surface
            // a distinct error so a future caller can re-handshake.
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
                self.recvLock.withLock { self.inboundBuffer.append(data) }
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

    override func cancel() {
        inner.cancel()
    }
}
