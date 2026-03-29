import Foundation
import CryptoKit

/// TLS cipher suite constants (1.2 and 1.3)
enum TLSCipherSuite {
    // TLS 1.3
    static let TLS_AES_128_GCM_SHA256: UInt16 = 0x1301
    static let TLS_AES_256_GCM_SHA384: UInt16 = 0x1302
    static let TLS_CHACHA20_POLY1305_SHA256: UInt16 = 0x1303

    // TLS 1.2 ECDHE AEAD
    static let TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: UInt16 = 0xC02B
    static let TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: UInt16 = 0xC02C
    static let TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: UInt16 = 0xC02F
    static let TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: UInt16 = 0xC030
    static let TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: UInt16 = 0xCCA9
    static let TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: UInt16 = 0xCCA8

    // TLS 1.2 ECDHE CBC
    static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: UInt16 = 0xC009
    static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: UInt16 = 0xC00A
    static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: UInt16 = 0xC013
    static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: UInt16 = 0xC014
    static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: UInt16 = 0xC023
    static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: UInt16 = 0xC024
    static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: UInt16 = 0xC027
    static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: UInt16 = 0xC028

    // TLS 1.2 RSA AEAD
    static let TLS_RSA_WITH_AES_128_GCM_SHA256: UInt16 = 0x009C
    static let TLS_RSA_WITH_AES_256_GCM_SHA384: UInt16 = 0x009D

    // TLS 1.2 RSA CBC
    static let TLS_RSA_WITH_AES_128_CBC_SHA: UInt16 = 0x002F
    static let TLS_RSA_WITH_AES_256_CBC_SHA: UInt16 = 0x0035
    static let TLS_RSA_WITH_AES_128_CBC_SHA256: UInt16 = 0x003C
    static let TLS_RSA_WITH_AES_256_CBC_SHA256: UInt16 = 0x003D

    // MARK: - Cipher Suite Properties

    /// Whether this cipher suite uses ECDHE key exchange
    static func isECDHE(_ suite: UInt16) -> Bool {
        switch suite {
        case 0xC009, 0xC00A, 0xC013, 0xC014,
             0xC023, 0xC024, 0xC027, 0xC028,
             0xC02B, 0xC02C, 0xC02F, 0xC030,
             0xCCA8, 0xCCA9:
            return true
        default:
            return false
        }
    }

    /// Whether this cipher suite uses AEAD (GCM or ChaCha20-Poly1305) vs CBC+HMAC
    static func isAEAD(_ suite: UInt16) -> Bool {
        switch suite {
        case 0x1301, 0x1302, 0x1303,                   // TLS 1.3
             0xC02B, 0xC02C, 0xC02F, 0xC030,           // ECDHE GCM
             0xCCA8, 0xCCA9,                             // ECDHE ChaCha20
             0x009C, 0x009D:                             // RSA GCM
            return true
        default:
            return false
        }
    }

    /// Whether this cipher suite uses ChaCha20-Poly1305
    static func isChaCha20(_ suite: UInt16) -> Bool {
        switch suite {
        case 0x1303, 0xCCA8, 0xCCA9:
            return true
        default:
            return false
        }
    }

    /// Whether this cipher suite uses SHA-384 (vs SHA-256)
    static func usesSHA384(_ suite: UInt16) -> Bool {
        switch suite {
        case 0x1302,                                     // TLS 1.3 AES-256-GCM
             0xC02C, 0xC030,                             // ECDHE AES-256-GCM
             0xC024, 0xC028,                             // ECDHE AES-256-CBC-SHA384
             0x009D:                                     // RSA AES-256-GCM
            return true
        default:
            return false
        }
    }

    /// Encryption key length in bytes for TLS 1.2 cipher suites
    static func keyLength(_ suite: UInt16) -> Int {
        switch suite {
        // 32-byte key (AES-256 or ChaCha20)
        case 0xC00A, 0xC014, 0xC024, 0xC028,           // ECDHE AES-256-CBC
             0xC02C, 0xC030,                             // ECDHE AES-256-GCM
             0xCCA8, 0xCCA9,                             // ECDHE ChaCha20
             0x0035, 0x003D,                             // RSA AES-256-CBC
             0x009D,                                     // RSA AES-256-GCM
             0x1302, 0x1303:                             // TLS 1.3
            return 32
        // 16-byte key (AES-128)
        default:
            return 16
        }
    }

    /// IV length in bytes for TLS 1.2 cipher suites (implicit nonce for AEAD, full IV for CBC)
    static func ivLength(_ suite: UInt16) -> Int {
        if isChaCha20(suite) { return 12 }               // 12-byte implicit nonce
        if isAEAD(suite) { return 4 }                    // 4-byte implicit nonce (GCM)
        return 16                                         // 16-byte IV (AES-CBC block size)
    }

    /// MAC key length in bytes (0 for AEAD suites)
    static func macLength(_ suite: UInt16) -> Int {
        if isAEAD(suite) { return 0 }
        if usesSHA384(suite) { return 48 }                // HMAC-SHA384
        switch suite {
        case 0xC023, 0xC027, 0x003C, 0x003D:             // SHA256 MAC suites
            return 32
        default:
            return 20                                     // HMAC-SHA1
        }
    }
}

/// TLS 1.3 handshake traffic keys
struct TLSHandshakeKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
    let clientTrafficSecret: Data
    let serverTrafficSecret: Data
}

/// TLS 1.3 application traffic keys
struct TLSApplicationKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
}

/// TLS 1.3 key derivation utilities
struct TLS13KeyDerivation {
    let cipherSuite: UInt16

    init(cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) {
        self.cipherSuite = cipherSuite
    }

    /// Get hash output length based on cipher suite
    var hashLength: Int {
        return cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 48 : 32
    }

    /// Get encryption key length based on cipher suite (RFC 8446 §B.4)
    var keyLength: Int {
        switch cipherSuite {
        case TLSCipherSuite.TLS_AES_256_GCM_SHA384,
             TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return 32
        default:
            return 16
        }
    }

    // MARK: - HKDF Primitives

    func hkdfExtract(salt: Data, ikm: Data) -> (prk: Data, key: SymmetricKey) {
        let saltData = salt.isEmpty ? Data(repeating: 0, count: hashLength) : salt
        let key = SymmetricKey(data: saltData)

        let prk: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            prk = Data(HMAC<SHA384>.authenticationCode(for: ikm, using: key))
        } else {
            prk = Data(HMAC<SHA256>.authenticationCode(for: ikm, using: key))
        }
        return (prk, SymmetricKey(data: prk))
    }

    func hkdfExpand(key: SymmetricKey, info: Data, length: Int) -> Data {
        let hashLen = cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 48 : 32
        var output = Data(capacity: length + hashLen)
        var t = Data()
        var counter: UInt8 = 1
        // Pre-allocate input buffer with max capacity: hashLen + info.count + 1
        var input = Data(capacity: hashLen + info.count + 1)

        while output.count < length {
            input.removeAll(keepingCapacity: true)
            input.append(t)
            input.append(info)
            input.append(counter)

            if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
                t = Data(HMAC<SHA384>.authenticationCode(for: input, using: key))
            } else {
                t = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
            }
            output.append(t)
            counter += 1
        }

        return Data(output.prefix(length))
    }

    func hkdfExpandLabel(key: SymmetricKey, label: String, context: Data, length: Int) -> Data {
        let fullLabel = "tls13 " + label
        var hkdfLabel = Data()
        hkdfLabel.append(UInt8((length >> 8) & 0xFF))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(fullLabel.count))
        hkdfLabel.append(contentsOf: fullLabel.utf8)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)
        return hkdfExpand(key: key, info: hkdfLabel, length: length)
    }

    func deriveSecret(key: SymmetricKey, label: String, messages: Data) -> Data {
        let hashData: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            hashData = Data(SHA384.hash(data: messages))
        } else {
            hashData = Data(SHA256.hash(data: messages))
        }
        return hkdfExpandLabel(key: key, label: label, context: hashData, length: hashLength)
    }

    // MARK: - Public API

    /// Compute transcript hash
    func transcriptHash(_ messages: Data) -> Data {
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(SHA384.hash(data: messages))
        } else {
            return Data(SHA256.hash(data: messages))
        }
    }

    /// Derive TLS 1.3 handshake keys from shared secret
    func deriveHandshakeKeys(sharedSecret: Data, transcript: Data) -> (handshakeSecret: Data, keys: TLSHandshakeKeys) {
        let (_, earlyKey) = hkdfExtract(salt: Data(), ikm: Data(repeating: 0, count: hashLength))
        let derivedEarly = deriveSecret(key: earlyKey, label: "derived", messages: Data())
        let (hsPRK, hsKey) = hkdfExtract(salt: derivedEarly, ikm: sharedSecret)

        let clientHTS = deriveSecret(key: hsKey, label: "c hs traffic", messages: transcript)
        let clientHTSKey = SymmetricKey(data: clientHTS)
        let clientKey = hkdfExpandLabel(key: clientHTSKey, label: "key", context: Data(), length: keyLength)
        let clientIV = hkdfExpandLabel(key: clientHTSKey, label: "iv", context: Data(), length: 12)

        let serverHTS = deriveSecret(key: hsKey, label: "s hs traffic", messages: transcript)
        let serverHTSKey = SymmetricKey(data: serverHTS)
        let serverKey = hkdfExpandLabel(key: serverHTSKey, label: "key", context: Data(), length: keyLength)
        let serverIV = hkdfExpandLabel(key: serverHTSKey, label: "iv", context: Data(), length: 12)

        let keys = TLSHandshakeKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV,
            clientTrafficSecret: clientHTS,
            serverTrafficSecret: serverHTS
        )
        return (hsPRK, keys)
    }

    /// Derive application keys from the full transcript (including server Finished)
    func deriveApplicationKeys(handshakeSecret: Data, fullTranscript: Data) -> TLSApplicationKeys {
        let hsKey = SymmetricKey(data: handshakeSecret)
        let derivedHS = deriveSecret(key: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = hkdfExtract(salt: derivedHS, ikm: Data(repeating: 0, count: hashLength))

        let clientATS = deriveSecret(key: masterKey, label: "c ap traffic", messages: fullTranscript)
        let clientATSKey = SymmetricKey(data: clientATS)
        let clientKey = hkdfExpandLabel(key: clientATSKey, label: "key", context: Data(), length: keyLength)
        let clientIV = hkdfExpandLabel(key: clientATSKey, label: "iv", context: Data(), length: 12)

        let serverATS = deriveSecret(key: masterKey, label: "s ap traffic", messages: fullTranscript)
        let serverATSKey = SymmetricKey(data: serverATS)
        let serverKey = hkdfExpandLabel(key: serverATSKey, label: "key", context: Data(), length: keyLength)
        let serverIV = hkdfExpandLabel(key: serverATSKey, label: "iv", context: Data(), length: 12)

        return TLSApplicationKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV
        )
    }

    /// Compute Finished verify data for a given traffic secret (client or server).
    func computeFinishedVerifyData(trafficSecret: Data, transcript: Data) -> Data {
        let tsKey = SymmetricKey(data: trafficSecret)
        let finishedKey = hkdfExpandLabel(key: tsKey, label: "finished", context: Data(), length: hashLength)
        let transcriptHash = self.transcriptHash(transcript)

        let key = SymmetricKey(data: finishedKey)
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: key))
        } else {
            return Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: key))
        }
    }

    /// Compute Client Finished verify data (convenience wrapper).
    func computeFinishedVerifyData(clientTrafficSecret: Data, transcript: Data) -> Data {
        computeFinishedVerifyData(trafficSecret: clientTrafficSecret, transcript: transcript)
    }
}
