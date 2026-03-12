import Foundation
import CryptoKit

/// TLS 1.3 cipher suite constants
enum TLSCipherSuite {
    static let TLS_AES_128_GCM_SHA256: UInt16 = 0x1301
    static let TLS_AES_256_GCM_SHA384: UInt16 = 0x1302
    static let TLS_CHACHA20_POLY1305_SHA256: UInt16 = 0x1303
}

/// TLS 1.3 handshake traffic keys
struct TLSHandshakeKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
    let clientTrafficSecret: Data
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

    /// Get encryption key length based on cipher suite
    var keyLength: Int {
        return cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 32 : 16
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
        let (earlyPRK, earlyKey) = hkdfExtract(salt: Data(), ikm: Data(repeating: 0, count: hashLength))
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
            clientTrafficSecret: clientHTS
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

    /// Compute Client Finished verify data
    func computeFinishedVerifyData(clientTrafficSecret: Data, transcript: Data) -> Data {
        let ctsKey = SymmetricKey(data: clientTrafficSecret)
        let finishedKey = hkdfExpandLabel(key: ctsKey, label: "finished", context: Data(), length: hashLength)
        let transcriptHash = self.transcriptHash(transcript)

        let key = SymmetricKey(data: finishedKey)
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: key))
        } else {
            return Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: key))
        }
    }
}
