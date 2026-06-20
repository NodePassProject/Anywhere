//
//  TLS13KeyDerivation.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit

struct TLS13KeyDerivation {
    let cipherSuite: UInt16

    init(cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) {
        self.cipherSuite = cipherSuite
    }

    var hashLength: Int {
        return cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 48 : 32
    }

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

    func extract(inputKeyMaterial: Data, salt: Data) -> (prk: Data, key: SymmetricKey) {
        let saltData = salt.isEmpty ? Data(repeating: 0, count: hashLength) : salt
        let key = SymmetricKey(data: saltData)

        let prk: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            prk = Data(HMAC<SHA384>.authenticationCode(for: inputKeyMaterial, using: key))
        } else {
            prk = Data(HMAC<SHA256>.authenticationCode(for: inputKeyMaterial, using: key))
        }
        return (prk, SymmetricKey(data: prk))
    }

    func expand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) -> Data {
        var output = Data(capacity: outputByteCount + hashLength)
        var previousBlock = Data()
        var counter: UInt8 = 1
        var input = Data(capacity: hashLength + info.count + 1)

        while output.count < outputByteCount {
            input.removeAll(keepingCapacity: true)
            input.append(previousBlock)
            input.append(info)
            input.append(counter)

            if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
                previousBlock = Data(HMAC<SHA384>.authenticationCode(for: input, using: pseudoRandomKey))
            } else {
                previousBlock = Data(HMAC<SHA256>.authenticationCode(for: input, using: pseudoRandomKey))
            }
            output.append(previousBlock)
            counter += 1
        }

        return Data(output.prefix(outputByteCount))
    }

    func expandLabel(secret: SymmetricKey, label: String, context: Data, length: Int) -> Data {
        // HkdfLabel (RFC 8446 §7.1): uint16 length; opaque label<7..255>="tls13 "+Label; opaque context<0..255>.
        let fullLabel = "tls13 " + label
        var hkdfLabel = Data()
        hkdfLabel.append(UInt8((length >> 8) & 0xFF))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(fullLabel.count))
        hkdfLabel.append(contentsOf: fullLabel.utf8)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)
        return expand(pseudoRandomKey: secret, info: hkdfLabel, outputByteCount: length)
    }

    func deriveSecret(secret: SymmetricKey, label: String, messages: Data) -> Data {
        let hashData: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            hashData = Data(SHA384.hash(data: messages))
        } else {
            hashData = Data(SHA256.hash(data: messages))
        }
        return expandLabel(secret: secret, label: label, context: hashData, length: hashLength)
    }

    // MARK: - Public API

    func transcriptHash(_ messages: Data) -> Data {
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(SHA384.hash(data: messages))
        } else {
            return Data(SHA256.hash(data: messages))
        }
    }

    /// Derive handshake-traffic keys and return the handshake secret.
    /// `psk` is for session resumption; `nil` means full handshake (all-zero IKM).
    func deriveHandshakeKeys(sharedSecret: Data, transcript: Data, psk: Data? = nil) -> (handshakeSecret: Data, keys: TLS13HandshakeKeys) {
        let earlyIKM = psk ?? Data(repeating: 0, count: hashLength)
        let (_, earlyKey) = extract(inputKeyMaterial: earlyIKM, salt: Data())
        let derivedEarly = deriveSecret(secret: earlyKey, label: "derived", messages: Data())
        let (hsPRK, hsKey) = extract(inputKeyMaterial: sharedSecret, salt: derivedEarly)

        let clientHTS = deriveSecret(secret: hsKey, label: "c hs traffic", messages: transcript)
        let clientHTSKey = SymmetricKey(data: clientHTS)
        let clientKey = expandLabel(secret: clientHTSKey, label: "key", context: Data(), length: keyLength)
        let clientIV = expandLabel(secret: clientHTSKey, label: "iv", context: Data(), length: 12)

        let serverHTS = deriveSecret(secret: hsKey, label: "s hs traffic", messages: transcript)
        let serverHTSKey = SymmetricKey(data: serverHTS)
        let serverKey = expandLabel(secret: serverHTSKey, label: "key", context: Data(), length: keyLength)
        let serverIV = expandLabel(secret: serverHTSKey, label: "iv", context: Data(), length: 12)

        let keys = TLS13HandshakeKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV,
            clientTrafficSecret: clientHTS,
            serverTrafficSecret: serverHTS
        )
        return (hsPRK, keys)
    }

    /// Derive application keys from the full transcript (including server Finished)
    func deriveApplicationKeys(handshakeSecret: Data, fullTranscript: Data) -> TLS13ApplicationKeys {
        let hsKey = SymmetricKey(data: handshakeSecret)
        let derivedHS = deriveSecret(secret: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = extract(inputKeyMaterial: Data(repeating: 0, count: hashLength), salt: derivedHS)

        let clientATS = deriveSecret(secret: masterKey, label: "c ap traffic", messages: fullTranscript)
        let clientATSKey = SymmetricKey(data: clientATS)
        let clientKey = expandLabel(secret: clientATSKey, label: "key", context: Data(), length: keyLength)
        let clientIV = expandLabel(secret: clientATSKey, label: "iv", context: Data(), length: 12)

        let serverATS = deriveSecret(secret: masterKey, label: "s ap traffic", messages: fullTranscript)
        let serverATSKey = SymmetricKey(data: serverATS)
        let serverKey = expandLabel(secret: serverATSKey, label: "key", context: Data(), length: keyLength)
        let serverIV = expandLabel(secret: serverATSKey, label: "iv", context: Data(), length: 12)

        return TLS13ApplicationKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV,
            clientTrafficSecret: clientATS,
            serverTrafficSecret: serverATS
        )
    }

    /// Advance an application traffic secret to its next generation and derive the matching
    /// AEAD key + IV, per RFC 8446 §7.2:
    ///   application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)
    func nextApplicationGeneration(trafficSecret: Data) -> (secret: Data, key: Data, iv: Data) {
        let next = expandLabel(secret: SymmetricKey(data: trafficSecret),
                               label: "traffic upd", context: Data(), length: hashLength)
        let nextKey = SymmetricKey(data: next)
        let key = expandLabel(secret: nextKey, label: "key", context: Data(), length: keyLength)
        let iv = expandLabel(secret: nextKey, label: "iv", context: Data(), length: 12)
        return (next, key, iv)
    }

    func finishedPayload(trafficSecret: Data, transcript: Data) -> Data {
        let tsKey = SymmetricKey(data: trafficSecret)
        let finishedKey = expandLabel(secret: tsKey, label: "finished", context: Data(), length: hashLength)
        let transcriptHash = self.transcriptHash(transcript)

        let key = SymmetricKey(data: finishedKey)
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: key))
        } else {
            return Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: key))
        }
    }

    func clientFinishedPayload(clientTrafficSecret: Data, transcript: Data) -> Data {
        finishedPayload(trafficSecret: clientTrafficSecret, transcript: transcript)
    }
}

// MARK: - Server-Side Helpers

extension TLS13KeyDerivation {
    func serverFinishedPayload(serverTrafficSecret: Data, transcript: Data) -> Data {
        finishedPayload(trafficSecret: serverTrafficSecret, transcript: transcript)
    }
}
