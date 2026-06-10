//
//  TLS12KeyDerivation.swift
//  Anywhere
//
//  TLS 1.2 key derivation matching utls/prf.go and utls/internal/tls12/tls12.go
//

import Foundation
import CryptoKit

/// TLS 1.2 key material derived from the master secret.
struct TLS12Keys {
    let clientMACKey: Data
    let serverMACKey: Data
    let clientKey: Data
    let serverKey: Data
    let clientIV: Data
    let serverIV: Data
}

/// Running TLS 1.2 server-side handshake state. The transcript is the concatenation of
/// plaintext handshake messages (no record framing), hashed for EMS and Finished.
struct TLS12ServerHandshakeState {
    var transcript: Data = Data()
    var masterSecret: Data?
    var keys: TLS12Keys?
    var clientRandom: Data?
    var serverRandom: Data?
    var extendedMasterSecret: Bool = false
    /// Once the client's CCS is seen, subsequent client handshake records are encrypted.
    var receivedCCS: Bool = false
}

/// TLS 1.2 key derivation utilities (RFC 5246 §5).
struct TLS12KeyDerivation {

    // MARK: - PRF (Pseudo-Random Function)

    /// TLS 1.2 PRF: `PRF(secret, label, seed) = P_<hash>(secret, label || seed)` (RFC 5246 §5).
    /// - Parameter useSHA384: Use SHA-384 instead of SHA-256 for SHA-384 cipher suites.
    static func prf(secret: Data, label: String, seed: Data, length: Int, useSHA384: Bool = false) -> Data {
        var labelAndSeed = Data(label.utf8)
        labelAndSeed.append(seed)
        return pHash(secret: secret, seed: labelAndSeed, length: length, useSHA384: useSHA384)
    }

    /// P_hash iterative expansion (RFC 5246 §5).
    private static func pHash(secret: Data, seed: Data, length: Int, useSHA384: Bool) -> Data {
        let key = SymmetricKey(data: secret)
        var result = Data(capacity: length + 64)
        var a = seed

        while result.count < length {
            if useSHA384 {
                a = Data(HMAC<SHA384>.authenticationCode(for: a, using: key))
                var input = a
                input.append(seed)
                result.append(Data(HMAC<SHA384>.authenticationCode(for: input, using: key)))
            } else {
                a = Data(HMAC<SHA256>.authenticationCode(for: a, using: key))
                var input = a
                input.append(seed)
                result.append(Data(HMAC<SHA256>.authenticationCode(for: input, using: key)))
            }
        }

        return Data(result.prefix(length))
    }

    // MARK: - Master Secret

    /// `master_secret = PRF(pre_master_secret, "master secret", client_random || server_random)[0..47]`.
    static func masterSecret(
        preMasterSecret: Data,
        clientRandom: Data,
        serverRandom: Data,
        useSHA384: Bool = false
    ) -> Data {
        var seed = clientRandom
        seed.append(serverRandom)
        return prf(secret: preMasterSecret, label: "master secret", seed: seed, length: 48, useSHA384: useSHA384)
    }

    // MARK: - Extended Master Secret (RFC 7627)

    /// RFC 7627 extended master secret: the PRF seed is the transcript hash through
    /// ClientKeyExchange, not the randoms.
    static func extendedMasterSecret(
        preMasterSecret: Data,
        sessionHash: Data,
        useSHA384: Bool = false
    ) -> Data {
        return prf(secret: preMasterSecret, label: "extended master secret", seed: sessionHash, length: 48, useSHA384: useSHA384)
    }

    // MARK: - Key Expansion

    /// Key block layout: client_MAC || server_MAC || client_key || server_key || client_IV || server_IV.
    static func keysFromMasterSecret(
        masterSecret: Data,
        clientRandom: Data,
        serverRandom: Data,
        macLen: Int,
        keyLen: Int,
        ivLen: Int,
        useSHA384: Bool = false
    ) -> TLS12Keys {
        // Seed order is server_random + client_random (reversed from master secret).
        var seed = serverRandom
        seed.append(clientRandom)
        let totalLen = 2 * macLen + 2 * keyLen + 2 * ivLen
        let keyBlock = prf(secret: masterSecret, label: "key expansion", seed: seed, length: totalLen, useSHA384: useSHA384)

        var offset = 0
        let clientMACKey = keyBlock.subdata(in: offset..<(offset + macLen)); offset += macLen
        let serverMACKey = keyBlock.subdata(in: offset..<(offset + macLen)); offset += macLen
        let clientKey = keyBlock.subdata(in: offset..<(offset + keyLen)); offset += keyLen
        let serverKey = keyBlock.subdata(in: offset..<(offset + keyLen)); offset += keyLen
        let clientIV = keyBlock.subdata(in: offset..<(offset + ivLen)); offset += ivLen
        let serverIV = keyBlock.subdata(in: offset..<(offset + ivLen))

        return TLS12Keys(
            clientMACKey: clientMACKey, serverMACKey: serverMACKey,
            clientKey: clientKey, serverKey: serverKey,
            clientIV: clientIV, serverIV: serverIV
        )
    }

    // MARK: - Finished Verify Data

    /// `verify_data = PRF(master_secret, "client finished"/"server finished", Hash(handshake_messages))[0..11]`.
    static func computeFinishedVerifyData(
        masterSecret: Data,
        label: String,
        handshakeHash: Data,
        useSHA384: Bool = false
    ) -> Data {
        return prf(secret: masterSecret, label: label, seed: handshakeHash, length: 12, useSHA384: useSHA384)
    }

    // MARK: - Transcript Hash

    static func transcriptHash(_ messages: Data, useSHA384: Bool = false) -> Data {
        if useSHA384 {
            return Data(SHA384.hash(data: messages))
        } else {
            return Data(SHA256.hash(data: messages))
        }
    }

    // MARK: - TLS 1.0/1.1 MAC

    /// CBC record MAC: `HMAC_hash(mac_key, seq(8) || type(1) || version(2) || length(2) || fragment)`.
    static func tls10MAC(
        macKey: Data,
        seqNum: UInt64,
        contentType: UInt8,
        protocolVersion: UInt16,
        payload: Data,
        useSHA384: Bool = false,
        useSHA256: Bool = false
    ) -> Data {
        let key = SymmetricKey(data: macKey)

        var input = Data(capacity: 13 + payload.count)
        for i in (0..<8).reversed() {
            input.append(UInt8((seqNum >> (i * 8)) & 0xFF))
        }
        input.append(contentType)
        input.append(UInt8(protocolVersion >> 8))
        input.append(UInt8(protocolVersion & 0xFF))
        input.append(UInt8((payload.count >> 8) & 0xFF))
        input.append(UInt8(payload.count & 0xFF))
        input.append(payload)

        if useSHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: input, using: key))
        } else if useSHA256 {
            return Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
        } else {
            // HMAC-SHA1 for legacy CBC suites
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: input, using: key))
        }
    }
}
