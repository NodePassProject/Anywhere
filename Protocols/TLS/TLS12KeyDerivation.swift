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

/// TLS 1.2 key derivation utilities.
///
/// Implements the TLS 1.2 PRF (RFC 5246 §5) and key schedule,
/// matching the behavior of utls `prf.go` and `internal/tls12/tls12.go`.
struct TLS12KeyDerivation {

    // MARK: - PRF (Pseudo-Random Function)

    /// TLS 1.2 PRF: `PRF(secret, label, seed) = P_<hash>(secret, label || seed)`
    ///
    /// RFC 5246 §5: The PRF is defined using a single hash function (SHA-256 or SHA-384).
    /// - Parameters:
    ///   - secret: The secret key material.
    ///   - label: An ASCII label string (e.g. "master secret").
    ///   - seed: The seed data (typically concatenated randoms).
    ///   - length: Number of output bytes.
    ///   - useSHA384: Use SHA-384 instead of SHA-256 (for SHA384 cipher suites).
    static func prf(secret: Data, label: String, seed: Data, length: Int, useSHA384: Bool = false) -> Data {
        var labelAndSeed = Data(label.utf8)
        labelAndSeed.append(seed)
        return pHash(secret: secret, seed: labelAndSeed, length: length, useSHA384: useSHA384)
    }

    /// P_hash iterative expansion (RFC 5246 §5).
    ///
    /// ```
    /// A(0) = seed
    /// A(i) = HMAC_hash(secret, A(i-1))
    /// P_hash(secret, seed) = HMAC_hash(secret, A(1) || seed) ||
    ///                        HMAC_hash(secret, A(2) || seed) || ...
    /// ```
    private static func pHash(secret: Data, seed: Data, length: Int, useSHA384: Bool) -> Data {
        let key = SymmetricKey(data: secret)
        var result = Data(capacity: length + 64)
        var a = seed  // A(0) = seed

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

    /// Derives the 48-byte master secret from the pre-master secret.
    ///
    /// `master_secret = PRF(pre_master_secret, "master secret",
    ///                      ClientHello.random + ServerHello.random)[0..47]`
    ///
    /// Matches utls `prf.go:masterFromPreMasterSecret()`.
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

    /// Derives the 48-byte master secret using the Extended Master Secret formula.
    ///
    /// `master_secret = PRF(pre_master_secret, "extended master secret",
    ///                      Hash(handshake_messages))[0..47]`
    ///
    /// The seed is the hash of all handshake messages up to and including
    /// ClientKeyExchange (NOT clientRandom + serverRandom).
    ///
    /// Matches utls `prf.go:extMasterFromPreMasterSecret()`.
    static func extendedMasterSecret(
        preMasterSecret: Data,
        sessionHash: Data,
        useSHA384: Bool = false
    ) -> Data {
        return prf(secret: preMasterSecret, label: "extended master secret", seed: sessionHash, length: 48, useSHA384: useSHA384)
    }

    // MARK: - Key Expansion

    /// Derives encryption keys from the master secret.
    ///
    /// `key_block = PRF(master_secret, "key expansion",
    ///                  server_random + client_random)`
    ///
    /// The key block is partitioned into:
    /// `client_write_MAC_key[macLen] + server_write_MAC_key[macLen] +
    ///  client_write_key[keyLen]     + server_write_key[keyLen] +
    ///  client_write_IV[ivLen]       + server_write_IV[ivLen]`
    ///
    /// Matches utls `prf.go:keysFromMasterSecret()`.
    static func keysFromMasterSecret(
        masterSecret: Data,
        clientRandom: Data,
        serverRandom: Data,
        macLen: Int,
        keyLen: Int,
        ivLen: Int,
        useSHA384: Bool = false
    ) -> TLS12Keys {
        // Note: seed order is server_random + client_random (reversed from master secret)
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

    /// Computes the 12-byte `verify_data` for the Finished message.
    ///
    /// `verify_data = PRF(master_secret, finished_label,
    ///                    Hash(handshake_messages))[0..11]`
    ///
    /// - Parameters:
    ///   - masterSecret: The 48-byte master secret.
    ///   - label: `"client finished"` or `"server finished"`.
    ///   - handshakeHash: Hash of all handshake messages so far.
    ///   - useSHA384: Use SHA-384 for the PRF.
    static func computeFinishedVerifyData(
        masterSecret: Data,
        label: String,
        handshakeHash: Data,
        useSHA384: Bool = false
    ) -> Data {
        return prf(secret: masterSecret, label: label, seed: handshakeHash, length: 12, useSHA384: useSHA384)
    }

    // MARK: - Transcript Hash

    /// Computes the transcript hash of all handshake messages.
    static func transcriptHash(_ messages: Data, useSHA384: Bool = false) -> Data {
        if useSHA384 {
            return Data(SHA384.hash(data: messages))
        } else {
            return Data(SHA256.hash(data: messages))
        }
    }

    // MARK: - TLS 1.0/1.1 MAC

    /// Computes the TLS record MAC for CBC cipher suites.
    ///
    /// `MAC = HMAC_hash(mac_key, seq_num(8) || type(1) || version(2) || length(2) || fragment)`
    ///
    /// Matches utls `cipher_suites.go:tls10MAC()`.
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
        // Sequence number (8 bytes, big-endian)
        for i in (0..<8).reversed() {
            input.append(UInt8((seqNum >> (i * 8)) & 0xFF))
        }
        // Content type (1 byte)
        input.append(contentType)
        // Protocol version (2 bytes)
        input.append(UInt8(protocolVersion >> 8))
        input.append(UInt8(protocolVersion & 0xFF))
        // Payload length (2 bytes)
        input.append(UInt8((payload.count >> 8) & 0xFF))
        input.append(UInt8(payload.count & 0xFF))
        // Payload
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
