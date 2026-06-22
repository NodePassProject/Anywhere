//
//  TLS12KeyDerivation.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit

struct TLS12KeyDerivation {

    // MARK: - PRF (Pseudo-Random Function)

    static func prf(secret: Data, label: String, seed: Data, length: Int, useSHA384: Bool = false) -> Data {
        var labelAndSeed = Data(label.utf8)
        labelAndSeed.append(seed)
        return pHash(secret: secret, seed: labelAndSeed, length: length, useSHA384: useSHA384)
    }

    private static func pHash(secret: Data, seed: Data, length: Int, useSHA384: Bool) -> Data {
        let key = SymmetricKey(data: secret)
        var result = Data(capacity: length + 64)
        var aValue = seed

        while result.count < length {
            if useSHA384 {
                aValue = Data(HMAC<SHA384>.authenticationCode(for: aValue, using: key))
                var input = aValue
                input.append(seed)
                result.append(Data(HMAC<SHA384>.authenticationCode(for: input, using: key)))
            } else {
                aValue = Data(HMAC<SHA256>.authenticationCode(for: aValue, using: key))
                var input = aValue
                input.append(seed)
                result.append(Data(HMAC<SHA256>.authenticationCode(for: input, using: key)))
            }
        }

        return Data(result.prefix(length))
    }

    // MARK: - Master Secret

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

    static func extendedMasterSecret(
        preMasterSecret: Data,
        sessionHash: Data,
        useSHA384: Bool = false
    ) -> Data {
        return prf(secret: preMasterSecret, label: "extended master secret", seed: sessionHash, length: 48, useSHA384: useSHA384)
    }

    // MARK: - Key Expansion

    static func keysFromMasterSecret(
        masterSecret: Data,
        clientRandom: Data,
        serverRandom: Data,
        macLen: Int,
        keyLen: Int,
        ivLen: Int,
        useSHA384: Bool = false
    ) -> TLS12HandshakeKeys {
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

        return TLS12HandshakeKeys(
            clientMACKey: clientMACKey, serverMACKey: serverMACKey,
            clientKey: clientKey, serverKey: serverKey,
            clientIV: clientIV, serverIV: serverIV
        )
    }

    // MARK: - Finished Verify Data

    static func finishedPayload(
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
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: input, using: key))
        }
    }
}
