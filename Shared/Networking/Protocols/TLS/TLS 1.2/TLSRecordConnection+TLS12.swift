//
//  TLSRecordConnection+TLS12.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit
import CommonCrypto

extension TLSRecordConnection {

    // MARK: - TLS 1.2 Record Crypto

    func encryptTLS12Record(plaintext: Data, contentType: UInt8 = TLSContentType.applicationData) throws -> Data {
        seqLock.lock()
        let seqNum: UInt64
        if direction == .server {
            seqNum = serverSeqNum
            serverSeqNum += 1
        } else {
            seqNum = clientSeqNum
            clientSeqNum += 1
        }
        seqLock.unlock()

        let version = tlsVersion

        if TLSCipherSuite.isAEAD(cipherSuite) {
            return try encryptTLS12AEAD(plaintext: plaintext, contentType: contentType, seqNum: seqNum, version: version)
        } else {
            return try encryptTLS12CBC(plaintext: plaintext, contentType: contentType, seqNum: seqNum, version: version)
        }
    }

    private func encryptTLS12AEAD(plaintext: Data, contentType: UInt8, seqNum: UInt64, version: UInt16) throws -> Data {
        let isChaCha = TLSCipherSuite.isChaCha20(cipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8

        let nonce: Data
        let explicitNonce: Data
        if isChaCha {
            var n = egressIV
            xorSeqIntoNonce(&n, seqNum: seqNum)
            nonce = n
            explicitNonce = Data()
        } else {
            var seqBytes = Data(count: 8)
            for i in 0..<8 { seqBytes[i] = UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
            var n = egressIV
            n.append(seqBytes)
            nonce = n
            explicitNonce = seqBytes
        }

        var aad = Data(capacity: 13)
        for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
        aad.append(contentType)
        aad.append(UInt8(version >> 8))
        aad.append(UInt8(version & 0xFF))
        aad.append(UInt8((plaintext.count >> 8) & 0xFF))
        aad.append(UInt8(plaintext.count & 0xFF))

        let (ct, tag) = try sealAEAD(plaintext: plaintext, nonce: nonce, aad: aad, key: egressSymmetricKey)

        let recordPayloadLen = explicitNonceLen + ct.count + tag.count
        var record = Data(capacity: 5 + recordPayloadLen)
        record.append(contentType)
        record.append(UInt8(version >> 8))
        record.append(UInt8(version & 0xFF))
        record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
        record.append(UInt8(recordPayloadLen & 0xFF))
        record.append(explicitNonce)
        record.append(ct)
        record.append(tag)
        return record
    }

    private func encryptTLS12CBC(plaintext: Data, contentType: UInt8, seqNum: UInt64, version: UInt16) throws -> Data {
        let useSHA384 = TLSCipherSuite.usesSHA384(cipherSuite)
        let useSHA256: Bool
        switch cipherSuite {
        case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            useSHA256 = true
        default:
            useSHA256 = false
        }

        let mac = TLS12KeyDerivation.tls10MAC(
            macKey: egressMACKey, seqNum: seqNum,
            contentType: contentType, protocolVersion: version,
            payload: plaintext, useSHA384: useSHA384, useSHA256: useSHA256
        )

        var data = plaintext
        data.append(mac)

        let blockSize = 16
        let paddingLen = blockSize - (data.count % blockSize)
        let paddingByte = UInt8(paddingLen - 1)
        data.append(contentsOf: [UInt8](repeating: paddingByte, count: paddingLen))

        var iv = Data(count: blockSize)
        guard iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, blockSize, $0.baseAddress!) }) == errSecSuccess else {
            throw TLSRecordError.ivGenerationFailed
        }

        var encrypted = Data(count: data.count)
        var numBytesEncrypted = 0
        let cbcKey = egressKey
        let status = encrypted.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                cbcKey.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,
                            keyPtr.baseAddress!, cbcKey.count,
                            ivPtr.baseAddress!,
                            inPtr.baseAddress!, data.count,
                            outPtr.baseAddress!, data.count,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw TLSRecordError.encryptionFailed
        }

        let recordPayloadLen = blockSize + numBytesEncrypted
        var record = Data(capacity: 5 + recordPayloadLen)
        record.append(contentType)
        record.append(UInt8(version >> 8))
        record.append(UInt8(version & 0xFF))
        record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
        record.append(UInt8(recordPayloadLen & 0xFF))
        record.append(iv)
        record.append(encrypted.prefix(numBytesEncrypted))
        return record
    }

    func decryptTLS12Record(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        if TLSCipherSuite.isAEAD(cipherSuite) {
            return try decryptTLS12AEAD(ciphertext: ciphertext, header: header, seqNum: seqNum)
        } else {
            return try decryptTLS12CBC(ciphertext: ciphertext, header: header, seqNum: seqNum)
        }
    }

    private func decryptTLS12AEAD(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        let isChaCha = TLSCipherSuite.isChaCha20(cipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8
        let version = tlsVersion
        let contentType = header.first ?? TLSContentType.applicationData

        guard ciphertext.count >= explicitNonceLen + 16 else {
            throw TLSRecordError.ciphertextTooShort
        }

        let explicitNonce = isChaCha ? Data() : Data(ciphertext.prefix(explicitNonceLen))
        let payload = Data(ciphertext.suffix(from: ciphertext.startIndex + explicitNonceLen))

        let nonce: Data
        if isChaCha {
            var n = ingressIV
            xorSeqIntoNonce(&n, seqNum: seqNum)
            nonce = n
        } else {
            var n = ingressIV
            n.append(explicitNonce)
            nonce = n
        }

        let plaintextLen = payload.count - 16
        var aad = Data(capacity: 13)
        for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
        aad.append(contentType)
        aad.append(UInt8(version >> 8))
        aad.append(UInt8(version & 0xFF))
        aad.append(UInt8((plaintextLen >> 8) & 0xFF))
        aad.append(UInt8(plaintextLen & 0xFF))

        let ct = Data(payload.prefix(payload.count - 16))
        let tag = Data(payload.suffix(16))

        return try openAEAD(ciphertext: ct, tag: tag, nonce: nonce, aad: aad, key: ingressSymmetricKey)
    }

    private func decryptTLS12CBC(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        let blockSize = 16
        let version = tlsVersion
        let contentType = header.first ?? TLSContentType.applicationData

        guard ciphertext.count >= blockSize * 2 else {
            throw TLSRecordError.ciphertextTooShort
        }

        let iv = Data(ciphertext.prefix(blockSize))
        let encrypted = Data(ciphertext.suffix(from: ciphertext.startIndex + blockSize))

        guard encrypted.count % blockSize == 0 else {
            throw TLSRecordError.malformedRecord("CBC ciphertext not block-aligned")
        }

        var decrypted = Data(count: encrypted.count)
        var numBytesDecrypted = 0
        let cbcKey = ingressKey
        let status = decrypted.withUnsafeMutableBytes { outPtr in
            encrypted.withUnsafeBytes { inPtr in
                cbcKey.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,
                            keyPtr.baseAddress!, cbcKey.count,
                            ivPtr.baseAddress!,
                            inPtr.baseAddress!, encrypted.count,
                            outPtr.baseAddress!, encrypted.count,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess, numBytesDecrypted > 0 else {
            throw TLSRecordError.malformedRecord("CBC decryption failed")
        }

        decrypted = decrypted.prefix(numBytesDecrypted)

        let paddingByte = Int(decrypted.last ?? 0)
        let paddingLen = paddingByte + 1

        var paddingGood: UInt8 = 0
        if paddingLen > decrypted.count {
            paddingGood = 1
        } else {
            for i in (decrypted.count - paddingLen)..<decrypted.count {
                paddingGood |= decrypted[i] ^ UInt8(paddingByte)
            }
        }

        guard paddingGood == 0 else {
            throw TLSRecordError.invalidPadding
        }

        decrypted = decrypted.prefix(decrypted.count - paddingLen)

        let macSize = TLSCipherSuite.macLength(cipherSuite)
        guard decrypted.count >= macSize else {
            throw TLSRecordError.malformedRecord("decrypted record too short for MAC")
        }

        let payload = Data(decrypted.prefix(decrypted.count - macSize))
        let receivedMAC = Data(decrypted.suffix(macSize))

        let useSHA384 = TLSCipherSuite.usesSHA384(cipherSuite)
        let useSHA256: Bool
        switch cipherSuite {
        case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            useSHA256 = true
        default:
            useSHA256 = false
        }

        let expectedMAC = TLS12KeyDerivation.tls10MAC(
            macKey: ingressMACKey, seqNum: seqNum,
            contentType: contentType, protocolVersion: version,
            payload: payload, useSHA384: useSHA384, useSHA256: useSHA256
        )

        guard receivedMAC.count == expectedMAC.count,
              constantTimeEqual(receivedMAC, expectedMAC) else {
            throw TLSRecordError.macVerificationFailed
        }

        return payload
    }

    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }
}
