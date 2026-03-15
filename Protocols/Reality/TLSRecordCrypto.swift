//
//  TLSRecordCrypto.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import CryptoKit

/// TLS 1.3 record layer cryptographic operations
struct TLSRecordCrypto {

    /// Encrypt a TLS 1.3 handshake record.
    /// Returns a complete TLS record (header + ciphertext + tag).
    static func encryptHandshakeRecord(plaintext: Data, key: SymmetricKey, iv: Data, seqNum: UInt64, cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) throws -> Data {
        let nonce = buildNonce(iv: iv, seqNum: seqNum)

        var innerPlaintext = plaintext
        innerPlaintext.append(0x16)

        let len = UInt16(innerPlaintext.count + 16)
        let aad = Data([0x17, 0x03, 0x03, UInt8(len >> 8), UInt8(len & 0xFF)])

        let (ct, tag) = try sealAEAD(plaintext: innerPlaintext, key: key, nonce: nonce, aad: aad, cipherSuite: cipherSuite)

        // Return full TLS record: header + ciphertext + tag
        var record = aad
        record.append(ct)
        record.append(tag)
        return record
    }

    static func decryptRecord(ciphertext: Data, key: SymmetricKey, iv: Data, seqNum: UInt64, recordHeader: Data, cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) throws -> Data {
        let nonce = buildNonce(iv: iv, seqNum: seqNum)

        guard ciphertext.count >= 16 else {
            throw TLSRecordError.ciphertextTooShort
        }

        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)

        let decrypted = try openAEAD(ciphertext: Data(ct), tag: Data(tag), key: key, nonce: nonce, aad: recordHeader, cipherSuite: cipherSuite)

        guard !decrypted.isEmpty else {
            throw TLSRecordError.emptyDecryptedData
        }

        var contentEnd = decrypted.count - 1
        while contentEnd >= 0 && decrypted[contentEnd] == 0 {
            contentEnd -= 1
        }

        guard contentEnd >= 0 else {
            throw TLSRecordError.noContentTypeFound
        }

        return Data(decrypted.prefix(contentEnd))
    }

    static func encryptAESGCM(plaintext: Data, key: SymmetricKey, nonce: Data, aad: Data) throws -> Data {
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)

        var result = Data(sealedBox.ciphertext)
        result.append(contentsOf: sealedBox.tag)
        return result
    }

    // MARK: - AEAD Dispatch

    private static func sealAEAD(plaintext: Data, key: SymmetricKey, nonce: Data, aad: Data, cipherSuite: UInt16) throws -> (ciphertext: Data, tag: Data) {
        if cipherSuite == TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256 {
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
            return (Data(sealedBox.ciphertext), Data(sealedBox.tag))
        } else {
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
            return (Data(sealedBox.ciphertext), Data(sealedBox.tag))
        }
    }

    private static func openAEAD(ciphertext: Data, tag: Data, key: SymmetricKey, nonce: Data, aad: Data, cipherSuite: UInt16) throws -> Data {
        if cipherSuite == TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256 {
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
            return Data(try ChaChaPoly.open(sealedBox, using: key, authenticating: aad))
        } else {
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
            return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
        }
    }

    // MARK: - Private

    private static func buildNonce(iv: Data, seqNum: UInt64) -> Data {
        var nonce = iv
        for i in 0..<8 {
            nonce[nonce.count - 8 + i] ^= UInt8((seqNum >> (56 - i * 8)) & 0xFF)
        }
        return nonce
    }
}

/// Errors from TLS record operations
enum TLSRecordError: Error, LocalizedError {
    case ciphertextTooShort
    case emptyDecryptedData
    case noContentTypeFound
    case encryptionFailed

    var errorDescription: String? {
        switch self {
        case .ciphertextTooShort:
            return "Ciphertext too short for decryption"
        case .emptyDecryptedData:
            return "Empty decrypted data"
        case .noContentTypeFound:
            return "No content type found in decrypted data"
        case .encryptionFailed:
            return "AES-GCM encryption failed"
        }
    }
}
