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

    /// Encrypt a TLS 1.3 handshake record using AES-GCM.
    /// Returns a complete TLS record (header + ciphertext + tag).
    static func encryptHandshakeRecord(plaintext: Data, key: Data, iv: Data, seqNum: UInt64) throws -> Data {
        let nonce = buildNonce(iv: iv, seqNum: seqNum)

        var innerPlaintext = plaintext
        innerPlaintext.append(0x16)

        let len = UInt16(innerPlaintext.count + 16)
        let aad = Data([0x17, 0x03, 0x03, UInt8(len >> 8), UInt8(len & 0xFF)])

        let symmetricKey = SymmetricKey(data: key)
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(innerPlaintext, using: symmetricKey, nonce: nonceObj, authenticating: aad)

        // Return full TLS record: header + ciphertext + tag
        var record = aad
        record.append(contentsOf: sealedBox.ciphertext)
        record.append(contentsOf: sealedBox.tag)
        return record
    }

    static func decryptRecord(ciphertext: Data, key: Data, iv: Data, seqNum: UInt64, recordHeader: Data) throws -> Data {
        let nonce = buildNonce(iv: iv, seqNum: seqNum)

        guard ciphertext.count >= 16 else {
            throw TLSRecordError.ciphertextTooShort
        }

        let symmetricKey = SymmetricKey(data: key)
        let nonceObj = try AES.GCM.Nonce(data: nonce)

        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: recordHeader)

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

    static func encryptAESGCM(plaintext: Data, key: Data, nonce: Data, aad: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonceObj, authenticating: aad)

        var result = Data(sealedBox.ciphertext)
        result.append(contentsOf: sealedBox.tag)
        return result
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
