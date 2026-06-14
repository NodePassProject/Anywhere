//
//  TLSRecordCrypto.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import CryptoKit

struct TLSRecordCrypto {

    static func encryptHandshakeRecord(plaintext: Data, key: SymmetricKey, iv: Data, seqNum: UInt64, cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) throws -> Data {
        let nonce = buildNonce(iv: iv, seqNum: seqNum)

        var innerPlaintext = plaintext
        innerPlaintext.append(TLSContentType.handshake)

        let len = UInt16(innerPlaintext.count + 16)
        let aad = Data([TLSContentType.applicationData, 0x03, 0x03, UInt8(len >> 8), UInt8(len & 0xFF)])

        let (ct, tag) = try sealAEAD(plaintext: innerPlaintext, key: key, nonce: nonce, aad: aad, cipherSuite: cipherSuite)

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
        do {
            if cipherSuite == TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256 {
                let nonceObj = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
                return Data(try ChaChaPoly.open(sealedBox, using: key, authenticating: aad))
            } else {
                let nonceObj = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
                return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
            }
        } catch CryptoKitError.authenticationFailure {
            throw TLSRecordError.recordAuthenticationFailed
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

enum TLSRecordError: Error, LocalizedError {
    case ciphertextTooShort
    case emptyDecryptedData
    case noContentTypeFound
    case encryptionFailed
    case recordAuthenticationFailed
    case macVerificationFailed
    case invalidPadding
    case malformedRecord(String)
    case ivGenerationFailed
    case connectionUnavailable
    case tlsAlert(level: UInt8, description: UInt8)
    case unexpectedAlert

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
        case .recordAuthenticationFailed:
            return "TLS record authentication failed (bad tag)"
        case .macVerificationFailed:
            return "TLS record MAC verification failed"
        case .invalidPadding:
            return "Invalid TLS record padding"
        case .malformedRecord(let reason):
            return "Malformed TLS record: \(reason)"
        case .ivGenerationFailed:
            return "Failed to generate TLS record IV"
        case .connectionUnavailable:
            return "TLS record transport unavailable"
        case .tlsAlert(let level, let description):
            let kind = level == 2 ? "fatal" : "warning"
            return "TLS alert received: \(TLSRecordError.alertName(description)) (\(kind), code \(description))"
        case .unexpectedAlert:
            return "Unexpected TLS alert record"
        }
    }

    static func alertName(_ code: UInt8) -> String {
        switch code {
        case 0:   return "close_notify"
        case 10:  return "unexpected_message"
        case 20:  return "bad_record_mac"
        case 22:  return "record_overflow"
        case 40:  return "handshake_failure"
        case 42:  return "bad_certificate"
        case 43:  return "unsupported_certificate"
        case 44:  return "certificate_revoked"
        case 45:  return "certificate_expired"
        case 46:  return "certificate_unknown"
        case 47:  return "illegal_parameter"
        case 48:  return "unknown_ca"
        case 49:  return "access_denied"
        case 50:  return "decode_error"
        case 51:  return "decrypt_error"
        case 70:  return "protocol_version"
        case 71:  return "insufficient_security"
        case 80:  return "internal_error"
        case 86:  return "inappropriate_fallback"
        case 90:  return "user_canceled"
        case 109: return "missing_extension"
        case 110: return "unsupported_extension"
        case 112: return "unrecognized_name"
        case 113: return "bad_certificate_status_response"
        case 115: return "unknown_psk_identity"
        case 116: return "certificate_required"
        case 120: return "no_application_protocol"
        default:  return "alert_\(code)"
        }
    }
}
