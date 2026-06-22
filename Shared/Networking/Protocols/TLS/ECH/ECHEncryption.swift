//
//  ECHEncryption.swift
//  Anywhere
//
//  Created by NodePassProject on 6/14/26.
//

import Foundation
import CryptoKit

/// One context corresponds to one ClientHelloOuter.
final class ECHClientContext {
    let config: ECHConfig
    let cipherSuite: ECHCipherSuite
    let encapsulatedKey: Data

    /// CryptoKit's sender is a value type whose `seal` mutates the sequence
    /// number, so it lives in a `var`.
    private var sender: HPKE.Sender

    /// Inner ClientHello with the outer's session_id spliced in; feeds the inner transcript when accepted.
    var innerTranscriptMessage = Data()

    /// 32-byte inner ClientHello random, used as IKM for the ECH accept-confirmation derivation.
    var innerRandom = Data()

    var rejected = false

    /// Retry configs the server may offer in EncryptedExtensions on rejection.
    var retryConfigList: Data?

    init(config: ECHConfig, cipherSuite: ECHCipherSuite) throws {
        self.config = config
        self.cipherSuite = cipherSuite

        guard config.kemID == ECHKemID.dhkemX25519HKDFSHA256 else {
            throw ECHEncryptionError.unsupportedKEM
        }
        guard let kdf = ECHEncryption.hpkeKDF(cipherSuite.kdfID) else {
            throw ECHEncryptionError.unsupportedKDF
        }
        guard let aead = ECHEncryption.hpkeAEAD(cipherSuite.aeadID) else {
            throw ECHEncryptionError.unsupportedAEAD
        }

        let recipientKey: Curve25519.KeyAgreement.PublicKey
        do {
            recipientKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: config.publicKey)
        } catch {
            throw ECHEncryptionError.invalidPublicKey
        }

        let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: kdf, aead: aead)

        // info = "tls ech" || 0x00 || ECHConfig (including its version+length header).
        var info = Data("tls ech".utf8)
        info.append(0x00)
        info.append(config.raw)

        let createdSender: HPKE.Sender
        do {
            createdSender = try HPKE.Sender(recipientKey: recipientKey, ciphersuite: suite, info: info)
        } catch {
            throw ECHEncryptionError.senderSetupFailed
        }
        self.sender = createdSender
        self.encapsulatedKey = createdSender.encapsulatedKey
    }

    /// Seal the encoded inner ClientHello. `aad` is the serialized
    /// ClientHelloOuter (without its 4-byte handshake header) carrying a
    /// zero-filled payload of the resulting ciphertext length.
    func seal(plaintext: Data, aad: Data) throws -> Data {
        do {
            return try sender.seal(plaintext, authenticating: aad)
        } catch {
            throw ECHEncryptionError.sealFailed
        }
    }
}

enum ECHEncryptionError: Error, LocalizedError {
    case unsupportedKEM
    case unsupportedKDF
    case unsupportedAEAD
    case invalidPublicKey
    case senderSetupFailed
    case sealFailed
    case malformedInnerHello

    var errorDescription: String? {
        switch self {
        case .unsupportedKEM:      return "ECH config uses an unsupported HPKE KEM"
        case .unsupportedKDF:      return "ECH cipher suite uses an unsupported HPKE KDF"
        case .unsupportedAEAD:     return "ECH cipher suite uses an unsupported HPKE AEAD"
        case .invalidPublicKey:    return "ECH config public key is invalid"
        case .senderSetupFailed:   return "Failed to set up HPKE sender for ECH"
        case .sealFailed:          return "Failed to seal inner ClientHello"
        case .malformedInnerHello: return "Inner ClientHello is malformed"
        }
    }
}

enum ECHEncryption {

    /// All ECH AEADs in use share a 16-byte authentication tag.
    static let aeadTagLength = 16

    // MARK: - HPKE identifier mapping

    static func hpkeKDF(_ id: UInt16) -> HPKE.KDF? {
        switch id {
        case ECHKdfID.hkdfSHA256: return .HKDF_SHA256
        case ECHKdfID.hkdfSHA384: return .HKDF_SHA384
        case ECHKdfID.hkdfSHA512: return .HKDF_SHA512
        default: return nil
        }
    }

    static func hpkeAEAD(_ id: UInt16) -> HPKE.AEAD? {
        switch id {
        case ECHAeadID.aesGCM128: return .AES_GCM_128
        case ECHAeadID.aesGCM256: return .AES_GCM_256
        case ECHAeadID.chaCha20Poly1305: return .chaChaPoly
        default: return nil
        }
    }

    // MARK: - EncodedClientHelloInner

    /// Strip the handshake header from an inner ClientHello message and pad the
    /// remaining body to a multiple of 32 (the EncodedClientHelloInner form).
    ///
    /// `innerMessage` must be a ClientHello *handshake message* (type + 3-byte
    /// length + body) whose `legacy_session_id` is empty, with no
    /// ech_outer_extensions compression (we send the inner extensions in full).
    static func encodeInnerClientHello(_ innerMessage: Data, serverName: String, maxNameLength: Int) throws -> Data {
        guard innerMessage.count >= 4 else { throw ECHEncryptionError.malformedInnerHello }

        // Drop the 4-byte handshake header (type + uint24 length).
        var encodedHelloBody = Data(innerMessage.dropFirst(4))

        let base: Int
        if !serverName.isEmpty {
            base = max(0, maxNameLength - serverName.utf8.count)
        } else {
            base = maxNameLength + 9
        }
        let paddingLength = 31 - ((encodedHelloBody.count + base - 1) % 32)
        if paddingLength > 0 {
            encodedHelloBody.append(Data(repeating: 0, count: paddingLength))
        }
        return encodedHelloBody
    }

    // MARK: - Outer extension serialization

    /// Build the body of the outer `encrypted_client_hello` extension:
    ///
    ///     struct {
    ///       ECHClientHelloType type = 0;     // outer
    ///       HpkeKdfId    kdf_id;
    ///       HpkeAeadId   aead_id;
    ///       uint8        config_id;
    ///       opaque enc<0..2^16-1>;           // empty on HRR
    ///       opaque payload<1..2^16-1>;
    ///     }
    ///
    /// This returns the extension *data*; the caller wraps it with the 0xFE0D
    /// extension type and length.
    static func outerExtensionData(configID: UInt8, kdfID: UInt16, aeadID: UInt16, enc: Data, payload: Data) -> Data {
        var data = Data()
        data.append(0x00) // outer ClientHello
        data.append(UInt8(kdfID >> 8)); data.append(UInt8(kdfID & 0xFF))
        data.append(UInt8(aeadID >> 8)); data.append(UInt8(aeadID & 0xFF))
        data.append(configID)
        data.append(UInt8(enc.count >> 8)); data.append(UInt8(enc.count & 0xFF))
        data.append(enc)
        data.append(UInt8(payload.count >> 8)); data.append(UInt8(payload.count & 0xFF))
        data.append(payload)
        return data
    }
}
