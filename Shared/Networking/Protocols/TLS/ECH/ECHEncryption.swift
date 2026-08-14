//
//  ECHEncryption.swift
//  Anywhere
//
//  Created by NodePassProject on 6/14/26.
//

import Foundation
import CryptoKit

nonisolated final class ECHClientContext {
    let config: ECHConfig
    let cipherSuite: ECHCipherSuite
    let encapsulatedKey: Data

    private var sender: HPKE.Sender

    var innerTranscriptMessage = Data()

    var innerRandom = Data()

    enum Outcome {
        case undetermined
        case accepted
        case rejected(retryConfigList: Data?)
    }
    var outcome: Outcome = .undetermined

    var isRejected: Bool {
        if case .rejected = outcome { return true }
        return false
    }

    private let sealClaim = OneShotLatch()

    init(config: ECHConfig, cipherSuite: ECHCipherSuite) throws {
        self.config = config
        self.cipherSuite = cipherSuite

        guard config.kemID == ECHKemID.dhkemX25519HKDFSHA256 else {
            throw AnywhereError.tls(.ech(.unsupportedKEM))
        }
        guard let kdf = ECHEncryption.hpkeKDF(cipherSuite.kdfID) else {
            throw AnywhereError.tls(.ech(.unsupportedKDF))
        }
        guard let aead = ECHEncryption.hpkeAEAD(cipherSuite.aeadID) else {
            throw AnywhereError.tls(.ech(.unsupportedAEAD))
        }

        let recipientKey: Curve25519.KeyAgreement.PublicKey
        do {
            recipientKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: config.publicKey)
        } catch {
            throw AnywhereError.tls(.ech(.invalidPublicKey))
        }

        let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: kdf, aead: aead)

        var info = Data("tls ech".utf8)
        info.append(0x00)
        info.append(config.raw)

        let createdSender: HPKE.Sender
        do {
            createdSender = try HPKE.Sender(recipientKey: recipientKey, ciphersuite: suite, info: info)
        } catch {
            throw AnywhereError.tls(.ech(.hpkeSetupFailed))
        }
        self.sender = createdSender
        self.encapsulatedKey = createdSender.encapsulatedKey
    }

    func seal(plaintext: Data, aad: Data) throws -> Data {
        guard sealClaim.claim() else {
            throw AnywhereError.tls(.ech(.sealFailed))
        }
        do {
            return try sender.seal(plaintext, authenticating: aad)
        } catch {
            throw AnywhereError.tls(.ech(.sealFailed))
        }
    }
}

nonisolated enum ECHEncryption {
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

    static func encodeInnerClientHello(_ innerMessage: Data, serverName: String, maxNameLength: Int) throws -> Data {
        guard innerMessage.count >= 4 else { throw AnywhereError.tls(.ech(.malformedInnerHello)) }

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
