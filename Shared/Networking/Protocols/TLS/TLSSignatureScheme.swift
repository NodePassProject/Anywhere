//
//  TLSSignatureScheme.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import Security

nonisolated enum TLSSignatureScheme {
    static let rsa_pkcs1_sha1: UInt16 = 0x0201
    static let ecdsa_sha1: UInt16 = 0x0203
    static let rsa_pkcs1_sha256: UInt16 = 0x0401
    static let rsa_pkcs1_sha384: UInt16 = 0x0501
    static let rsa_pkcs1_sha512: UInt16 = 0x0601
    static let ecdsa_secp256r1_sha256: UInt16 = 0x0403
    static let ecdsa_secp384r1_sha384: UInt16 = 0x0503
    static let ecdsa_secp521r1_sha512: UInt16 = 0x0603
    static let rsa_pss_rsae_sha256: UInt16 = 0x0804
    static let rsa_pss_rsae_sha384: UInt16 = 0x0805
    static let rsa_pss_rsae_sha512: UInt16 = 0x0806

    /// Signature schemes permitted in a TLS 1.3 `CertificateVerify` (RFC 8446 §4.2.3).
    static let tls13HandshakeSignatureAlgorithms: Set<UInt16> = [
        ecdsa_secp256r1_sha256,
        ecdsa_secp384r1_sha384,
        ecdsa_secp521r1_sha512,
        rsa_pss_rsae_sha256,
        rsa_pss_rsae_sha384,
        rsa_pss_rsae_sha512,
    ]

    /// Maps a TLS signature scheme to the `SecKeyAlgorithm` used to verify it.
    static func secKeyAlgorithm(for scheme: UInt16) -> SecKeyAlgorithm {
        switch scheme {
        case ecdsa_secp256r1_sha256: return .ecdsaSignatureMessageX962SHA256
        case ecdsa_secp384r1_sha384: return .ecdsaSignatureMessageX962SHA384
        case ecdsa_secp521r1_sha512: return .ecdsaSignatureMessageX962SHA512
        case ecdsa_sha1:             return .ecdsaSignatureMessageX962SHA1
        case rsa_pss_rsae_sha256:    return .rsaSignatureMessagePSSSHA256
        case rsa_pss_rsae_sha384:    return .rsaSignatureMessagePSSSHA384
        case rsa_pss_rsae_sha512:    return .rsaSignatureMessagePSSSHA512
        case rsa_pkcs1_sha256:       return .rsaSignatureMessagePKCS1v15SHA256
        case rsa_pkcs1_sha384:       return .rsaSignatureMessagePKCS1v15SHA384
        case rsa_pkcs1_sha512:       return .rsaSignatureMessagePKCS1v15SHA512
        case rsa_pkcs1_sha1:         return .rsaSignatureMessagePKCS1v15SHA1
        default:                     return .rsaSignatureMessagePSSSHA256
        }
    }
}

nonisolated enum TLS13CertificateVerifier {
    static func verify(
        transcriptBeforeCertVerify: Data?,
        algorithm: UInt16,
        signature: Data?,
        serverCertificates: [SecCertificate],
        keyDerivation: TLS13KeyDerivation?
    ) -> Error? {
        guard let keyDerivation else {
            return TLSError.handshakeFailed("Missing key derivation")
        }

        // Mandatory in a full handshake: the CertificateVerify (transcript + signature)
        // and a certificate to verify it against.
        guard let transcript = transcriptBeforeCertVerify,
              let signature,
              let serverCert = serverCertificates.first else {
            return TLSError.certificateValidationFailed("Full handshake missing CertificateVerify")
        }

        // Legal for a TLS 1.3 handshake signature (RFC 8446 §4.2.3).
        guard TLSSignatureScheme.tls13HandshakeSignatureAlgorithms.contains(algorithm) else {
            return TLSError.certificateValidationFailed("CertificateVerify algorithm not permitted")
        }

        guard let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            return TLSError.certificateValidationFailed("Failed to extract public key from certificate")
        }

        let transcriptHash = keyDerivation.transcriptHash(transcript)

        // RFC 8446 §4.4.3: 64 spaces, context string, a single 0x00, then the transcript hash.
        var content = Data(repeating: 0x20, count: 64)
        content.append("TLS 1.3, server CertificateVerify".data(using: .ascii)!)
        content.append(0x00)
        content.append(transcriptHash)

        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            serverPublicKey,
            TLSSignatureScheme.secKeyAlgorithm(for: algorithm),
            content as CFData,
            signature as CFData,
            &error
        )

        guard isValid else {
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            return TLSError.certificateValidationFailed("CertificateVerify failed: \(message)")
        }

        return nil
    }
}
