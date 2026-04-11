//
//  QUICCrypto.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation
import CryptoKit

enum QUICCrypto {

    /// Registers CryptoKit AEAD callbacks with the ngtcp2 C crypto backend.
    /// Must be called once before any QUIC connection is created.
    static func registerCallbacks() {
        ngtcp2_crypto_apple_set_aead_callbacks(aeadEncrypt, aeadDecrypt)
    }
}

// MARK: - AEAD Encrypt Callback

/// CryptoKit-based AEAD encryption called from the C crypto backend.
/// Writes ciphertext + 16-byte tag to `dest`.
private let aeadEncrypt: @convention(c) (
    UnsafeMutablePointer<UInt8>?,    // dest
    UnsafePointer<UInt8>?,           // key
    Int,                              // keylen
    UnsafePointer<UInt8>?,           // nonce
    Int,                              // noncelen
    UnsafePointer<UInt8>?,           // plaintext
    Int,                              // plaintextlen
    UnsafePointer<UInt8>?,           // aad
    Int,                              // aadlen
    Int32                             // aead_type
) -> Int32 = { dest, key, keylen, nonce, noncelen, plaintext, plaintextlen, aad, aadlen, aeadType in
    guard let dest, let key, let nonce else { return -1 }

    let symmetricKey = SymmetricKey(data: UnsafeBufferPointer(start: key, count: keylen))
    let nonceData = Data(bytes: nonce, count: noncelen)

    let ptData: Data
    if let plaintext, plaintextlen > 0 {
        ptData = Data(bytes: plaintext, count: plaintextlen)
    } else {
        ptData = Data()
    }

    let aadData: Data
    if let aad, aadlen > 0 {
        aadData = Data(bytes: aad, count: aadlen)
    } else {
        aadData = Data()
    }

    do {
        switch aeadType {
        case NGTCP2_APPLE_AEAD_AES_128_GCM, NGTCP2_APPLE_AEAD_AES_256_GCM:
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealed = try AES.GCM.seal(ptData, using: symmetricKey, nonce: gcmNonce,
                                          authenticating: aadData)
            // Copy ciphertext + tag to dest
            sealed.ciphertext.copyBytes(to: dest, count: sealed.ciphertext.count)
            sealed.tag.copyBytes(to: dest.advanced(by: sealed.ciphertext.count),
                                count: sealed.tag.count)
            return 0

        case NGTCP2_APPLE_AEAD_CHACHA20_POLY1305:
            let ccNonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealed = try ChaChaPoly.seal(ptData, using: symmetricKey, nonce: ccNonce,
                                            authenticating: aadData)
            sealed.ciphertext.copyBytes(to: dest, count: sealed.ciphertext.count)
            sealed.tag.copyBytes(to: dest.advanced(by: sealed.ciphertext.count),
                                count: sealed.tag.count)
            return 0

        default:
            return -1
        }
    } catch {
        return -1
    }
}

// MARK: - AEAD Decrypt Callback

/// CryptoKit-based AEAD decryption called from the C crypto backend.
/// Expects ciphertext + 16-byte tag in `ciphertext`, writes plaintext to `dest`.
private let aeadDecrypt: @convention(c) (
    UnsafeMutablePointer<UInt8>?,    // dest
    UnsafePointer<UInt8>?,           // key
    Int,                              // keylen
    UnsafePointer<UInt8>?,           // nonce
    Int,                              // noncelen
    UnsafePointer<UInt8>?,           // ciphertext (includes tag)
    Int,                              // ciphertextlen (includes tag)
    UnsafePointer<UInt8>?,           // aad
    Int,                              // aadlen
    Int32                             // aead_type
) -> Int32 = { dest, key, keylen, nonce, noncelen, ciphertext, ciphertextlen, aad, aadlen, aeadType in
    guard let dest, let key, let nonce, let ciphertext else { return -1 }

    let tagLen = 16
    guard ciphertextlen >= tagLen else { return -1 }

    let symmetricKey = SymmetricKey(data: UnsafeBufferPointer(start: key, count: keylen))
    let nonceData = Data(bytes: nonce, count: noncelen)
    let ctLen = ciphertextlen - tagLen
    let ctData = Data(bytes: ciphertext, count: ctLen)
    let tagData = Data(bytes: ciphertext.advanced(by: ctLen), count: tagLen)

    let aadData: Data
    if let aad, aadlen > 0 {
        aadData = Data(bytes: aad, count: aadlen)
    } else {
        aadData = Data()
    }

    do {
        switch aeadType {
        case NGTCP2_APPLE_AEAD_AES_128_GCM, NGTCP2_APPLE_AEAD_AES_256_GCM:
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ctData, tag: tagData)
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey,
                                             authenticating: aadData)
            plaintext.copyBytes(to: UnsafeMutableRawBufferPointer(start: dest, count: plaintext.count))
            return 0

        case NGTCP2_APPLE_AEAD_CHACHA20_POLY1305:
            let ccNonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: ccNonce, ciphertext: ctData, tag: tagData)
            let plaintext = try ChaChaPoly.open(sealedBox, using: symmetricKey,
                                               authenticating: aadData)
            plaintext.copyBytes(to: UnsafeMutableRawBufferPointer(start: dest, count: plaintext.count))
            return 0

        default:
            return -1
        }
    } catch {
        return -1
    }
}
