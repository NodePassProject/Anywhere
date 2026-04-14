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
///
/// Input buffers are wrapped with `Data(bytesNoCopy:deallocator:.none)` —
/// non-owning views into ngtcp2's memory. The callback is synchronous and
/// CryptoKit only reads via `withUnsafeBytes`, so borrowing is safe and
/// avoids the ~1.3 KB memcpy + `Data` alloc per packet.
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
    let nonceData = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: nonce),
        count: noncelen, deallocator: .none
    )
    let ptData: Data = (plaintext != nil && plaintextlen > 0)
        ? Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: plaintext!),
               count: plaintextlen, deallocator: .none)
        : Data()
    let aadData: Data = (aad != nil && aadlen > 0)
        ? Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: aad!),
               count: aadlen, deallocator: .none)
        : Data()

    do {
        switch aeadType {
        case NGTCP2_APPLE_AEAD_AES_128_GCM, NGTCP2_APPLE_AEAD_AES_256_GCM:
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealed = try AES.GCM.seal(ptData, using: symmetricKey, nonce: gcmNonce,
                                          authenticating: aadData)
            let ctLen = sealed.ciphertext.count
            sealed.ciphertext.withUnsafeBytes { buf in
                if let base = buf.baseAddress, ctLen > 0 {
                    memcpy(dest, base, ctLen)
                }
            }
            sealed.tag.withUnsafeBytes { buf in
                if let base = buf.baseAddress {
                    memcpy(dest.advanced(by: ctLen), base, buf.count)
                }
            }
            return 0

        case NGTCP2_APPLE_AEAD_CHACHA20_POLY1305:
            let ccNonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealed = try ChaChaPoly.seal(ptData, using: symmetricKey, nonce: ccNonce,
                                            authenticating: aadData)
            let ctLen = sealed.ciphertext.count
            sealed.ciphertext.withUnsafeBytes { buf in
                if let base = buf.baseAddress, ctLen > 0 {
                    memcpy(dest, base, ctLen)
                }
            }
            sealed.tag.withUnsafeBytes { buf in
                if let base = buf.baseAddress {
                    memcpy(dest.advanced(by: ctLen), base, buf.count)
                }
            }
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
///
/// Same zero-copy strategy as `aeadEncrypt`.
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
    let ctLen = ciphertextlen - tagLen

    let symmetricKey = SymmetricKey(data: UnsafeBufferPointer(start: key, count: keylen))
    let nonceData = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: nonce),
        count: noncelen, deallocator: .none
    )
    let ctData = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: ciphertext),
        count: ctLen, deallocator: .none
    )
    let tagData = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: ciphertext.advanced(by: ctLen)),
        count: tagLen, deallocator: .none
    )
    let aadData: Data = (aad != nil && aadlen > 0)
        ? Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: aad!),
               count: aadlen, deallocator: .none)
        : Data()

    do {
        switch aeadType {
        case NGTCP2_APPLE_AEAD_AES_128_GCM, NGTCP2_APPLE_AEAD_AES_256_GCM:
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ctData, tag: tagData)
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey,
                                             authenticating: aadData)
            plaintext.withUnsafeBytes { buf in
                if let base = buf.baseAddress, buf.count > 0 {
                    memcpy(dest, base, buf.count)
                }
            }
            return 0

        case NGTCP2_APPLE_AEAD_CHACHA20_POLY1305:
            let ccNonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: ccNonce, ciphertext: ctData, tag: tagData)
            let plaintext = try ChaChaPoly.open(sealedBox, using: symmetricKey,
                                               authenticating: aadData)
            plaintext.withUnsafeBytes { buf in
                if let base = buf.baseAddress, buf.count > 0 {
                    memcpy(dest, base, buf.count)
                }
            }
            return 0

        default:
            return -1
        }
    } catch {
        return -1
    }
}
