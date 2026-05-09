//
//  ShadowsocksCipher.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

/// Supported Shadowsocks AEAD cipher methods.
enum ShadowsocksCipher {
    case aes128gcm
    case aes256gcm
    case chacha20poly1305
    case none
    // Shadowsocks 2022 (BLAKE3-based)
    case blake3aes128gcm
    case blake3aes256gcm
    case blake3chacha20poly1305

    var keySize: Int {
        switch self {
        case .aes128gcm, .blake3aes128gcm: return 16
        case .aes256gcm, .chacha20poly1305: return 32
        case .blake3aes256gcm, .blake3chacha20poly1305: return 32
        case .none: return 0
        }
    }

    /// Salt size (also called IV size in Xray-core). Equals keySize for all ciphers.
    var saltSize: Int { keySize }

    /// AEAD authentication tag size (16 for all AEAD ciphers).
    var tagSize: Int {
        switch self {
        case .none: return 0
        default: return 16
        }
    }

    /// AEAD nonce size (12 for GCM and ChaCha20-Poly1305).
    var nonceSize: Int {
        switch self {
        case .none: return 0
        default: return 12
        }
    }

    /// Whether this is a Shadowsocks 2022 cipher.
    var isSS2022: Bool {
        switch self {
        case .blake3aes128gcm, .blake3aes256gcm, .blake3chacha20poly1305: return true
        default: return false
        }
    }

    init?(method: String) {
        switch method.lowercased() {
        case "aes-128-gcm": self = .aes128gcm
        case "aes-256-gcm": self = .aes256gcm
        case "chacha20-ietf-poly1305", "chacha20-poly1305": self = .chacha20poly1305
        case "none", "plain": self = .none
        case "2022-blake3-aes-128-gcm": self = .blake3aes128gcm
        case "2022-blake3-aes-256-gcm": self = .blake3aes256gcm
        case "2022-blake3-chacha20-poly1305": self = .blake3chacha20poly1305
        default: return nil
        }
    }
}
