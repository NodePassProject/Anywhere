//
//  TLSCipherSuite.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSCipherSuite {
    // TLS 1.3
    static let TLS_AES_128_GCM_SHA256: UInt16 = 0x1301
    static let TLS_AES_256_GCM_SHA384: UInt16 = 0x1302
    static let TLS_CHACHA20_POLY1305_SHA256: UInt16 = 0x1303

    // TLS 1.2 ECDHE AEAD
    static let TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: UInt16 = 0xC02B
    static let TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: UInt16 = 0xC02C
    static let TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: UInt16 = 0xC02F
    static let TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: UInt16 = 0xC030
    static let TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: UInt16 = 0xCCA9
    static let TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: UInt16 = 0xCCA8

    // TLS 1.2 ECDHE CBC
    static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: UInt16 = 0xC009
    static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: UInt16 = 0xC00A
    static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: UInt16 = 0xC013
    static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: UInt16 = 0xC014
    static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: UInt16 = 0xC023
    static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: UInt16 = 0xC024
    static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: UInt16 = 0xC027
    static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: UInt16 = 0xC028

    // TLS 1.2 RSA AEAD
    static let TLS_RSA_WITH_AES_128_GCM_SHA256: UInt16 = 0x009C
    static let TLS_RSA_WITH_AES_256_GCM_SHA384: UInt16 = 0x009D

    // TLS 1.2 RSA CBC
    static let TLS_RSA_WITH_AES_128_CBC_SHA: UInt16 = 0x002F
    static let TLS_RSA_WITH_AES_256_CBC_SHA: UInt16 = 0x0035
    static let TLS_RSA_WITH_AES_128_CBC_SHA256: UInt16 = 0x003C
    static let TLS_RSA_WITH_AES_256_CBC_SHA256: UInt16 = 0x003D

    // MARK: - Cipher Suite Properties

    static func isECDHE(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
             TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
             TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
             TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return true
        default:
            return false
        }
    }

    static func isAEAD(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
             TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
             TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384:
            return true
        default:
            return false
        }
    }

    static func isChaCha20(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_CHACHA20_POLY1305_SHA256,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return true
        default:
            return false
        }
    }

    static func usesSHA384(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_AES_256_GCM_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
             TLS_RSA_WITH_AES_256_GCM_SHA384:
            return true
        default:
            return false
        }
    }

    static func keyLength(_ suite: UInt16) -> Int {
        switch suite {
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
             TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
             TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA256,
             TLS_RSA_WITH_AES_256_GCM_SHA384,
             TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
            return 32
        default:
            return 16
        }
    }

    static func ivLength(_ suite: UInt16) -> Int {
        if isChaCha20(suite) { return 12 }
        if isAEAD(suite) { return 4 }
        return 16
    }

    static func macLength(_ suite: UInt16) -> Int {
        if isAEAD(suite) { return 0 }
        if usesSHA384(suite) { return 48 }
        switch suite {
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
             TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256:
            return 32
        default:
            return 20
        }
    }
}
