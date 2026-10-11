//
//  QUICCipherSuite.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public enum QUICCipherSuite: UInt16, Hashable, CaseIterable, Sendable {
    case TLS_AES_128_GCM_SHA256 = 0x1301
    case TLS_AES_256_GCM_SHA384 = 0x1302
    case TLS_CHACHA20_POLY1305_SHA256 = 0x1303

    var hash: HashAlgorithm {
        switch self {
        case .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256:
            return .sha256
        case .TLS_AES_256_GCM_SHA384:
            return .sha384
        }
    }

    var aead: AEADAlgorithm {
        switch self {
        case .TLS_AES_128_GCM_SHA256:
            return .aes128GCM
        case .TLS_AES_256_GCM_SHA384:
            return .aes256GCM
        case .TLS_CHACHA20_POLY1305_SHA256:
            return .chaCha20Poly1305
        }
    }
}

public enum QUICEncryptionLevel: Hashable, CaseIterable, Sendable {
    case initial
    case handshake
    case application
}

enum HashAlgorithm: Hashable, Sendable {
    case sha256
    case sha384

    var digestLength: Int {
        switch self {
        case .sha256:
            return 32
        case .sha384:
            return 48
        }
    }
}

enum AEADAlgorithm: Hashable, Sendable {
    case aes128GCM
    case aes256GCM
    case chaCha20Poly1305

    static let tagLength = 16
    static let nonceLength = 12

    var keyLength: Int {
        switch self {
        case .aes128GCM:
            return 16
        case .aes256GCM, .chaCha20Poly1305:
            return 32
        }
    }

    var confidentialityLimit: UInt64 {
        switch self {
        case .aes128GCM, .aes256GCM:
            return 1 << 23
        case .chaCha20Poly1305:
            return 1 << 62
        }
    }

    var integrityLimit: UInt64 {
        switch self {
        case .aes128GCM, .aes256GCM:
            return 1 << 52
        case .chaCha20Poly1305:
            return 1 << 36
        }
    }
}
