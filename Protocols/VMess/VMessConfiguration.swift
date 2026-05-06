//
//  VMessConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import Foundation

enum VMessSecurity: String, CaseIterable, Codable, Hashable {
    case auto
    case aes128GCM = "aes-128-gcm"
    case chacha20Poly1305 = "chacha20-poly1305"
    case none
    case zero

    init(normalized rawValue: String?) {
        let value = (rawValue ?? "auto").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch value {
        case "", "auto":
            self = .auto
        case "aes-128-gcm", "aes128-gcm", "aes128gcm":
            self = .aes128GCM
        case "chacha20-poly1305", "chacha20-ietf-poly1305", "chacha20poly1305":
            self = .chacha20Poly1305
        case "none":
            self = .none
        case "zero":
            self = .zero
        default:
            self = .auto
        }
    }

    var displayName: String {
        switch self {
        case .auto:
            "Auto"
        case .aes128GCM:
            "AES-128-GCM"
        case .chacha20Poly1305:
            "ChaCha20-Poly1305"
        case .none:
            "None"
        case .zero:
            "Zero"
        }
    }

    var requestSecurity: VMessSecurity {
        switch self {
        case .auto:
            return .aes128GCM
        default:
            return self
        }
    }

    var wireValue: UInt8 {
        switch requestSecurity {
        case .auto:
            return VMessSecurity.aes128GCM.wireValue
        case .aes128GCM:
            return 0x03
        case .chacha20Poly1305:
            return 0x04
        case .none:
            return 0x05
        case .zero:
            return 0x05
        }
    }

    var usesChunkStream: Bool {
        self != .zero
    }

    var usesGlobalPadding: Bool {
        switch requestSecurity {
        case .aes128GCM, .chacha20Poly1305:
            return true
        case .auto, .none, .zero:
            return false
        }
    }

    var aeadTagSize: Int {
        switch requestSecurity {
        case .aes128GCM, .chacha20Poly1305:
            return 16
        case .auto, .none, .zero:
            return 0
        }
    }
}

struct VMessConfiguration: Hashable {
    var uuid: UUID
    var security: VMessSecurity
    var alterId: Int
    var transport: TransportLayer
    var securityLayer: SecurityLayer
    var muxEnabled: Bool

    init(
        uuid: UUID,
        security: VMessSecurity = .auto,
        alterId: Int = 0,
        transport: TransportLayer = .tcp,
        securityLayer: SecurityLayer = .none,
        muxEnabled: Bool = false
    ) {
        self.uuid = uuid
        self.security = security
        self.alterId = max(0, alterId)
        self.transport = transport
        self.securityLayer = securityLayer
        self.muxEnabled = muxEnabled
    }
}
