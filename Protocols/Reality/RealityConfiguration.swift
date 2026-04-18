//
//  RealityConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Reality configuration for VLESS connections
struct RealityConfiguration {
    let serverName: String          // SNI (target website to impersonate)
    let publicKey: Data             // Server's X25519 public key (32 bytes)
    let shortId: Data               // 0-8 bytes identifier
    let fingerprint: TLSFingerprint // Browser fingerprint to mimic

    init(serverName: String, publicKey: Data, shortId: Data, fingerprint: TLSFingerprint = .chrome133) {
        self.serverName = serverName
        self.publicKey = publicKey
        self.shortId = shortId
        self.fingerprint = fingerprint
    }

    /// Parse Reality parameters from VLESS URL query parameters
    static func parse(from params: [String: String]) throws -> RealityConfiguration? {
        guard params["security"] == "reality" else { return nil }

        guard let sni = params["sni"], !sni.isEmpty else {
            throw RealityError.missingParameter("sni")
        }

        guard let pbkString = params["pbk"], !pbkString.isEmpty else {
            throw RealityError.missingParameter("pbk (public key)")
        }

        guard let publicKey = Data(base64URLEncoded: pbkString), publicKey.count == 32 else {
            throw RealityError.invalidPublicKey
        }

        let sidString = params["sid"] ?? ""
        let shortId = Data(hexString: sidString) ?? Data()

        let fpString = params["fp"] ?? "chrome_133"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome133

        return RealityConfiguration(
            serverName: sni,
            publicKey: publicKey,
            shortId: shortId,
            fingerprint: fingerprint
        )
    }
}

extension RealityConfiguration: Codable {
    enum CodingKeys: String, CodingKey {
        case serverName, publicKey, shortId, fingerprint
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try container.decode(String.self, forKey: .serverName)
        fingerprint = try container.decode(TLSFingerprint.self, forKey: .fingerprint)

        let publicKeyString = try container.decode(String.self, forKey: .publicKey)
        guard let pk = Data(base64URLEncoded: publicKeyString) else {
            throw DecodingError.dataCorruptedError(forKey: .publicKey, in: container, debugDescription: "Invalid base64url public key")
        }
        publicKey = pk

        let shortIdString = try container.decode(String.self, forKey: .shortId)
        shortId = Data(hexString: shortIdString) ?? Data()
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(serverName, forKey: .serverName)
        try container.encode(publicKey.base64URLEncodedString(), forKey: .publicKey)
        try container.encode(shortId.hexEncodedString(), forKey: .shortId)
        try container.encode(fingerprint, forKey: .fingerprint)
    }
}

extension RealityConfiguration: Equatable, Hashable {
    static func == (lhs: RealityConfiguration, rhs: RealityConfiguration) -> Bool {
        lhs.serverName == rhs.serverName &&
        lhs.publicKey == rhs.publicKey &&
        lhs.shortId == rhs.shortId &&
        lhs.fingerprint == rhs.fingerprint
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(serverName)
        hasher.combine(publicKey)
        hasher.combine(shortId)
        hasher.combine(fingerprint)
    }
}

enum TLSFingerprint: String, Codable, CaseIterable {
    // Latest / Auto fingerprints (matching uTLS Auto mappings)
    case chrome133 = "chrome_133"
    case firefox148 = "firefox_148"
    case safari26 = "safari_26"
    case ios14 = "ios_14"
    case edge85 = "edge_85"
    case android11 = "android_11"     // TLS 1.2 only — Reality only
    case qq11 = "qq_11"
    case browser360 = "360_7"         // TLS 1.2 only — Reality only

    // Legacy fingerprints (kept for backward compatibility)
    case chrome120 = "chrome_120"
    case firefox120 = "firefox_120"
    case safari16 = "safari_16"
    case edge106 = "edge_106"

    case random = "random"

    var displayName: String {
        switch self {
        case .chrome133:  return "Chrome 133"
        case .firefox148: return "Firefox 148"
        case .safari26:   return "Safari 26.3"
        case .ios14:      return "iOS 14"
        case .edge85:     return "Edge 85"
        case .android11:  return "Android 11"
        case .qq11:       return "QQ 11.1"
        case .browser360: return "360 Browser 7.5"
        case .chrome120:  return "Chrome 120"
        case .firefox120: return "Firefox 120"
        case .safari16:   return "Safari 16.0"
        case .edge106:    return "Edge 106"
        case .random:     return "Random"
        }
    }

    /// Whether this fingerprint supports TLS 1.3. Fingerprints that don't
    /// (Android 11, 360 Browser) can only be used with Reality protocol,
    /// which has its own authentication and doesn't complete a real TLS handshake.
    var supportsTLS13: Bool {
        switch self {
        case .android11, .browser360:
            return false
        default:
            return true
        }
    }

    /// All concrete (non-random) fingerprints for random selection.
    /// Excludes TLS 1.2-only fingerprints since they can't complete a standard TLS handshake.
    static let concreteFingerprints: [TLSFingerprint] = allCases.filter { $0 != .random && $0.supportsTLS13 }
}

/// Reality protocol errors
enum RealityError: Error, LocalizedError {
    case missingParameter(String)
    case invalidPublicKey
    case handshakeFailed(String)
    case authenticationFailed
    case connectionFailed(String)
    case decryptionFailed  // Server switched to direct copy mode

    var errorDescription: String? {
        switch self {
        case .missingParameter(let param):
            return "Missing Reality parameter: \(param)"
        case .invalidPublicKey:
            return "Invalid Reality public key"
        case .handshakeFailed(let reason):
            return "Reality handshake failed: \(reason)"
        case .authenticationFailed:
            return "Reality authentication failed"
        case .connectionFailed(let reason):
            return "Reality connection failed: \(reason)"
        case .decryptionFailed:
            return "Reality decryption failed - server may have switched to direct copy"
        }
    }
}
