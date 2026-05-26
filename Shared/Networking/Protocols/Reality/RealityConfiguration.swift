//
//  RealityConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
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

    // Legacy fingerprints (kept for backward compatibility)
    case chrome120 = "chrome_120"
    case firefox120 = "firefox_120"
    case safari16 = "safari_16"
    case edge106 = "edge_106"

    case random = "random"

    /// Internal, non-camouflage fingerprint for REAL handshakes (e.g. the MITM
    /// outer leg). Emits a minimal, standards-correct TLS 1.3/1.2 ClientHello
    /// that advertises only capabilities we actually implement — no GREASE,
    /// ALPS, certificate compression, ECH, padding, or extension shuffle. A
    /// browser fingerprint advertises ALPS, which commits the client to send a
    /// ``ClientEncryptedExtensions`` message we don't implement; strict origins
    /// (Google's GFE) then abort with `unexpected_message`. Deliberately
    /// excluded from ``allCases`` so it never appears in proxy pickers or gets
    /// chosen by ``random``.
    case nonBrowser = "non_browser"

    var displayName: String {
        switch self {
        case .chrome133:  return "Chrome 133"
        case .firefox148: return "Firefox 148"
        case .safari26:   return "Safari 26.3"
        case .ios14:      return "iOS 14"
        case .edge85:     return "Edge 85"
        case .chrome120:  return "Chrome 120"
        case .firefox120: return "Firefox 120"
        case .safari16:   return "Safari 16.0"
        case .edge106:    return "Edge 106"
        case .random:     return "Random"
        case .nonBrowser: return "Non-Browser"
        }
    }

    /// User-selectable fingerprints. ``nonBrowser`` is intentionally omitted —
    /// it's an internal real-handshake fingerprint, not a camouflage option, so
    /// it must not surface in proxy pickers or be reachable via ``random``.
    /// (Manually maintained: add new camouflage fingerprints here too.)
    static var allCases: [TLSFingerprint] {
        [.chrome133, .firefox148, .safari26, .ios14, .edge85,
         .chrome120, .firefox120, .safari16, .edge106, .random]
    }

    /// All concrete (non-random) fingerprints for random selection.
    /// Excludes TLS 1.2-only fingerprints since they can't complete a standard TLS handshake.
    static let concreteFingerprints: [TLSFingerprint] = allCases.filter { $0 != .random }
}

/// Reality protocol errors
enum RealityError: Error, LocalizedError {
    case missingParameter(String)
    case invalidPublicKey
    case handshakeFailed(String)
    case authenticationFailed
    case connectionFailed(String)
    case decryptionFailed  // Server switched to direct copy mode
    case tlsAlert(level: UInt8, description: UInt8)  // Peer sent a non-close_notify TLS alert

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
        case .tlsAlert(let level, let description):
            let kind = level == 2 ? "fatal" : "warning"
            return "TLS alert received: \(RealityError.alertName(description)) (\(kind), code \(description))"
        }
    }

    /// Human name for a TLS alert description code (RFC 8446 §6).
    static func alertName(_ code: UInt8) -> String {
        switch code {
        case 0:   return "close_notify"
        case 10:  return "unexpected_message"
        case 20:  return "bad_record_mac"
        case 22:  return "record_overflow"
        case 40:  return "handshake_failure"
        case 42:  return "bad_certificate"
        case 43:  return "unsupported_certificate"
        case 44:  return "certificate_revoked"
        case 45:  return "certificate_expired"
        case 46:  return "certificate_unknown"
        case 47:  return "illegal_parameter"
        case 48:  return "unknown_ca"
        case 49:  return "access_denied"
        case 50:  return "decode_error"
        case 51:  return "decrypt_error"
        case 70:  return "protocol_version"
        case 71:  return "insufficient_security"
        case 80:  return "internal_error"
        case 86:  return "inappropriate_fallback"
        case 90:  return "user_canceled"
        case 109: return "missing_extension"
        case 110: return "unsupported_extension"
        case 112: return "unrecognized_name"
        case 113: return "bad_certificate_status_response"
        case 115: return "unknown_psk_identity"
        case 116: return "certificate_required"
        case 120: return "no_application_protocol"
        default:  return "alert_\(code)"
        }
    }
}
