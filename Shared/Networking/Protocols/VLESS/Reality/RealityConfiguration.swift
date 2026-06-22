//
//  RealityConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

struct RealityConfiguration {
    let serverName: String          // SNI of the website to impersonate
    let publicKey: Data             // X25519, 32 bytes
    let shortId: Data               // 0-8 bytes
    let fingerprint: TLSFingerprint

    init(serverName: String, publicKey: Data, shortId: Data, fingerprint: TLSFingerprint = .chrome120) {
        self.serverName = serverName
        self.publicKey = publicKey
        self.shortId = shortId
        self.fingerprint = fingerprint
    }

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

        let fpString = params["fp"] ?? "chrome_120"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

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
    case chrome133 = "chrome_133"
    case chrome120 = "chrome_120"
    case chrome106 = "chrome_106"

    case firefox148 = "firefox_148"
    case firefox120 = "firefox_120"

    case safari26 = "safari_26"

    case edge106 = "edge_106"

    /// Minimal ClientHello for real (non-camouflage) handshakes, e.g. the MITM outer leg.
    /// Browser fingerprints advertise ALPS, which needs a ClientEncryptedExtensions we don't
    /// send — strict origins (e.g. Google's GFE) abort with `unexpected_message`.
    case nonBrowser = "non_browser"

    /// Tolerant decoder: an unknown saved fingerprint falls back to Chrome 120
    /// rather than failing to decode.
    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = TLSFingerprint(rawValue: raw) ?? .chrome120
    }

    var displayName: String {
        switch self {
        case .chrome133:  return "Chrome 133"
        case .chrome120:  return "Chrome 120"
        case .chrome106:  return "Chrome 106"
        case .firefox148: return "Firefox 148"
        case .firefox120: return "Firefox 120"
        case .safari26:   return "Safari 26.3"
        case .edge106:    return "Edge 106"
        case .nonBrowser: return "Non-Browser"
        }
    }

    /// User-selectable camouflage fingerprints; `nonBrowser` is intentionally excluded.
    static var allCases: [TLSFingerprint] {
        [.chrome133, .chrome120, .chrome106,
         .firefox148, .firefox120,
         .safari26,
         .edge106]
    }
}

enum RealityError: Error, LocalizedError {
    case missingParameter(String)
    case invalidPublicKey
    case handshakeFailed(String)
    case authenticationFailed
    case connectionFailed(String)
    case decryptionFailed  // Record no longer decrypts — server may have switched to direct copy

    var errorDescription: String? {
        switch self {
        case .missingParameter(let parameter):
            return "Missing Reality parameter: \(parameter)"
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
