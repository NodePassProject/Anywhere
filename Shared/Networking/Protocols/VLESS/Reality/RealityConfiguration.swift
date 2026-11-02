//
//  RealityConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated struct RealityConfiguration {
    let serverName: String          // SNI of the website to impersonate
    let publicKey: Data             // X25519, 32 bytes
    let shortId: Data               // 0-8 bytes
    let fingerprint: TLSFingerprint

    init(serverName: String, publicKey: Data, shortId: Data, fingerprint: TLSFingerprint = .default) {
        self.serverName = serverName
        self.publicKey = publicKey
        self.shortId = shortId
        self.fingerprint = fingerprint
    }

    static func parse(from params: [String: String]) throws -> RealityConfiguration? {
        guard params["security"] == "reality" else { return nil }

        guard let sni = params["sni"], !sni.isEmpty else {
            throw AnywhereError.proxy(.vless, .invalidConfiguration(detail: "missing parameter: sni"))
        }

        guard let pbkString = params["pbk"], !pbkString.isEmpty else {
            throw AnywhereError.proxy(.vless, .invalidConfiguration(detail: "missing parameter: pbk (public key)"))
        }

        guard let publicKey = Data(base64URLEncoded: pbkString), publicKey.count == 32 else {
            throw AnywhereError.tls(.reality(.invalidPublicKey))
        }

        let sidString = params["sid"] ?? ""
        let shortId = Data(hexString: sidString) ?? Data()

        let fingerprint = TLSFingerprint(linkValue: params["fp"])

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

nonisolated extension RealityConfiguration: Equatable, Hashable {
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

nonisolated enum TLSFingerprint: String, Codable, CaseIterable {
    case chrome133 = "chrome_133"
    case chrome120 = "chrome_120"
    case chrome106 = "chrome_106"

    case firefox148 = "firefox_148"
    case firefox120 = "firefox_120"

    case safari26 = "safari_26"

    case edge106 = "edge_106"
    
    case plain = "plain"
    
    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = TLSFingerprint(importValue: raw) ?? .default
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
        case .plain:      return "Plain"
        }
    }
    
    static var `default`: TLSFingerprint { TLSFingerprint.chrome133.supportedOnThisOS }

    init(linkValue: String?) {
        guard let linkValue, !linkValue.isEmpty else {
            self = .plain
            return
        }
        self = TLSFingerprint(importValue: linkValue) ?? .default
    }
    
    init?(importValue: String) {
        if let exact = TLSFingerprint(rawValue: importValue) {
            self = exact
            return
        }
        switch importValue.lowercased() {
        case "chrome":  self = TLSFingerprint.chrome133.supportedOnThisOS
        case "firefox": self = TLSFingerprint.firefox148.supportedOnThisOS
        case "safari":  self = TLSFingerprint.safari26.supportedOnThisOS
        case "edge":    self = TLSFingerprint.edge106.supportedOnThisOS
        case "plain":   self = .plain
        default:        return nil
        }
    }
    
    var supportedOnThisOS: TLSFingerprint {
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            return self
        }
        return withoutPostQuantum
    }

    var withoutPostQuantum: TLSFingerprint {
        switch self {
        case .chrome133:  return .chrome120
        case .firefox148: return .firefox120
        case .safari26:   return .chrome120
        default:          return self
        }
    }

    var offersPostQuantumKeyShare: Bool {
        withoutPostQuantum != self
    }
}
