//
//  TLSConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

enum TLSVersion: UInt16, Codable {
    case tls10 = 0x0301
    case tls11 = 0x0302
    case tls12 = 0x0303
    case tls13 = 0x0304
}

/// Standard TLS transport configuration for VLESS connections.
struct TLSConfiguration {
    let serverName: String              // SNI (defaults to server address)
    let alpn: [String]?                 // e.g. ["h2", "http/1.1"]
    let minVersion: TLSVersion?         // nil = no constraint
    let maxVersion: TLSVersion?         // nil = no constraint

    /// Encrypted Client Hello config: a base64 ECHConfigList (as published for
    /// the server), decoded and sealed against just before the handshake.
    /// `nil` = no ECH.
    let echConfig: String?

    let fingerprint: TLSFingerprint

    init(serverName: String, alpn: [String]? = nil,
         minVersion: TLSVersion? = nil, maxVersion: TLSVersion? = nil,
         echConfig: String? = nil,
         fingerprint: TLSFingerprint = .chrome120) {
        self.serverName = serverName
        self.alpn = alpn
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.echConfig = echConfig
        self.fingerprint = fingerprint
    }

    /// Parse TLS parameters from VLESS URL query parameters.
    /// Expected: `security=tls&sni=example.com&alpn=h2,http/1.1&fp=chrome_133[&minVersion=1.2&maxVersion=1.3]`
    static func parse(from params: [String: String], serverAddress: String) throws -> TLSConfiguration? {
        guard params["security"] == "tls" else { return nil }

        let sni = params["sni"] ?? serverAddress

        var alpn: [String]? = nil
        if let alpnString = params["alpn"], !alpnString.isEmpty {
            alpn = alpnString.split(separator: ",").map { String($0) }
        }

        let fpString = params["fp"] ?? "chrome_120"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

        let minVersion = Self.parseTLSVersion(params["minVersion"])
        let maxVersion = Self.parseTLSVersion(params["maxVersion"])

        let ech = (params["ech"]?.isEmpty == false) ? params["ech"] : nil

        return TLSConfiguration(
            serverName: sni,
            alpn: alpn,
            minVersion: minVersion,
            maxVersion: maxVersion,
            echConfig: ech,
            fingerprint: fingerprint
        )
    }

    private static func parseTLSVersion(_ string: String?) -> TLSVersion? {
        switch string {
        case "1.0": return .tls10
        case "1.1": return .tls11
        case "1.2": return .tls12
        case "1.3": return .tls13
        default:    return nil
        }
    }

    /// The percent-encoded `ech=` query value for a `vless://` URL, or nil when ECH is unset.
    /// Encodes `+`, `/`, and `=` so a base64 ECHConfigList survives the URL round-trip
    /// (a bare `+` would otherwise decode back to a space).
    var echQueryValue: String? {
        guard let ech = echConfig, !ech.isEmpty else { return nil }
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&#=+/")
        return ech.addingPercentEncoding(withAllowedCharacters: allowed) ?? ech
    }
}

extension TLSConfiguration: Codable {
    enum CodingKeys: String, CodingKey {
        case serverName, alpn, fingerprint, minVersion, maxVersion, echConfig
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try container.decode(String.self, forKey: .serverName)
        alpn = try container.decodeIfPresent([String].self, forKey: .alpn)
        fingerprint = try container.decodeIfPresent(TLSFingerprint.self, forKey: .fingerprint) ?? .chrome120
        minVersion = try container.decodeIfPresent(TLSVersion.self, forKey: .minVersion)
        maxVersion = try container.decodeIfPresent(TLSVersion.self, forKey: .maxVersion)
        echConfig = try container.decodeIfPresent(String.self, forKey: .echConfig)
    }
}

extension TLSConfiguration: Equatable, Hashable {
    static func == (lhs: TLSConfiguration, rhs: TLSConfiguration) -> Bool {
        lhs.serverName == rhs.serverName &&
        lhs.alpn == rhs.alpn &&
        lhs.fingerprint == rhs.fingerprint &&
        lhs.minVersion == rhs.minVersion &&
        lhs.maxVersion == rhs.maxVersion &&
        lhs.echConfig == rhs.echConfig
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(serverName)
        hasher.combine(alpn)
        hasher.combine(fingerprint)
        hasher.combine(minVersion)
        hasher.combine(maxVersion)
        hasher.combine(echConfig)
    }
}

enum TLSError: Error, LocalizedError {
    case handshakeFailed(String)
    case certificateValidationFailed(String)
    case connectionFailed(String)
    case unsupportedTLSVersion
    case alert(level: UInt8, description: UInt8)
    /// The server replied with a HelloRetryRequest, which this client does not
    /// support (it would require a second ClientHello flight).
    case helloRetryRequest
    /// The server rejected ECH. `retryConfigList`, if present, is a fresh
    /// ECHConfigList the server offered for a retry.
    case echRejected(retryConfigList: Data?)

    var errorDescription: String? {
        switch self {
        case .handshakeFailed(let reason):
            return "TLS handshake failed: \(reason)"
        case .certificateValidationFailed(let reason):
            return "TLS certificate validation failed: \(reason)"
        case .connectionFailed(let reason):
            return "TLS connection failed: \(reason)"
        case .unsupportedTLSVersion:
            return "Server TLS version not supported"
        case .alert(let level, let description):
            return "TLS alert: level=\(level), description=\(description)"
        case .helloRetryRequest:
            return "TLS server sent HelloRetryRequest (unsupported)"
        case .echRejected(let retryConfigList):
            return "TLS server rejected ECH" + (retryConfigList != nil ? " (retry config offered)" : "")
        }
    }
}
