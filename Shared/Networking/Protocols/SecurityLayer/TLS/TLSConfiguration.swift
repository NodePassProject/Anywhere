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

    /// Master switch for Encrypted Client Hello. With an inline `echConfig` that
    /// ECHConfigList is used; without one, it is discovered at connect time from
    /// the server domain's DNS HTTPS record (RFC 9460 SvcParamKey 5, `ech`) —
    /// fail-closed, so a connection that finds none errors out rather than sending
    /// the real SNI in the clear. `false` = ordinary cleartext-SNI handshake.
    let echEnabled: Bool

    /// Inline Encrypted Client Hello config: a base64 ECHConfigList (as published
    /// for the server), decoded and sealed against just before the handshake.
    /// `nil` when ECH is off, or when it is on but the config is to be discovered
    /// from DNS (see `echEnabled` / `echIsOpportunistic`).
    let echConfig: String?

    /// ECH is on but carries no inline config, so the ECHConfigList must be
    /// discovered from DNS. Derived rather than stored: callers only ever set
    /// "enabled" plus an optional config, and the inline/opportunistic split
    /// falls out here.
    var echIsOpportunistic: Bool { echEnabled && echConfig == nil }

    let fingerprint: TLSFingerprint

    init(serverName: String, alpn: [String]? = nil,
         minVersion: TLSVersion? = nil, maxVersion: TLSVersion? = nil,
         echEnabled: Bool? = nil, echConfig: String? = nil,
         fingerprint: TLSFingerprint = .chrome120) {
        self.serverName = serverName
        self.alpn = alpn
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        // Normalize an empty inline config to nil so `echConfig == nil` is the one
        // canonical "no inline ECH" test everywhere.
        let inlineECH = (echConfig?.isEmpty ?? true) ? nil : echConfig
        // Default ECH on whenever an inline config is supplied — covers share
        // links and configs saved before the flag existed; pass `echEnabled`
        // explicitly to force it (opportunistic, no config) or to suppress it.
        self.echEnabled = echEnabled ?? (inlineECH != nil)
        self.echConfig = inlineECH
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
    /// (a bare `+` would otherwise decode back to a space). Opportunistic mode (no inline
    /// config) is not carried in share links — it is sourced from a Clash `ech-opts` block.
    var echQueryValue: String? {
        guard let ech = echConfig, !ech.isEmpty else { return nil }
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&#=+/")
        return ech.addingPercentEncoding(withAllowedCharacters: allowed) ?? ech
    }
}

extension TLSConfiguration: Codable {
    enum CodingKeys: String, CodingKey {
        case serverName, alpn, fingerprint, minVersion, maxVersion, echEnabled, echConfig
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try container.decode(String.self, forKey: .serverName)
        alpn = try container.decodeIfPresent([String].self, forKey: .alpn)
        fingerprint = try container.decodeIfPresent(TLSFingerprint.self, forKey: .fingerprint) ?? .chrome120
        minVersion = try container.decodeIfPresent(TLSVersion.self, forKey: .minVersion)
        maxVersion = try container.decodeIfPresent(TLSVersion.self, forKey: .maxVersion)
        let rawECH = try container.decodeIfPresent(String.self, forKey: .echConfig)
        let inlineECH = (rawECH?.isEmpty ?? true) ? nil : rawECH
        // Absent flag → infer from inline config, so configs saved before the
        // flag existed (inline ECH only) keep ECH enabled.
        echEnabled = try container.decodeIfPresent(Bool.self, forKey: .echEnabled) ?? (inlineECH != nil)
        echConfig = inlineECH
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(serverName, forKey: .serverName)
        try container.encodeIfPresent(alpn, forKey: .alpn)
        try container.encode(fingerprint, forKey: .fingerprint)
        try container.encodeIfPresent(minVersion, forKey: .minVersion)
        try container.encodeIfPresent(maxVersion, forKey: .maxVersion)
        // Persist the flag only when it can't be inferred from `echConfig`
        // presence, so existing inline / no-ECH configs serialize unchanged.
        if echEnabled != (echConfig != nil) { try container.encode(echEnabled, forKey: .echEnabled) }
        try container.encodeIfPresent(echConfig, forKey: .echConfig)
    }
}

extension TLSConfiguration: Equatable, Hashable {
    static func == (lhs: TLSConfiguration, rhs: TLSConfiguration) -> Bool {
        lhs.serverName == rhs.serverName &&
        lhs.alpn == rhs.alpn &&
        lhs.fingerprint == rhs.fingerprint &&
        lhs.minVersion == rhs.minVersion &&
        lhs.maxVersion == rhs.maxVersion &&
        lhs.echEnabled == rhs.echEnabled &&
        lhs.echConfig == rhs.echConfig
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(serverName)
        hasher.combine(alpn)
        hasher.combine(fingerprint)
        hasher.combine(minVersion)
        hasher.combine(maxVersion)
        hasher.combine(echEnabled)
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
