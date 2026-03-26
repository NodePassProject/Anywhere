//
//  TLSConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Standard TLS transport configuration for VLESS connections.
struct TLSConfiguration {
    let serverName: String              // SNI (defaults to server address)
    let alpn: [String]?                 // ALPN protocols (e.g. ["h2", "http/1.1"])
    let fingerprint: TLSFingerprint     // Browser fingerprint to mimic
    let minVersion: TLSVersion?         // Minimum TLS version (nil = no constraint)
    let maxVersion: TLSVersion?         // Maximum TLS version (nil = no constraint)

    init(serverName: String, alpn: [String]? = nil, fingerprint: TLSFingerprint = .chrome133,
         minVersion: TLSVersion? = nil, maxVersion: TLSVersion? = nil) {
        self.serverName = serverName
        self.alpn = alpn
        self.fingerprint = fingerprint
        self.minVersion = minVersion
        self.maxVersion = maxVersion
    }

    /// Parse TLS parameters from VLESS URL query parameters.
    ///
    /// Expected parameters: `security=tls&sni=example.com&alpn=h2,http/1.1&fp=chrome_133`
    ///
    /// Optional version constraints: `&minVersion=1.2&maxVersion=1.3`
    static func parse(from params: [String: String], serverAddress: String) throws -> TLSConfiguration? {
        guard params["security"] == "tls" else { return nil }

        let sni = params["sni"] ?? serverAddress

        var alpn: [String]? = nil
        if let alpnString = params["alpn"], !alpnString.isEmpty {
            alpn = alpnString.split(separator: ",").map { String($0) }
        }

        let fpString = params["fp"] ?? "chrome_133"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome133

        let minVersion = Self.parseTLSVersion(params["minVersion"])
        let maxVersion = Self.parseTLSVersion(params["maxVersion"])

        return TLSConfiguration(
            serverName: sni,
            alpn: alpn,
            fingerprint: fingerprint,
            minVersion: minVersion,
            maxVersion: maxVersion
        )
    }

    /// Parses a version string like "1.0", "1.1", "1.2", "1.3" into a TLSVersion.
    private static func parseTLSVersion(_ string: String?) -> TLSVersion? {
        switch string {
        case "1.0": return .tls10
        case "1.1": return .tls11
        case "1.2": return .tls12
        case "1.3": return .tls13
        default:    return nil
        }
    }
}

extension TLSConfiguration: Codable {
    enum CodingKeys: String, CodingKey {
        case serverName, alpn, fingerprint, minVersion, maxVersion
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try container.decode(String.self, forKey: .serverName)
        alpn = try container.decodeIfPresent([String].self, forKey: .alpn)
        fingerprint = try container.decodeIfPresent(TLSFingerprint.self, forKey: .fingerprint) ?? .chrome133
        minVersion = try container.decodeIfPresent(TLSVersion.self, forKey: .minVersion)
        maxVersion = try container.decodeIfPresent(TLSVersion.self, forKey: .maxVersion)
    }
}

extension TLSConfiguration: Equatable, Hashable {
    static func == (lhs: TLSConfiguration, rhs: TLSConfiguration) -> Bool {
        lhs.serverName == rhs.serverName &&
        lhs.alpn == rhs.alpn &&
        lhs.fingerprint == rhs.fingerprint &&
        lhs.minVersion == rhs.minVersion &&
        lhs.maxVersion == rhs.maxVersion
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(serverName)
        hasher.combine(alpn)
        hasher.combine(fingerprint)
        hasher.combine(minVersion)
        hasher.combine(maxVersion)
    }
}

/// TLS transport errors
enum TLSError: Error, LocalizedError {
    case handshakeFailed(String)
    case certificateValidationFailed(String)
    case connectionFailed(String)
    case unsupportedTLSVersion

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
        }
    }
}
