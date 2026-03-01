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
    let allowInsecure: Bool             // Skip certificate verification
    let fingerprint: TLSFingerprint     // Browser fingerprint to mimic

    init(serverName: String, alpn: [String]? = nil, allowInsecure: Bool = false, fingerprint: TLSFingerprint = .chrome120) {
        self.serverName = serverName
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.fingerprint = fingerprint
    }

    /// Parse TLS parameters from VLESS URL query parameters.
    ///
    /// Expected parameters: `security=tls&sni=example.com&alpn=h2,http/1.1&allowInsecure=1&fp=chrome_120`
    static func parse(from params: [String: String], serverAddress: String) throws -> TLSConfiguration? {
        guard params["security"] == "tls" else { return nil }

        let sni = params["sni"] ?? serverAddress

        var alpn: [String]? = nil
        if let alpnString = params["alpn"], !alpnString.isEmpty {
            alpn = alpnString.split(separator: ",").map { String($0) }
        }

        let allowInsecure = params["allowInsecure"] == "1" || params["allowInsecure"] == "true"

        let fpString = params["fp"] ?? "chrome_120"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

        return TLSConfiguration(
            serverName: sni,
            alpn: alpn,
            allowInsecure: allowInsecure,
            fingerprint: fingerprint
        )
    }
}

extension TLSConfiguration: Codable {
    enum CodingKeys: String, CodingKey {
        case serverName, alpn, allowInsecure, fingerprint
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try container.decode(String.self, forKey: .serverName)
        alpn = try container.decodeIfPresent([String].self, forKey: .alpn)
        allowInsecure = try container.decode(Bool.self, forKey: .allowInsecure)
        fingerprint = try container.decodeIfPresent(TLSFingerprint.self, forKey: .fingerprint) ?? .chrome120
    }
}

extension TLSConfiguration: Equatable, Hashable {
    static func == (lhs: TLSConfiguration, rhs: TLSConfiguration) -> Bool {
        lhs.serverName == rhs.serverName &&
        lhs.alpn == rhs.alpn &&
        lhs.allowInsecure == rhs.allowInsecure &&
        lhs.fingerprint == rhs.fingerprint
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(serverName)
        hasher.combine(alpn)
        hasher.combine(allowInsecure)
        hasher.combine(fingerprint)
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
            return "Server does not support TLS 1.3"
        }
    }
}
