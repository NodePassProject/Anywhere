//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// XHTTP transport mode.
///
/// Matches Xray-core's `XmuxMode` enum in `splithttp/config.go`.
enum XHTTPMode: String, Codable, CaseIterable, Hashable {
    case auto
    case streamOne = "stream-one"
    case packetUp = "packet-up"

    var displayName: String {
        switch self {
        case .auto: return "Auto"
        case .streamOne: return "Stream One"
        case .packetUp: return "Packet Up"
        }
    }
}

/// XHTTP transport configuration.
///
/// Matches Xray-core's `splithttp.Config` protobuf definition.
struct XHTTPConfiguration: Codable, Equatable, Hashable {
    /// Host header value (defaults to server address).
    let host: String
    /// URL path (default "/").
    let path: String
    /// Transport mode (default `.auto`).
    let mode: XHTTPMode
    /// Custom HTTP headers.
    let headers: [String: String]
    /// When false, adds `Content-Type: application/grpc` header (default false).
    let noGRPCHeader: Bool
    /// Maximum bytes per POST body in packet-up mode (default 1,000,000).
    let scMaxEachPostBytes: Int
    /// Minimum interval between consecutive POSTs in ms (default 30).
    let scMinPostsIntervalMs: Int

    init(
        host: String,
        path: String = "/",
        mode: XHTTPMode = .auto,
        headers: [String: String] = [:],
        noGRPCHeader: Bool = false,
        scMaxEachPostBytes: Int = 1_000_000,
        scMinPostsIntervalMs: Int = 30
    ) {
        self.host = host
        self.path = path
        self.mode = mode
        self.headers = headers
        self.noGRPCHeader = noGRPCHeader
        self.scMaxEachPostBytes = scMaxEachPostBytes
        self.scMinPostsIntervalMs = scMinPostsIntervalMs
    }

    /// Normalized path: ensure leading "/" and trailing "/".
    var normalizedPath: String {
        var p = path
        if !p.hasPrefix("/") {
            p = "/" + p
        }
        if !p.hasSuffix("/") {
            p = p + "/"
        }
        return p
    }

    /// Parse XHTTP parameters from VLESS URL query parameters.
    ///
    /// Expected parameters: `type=xhttp&host=example.com&path=/xhttp&mode=packet-up`
    static func parse(from params: [String: String], serverAddress: String) -> XHTTPConfiguration? {
        let host = params["host"] ?? serverAddress
        let path = (params["path"] ?? "/").removingPercentEncoding ?? "/"
        let modeStr = params["mode"] ?? "auto"
        let mode = XHTTPMode(rawValue: modeStr) ?? .auto

        return XHTTPConfiguration(
            host: host,
            path: path,
            mode: mode
        )
    }
}

/// XHTTP transport errors.
enum XHTTPError: Error, LocalizedError {
    case setupFailed(String)
    case httpError(String)
    case connectionClosed

    var errorDescription: String? {
        switch self {
        case .setupFailed(let reason):
            return "XHTTP setup failed: \(reason)"
        case .httpError(let reason):
            return "XHTTP HTTP error: \(reason)"
        case .connectionClosed:
            return "XHTTP connection closed"
        }
    }
}
