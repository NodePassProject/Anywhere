//
//  GRPCConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/23/26.
//

import Foundation

/// gRPC transport configuration.
struct GRPCConfiguration: Codable, Equatable, Hashable {
    /// Default gRPC service name used when `serviceName` is empty.
    static let defaultServiceName = "xray.transport.internet.grpc.encoding.GRPCService"

    /// gRPC service name. Two interpretations:
    /// - Plain name (e.g. `"example"`): standard stream names `Tun` / `TunMulti` are used.
    ///   Path becomes `/<serviceName>/Tun` (or `/TunMulti`).
    /// - Custom path (starts with `/`, e.g. `"/my/service/TunName"`): treated as the full
    ///   path; the substring between the first and last `/` becomes the service name and
    ///   the final segment is the stream name. Components are URL-path-escaped.
    let serviceName: String

    /// HTTP/2 `:authority` header value. When empty, derived from the TLS SNI /
    /// Reality server name / server address at dial time.
    let authority: String

    /// When `true`, uses the `TunMulti` stream (`MultiHunk` messages) instead of `Tun`.
    /// A single-element `MultiHunk` is wire-compatible with `Hunk`, so encoding always
    /// emits one data element per message regardless of mode; decoding accepts both.
    let multiMode: Bool

    /// Custom `User-Agent` header. When empty, falls back to the default Chrome UA.
    let userAgent: String

    /// HTTP/2 initial window size (bytes). `0` means use gRPC's default (65535).
    let initialWindowsSize: Int

    /// Keepalive ping interval in seconds. `0` disables keepalive pings.
    let idleTimeout: Int

    /// Keepalive ping timeout in seconds. `0` uses the gRPC default (20 seconds).
    let healthCheckTimeout: Int

    /// When `true`, send keepalive pings even when no streams are active.
    let permitWithoutStream: Bool

    init(
        serviceName: String = "",
        authority: String = "",
        multiMode: Bool = false,
        userAgent: String = "",
        initialWindowsSize: Int = 0,
        idleTimeout: Int = 0,
        healthCheckTimeout: Int = 0,
        permitWithoutStream: Bool = false
    ) {
        self.serviceName = serviceName
        self.authority = authority
        self.multiMode = multiMode
        self.userAgent = userAgent
        self.initialWindowsSize = initialWindowsSize
        self.idleTimeout = idleTimeout
        self.healthCheckTimeout = healthCheckTimeout
        self.permitWithoutStream = permitWithoutStream
    }

    /// Parse gRPC parameters from VLESS URL query parameters.
    ///
    /// Recognised keys:
    /// - `serviceName`: gRPC service name.
    /// - `authority`: `:authority` override.
    /// - `mode`: `"gun"` for single-Hunk `Tun`, `"multi"` for `TunMulti`. Default `"gun"`.
    /// - `userAgent`: custom User-Agent.
    /// - `idle_timeout`, `health_check_timeout`, `initial_windows_size` (integers).
    /// - `permit_without_stream` (`"true"`/`"1"`).
    static func parse(from params: [String: String]) -> GRPCConfiguration? {
        let serviceName = params["serviceName"] ?? ""
        let authority = params["authority"] ?? ""
        let mode = (params["mode"] ?? "gun").lowercased()
        let multiMode = (mode == "multi")
        let userAgent = params["userAgent"] ?? ""

        let initialWindowsSize = params["initial_windows_size"].flatMap { Int($0) } ?? 0
        let idleTimeout = params["idle_timeout"].flatMap { Int($0) } ?? 0
        let healthCheckTimeout = params["health_check_timeout"].flatMap { Int($0) } ?? 0
        let permitWithoutStream = params["permit_without_stream"].map { $0 != "false" && $0 != "0" } ?? false

        return GRPCConfiguration(
            serviceName: serviceName,
            authority: authority,
            multiMode: multiMode,
            userAgent: userAgent,
            initialWindowsSize: initialWindowsSize,
            idleTimeout: idleTimeout,
            healthCheckTimeout: healthCheckTimeout,
            permitWithoutStream: permitWithoutStream
        )
    }

    // MARK: - Path resolution

    /// Returns the `:authority` value to advertise over HTTP/2.
    ///
    /// Priority: explicit `authority` config value → TLS SNI → Reality SNI → server address.
    func resolvedAuthority(tlsServerName: String?, realityServerName: String?, serverAddress: String) -> String {
        if !authority.isEmpty { return authority }
        if let tlsServerName, !tlsServerName.isEmpty { return tlsServerName }
        if let realityServerName, !realityServerName.isEmpty { return realityServerName }
        return serverAddress
    }

    /// Returns the HTTP/2 `:path` value for this transport.
    ///
    /// - Plain `serviceName`: path = `/<url-escaped serviceName>/Tun` (or `/TunMulti`).
    /// - `serviceName` starting with `/`: treated as a full custom path. The part between
    ///   the first and last `/` becomes the service path (each segment URL-escaped); the
    ///   part after the last `/` is the stream name. For multi mode, if the last segment
    ///   contains `|` the first half is Tun and the second is TunMulti.
    func resolvedPath() -> String {
        let name = serviceName.isEmpty ? Self.defaultServiceName : serviceName
        if !name.hasPrefix("/") {
            let stream = multiMode ? "TunMulti" : "Tun"
            return "/\(urlPathEscape(name))/\(stream)"
        }
        let lastSlashIndex = name.range(of: "/", options: .backwards)?.lowerBound ?? name.startIndex
        let serviceRawStart = name.index(after: name.startIndex)
        let serviceRaw = String(name[serviceRawStart..<lastSlashIndex])
        let streamEnd = name.endIndex
        let endingPath = String(name[name.index(after: lastSlashIndex)..<streamEnd])

        let servicePart = serviceRaw
            .split(separator: "/", omittingEmptySubsequences: false)
            .map { urlPathEscape(String($0)) }
            .joined(separator: "/")

        let streamName: String
        let parts = endingPath.split(separator: "|", omittingEmptySubsequences: false).map { String($0) }
        if multiMode {
            // A `|` in the last segment splits Tun (before) from TunMulti (after);
            // without `|`, the single stream name is reused for both modes.
            streamName = parts.count >= 2 ? parts[1] : parts[0]
        } else {
            streamName = parts[0]
        }

        let prefix = servicePart.isEmpty ? "" : "/\(servicePart)"
        return "\(prefix)/\(urlPathEscape(streamName))"
    }

    /// Percent-encodes a single URL path segment.
    private func urlPathEscape(_ value: String) -> String {
        return value.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? value
    }
}

/// gRPC transport errors.
enum GRPCError: Error, LocalizedError {
    case setupFailed(String)
    case connectionClosed
    case invalidResponse(String)
    case compressedMessageUnsupported
    /// Server closed the stream with a non-OK gRPC status (trailer headers).
    /// Example: `.callFailed(status: 12, name: "UNIMPLEMENTED", message: "unknown service …")`.
    case callFailed(status: Int, name: String, message: String?)

    var errorDescription: String? {
        switch self {
        case .setupFailed(let reason):
            return "gRPC setup failed: \(reason)"
        case .connectionClosed:
            return "gRPC connection closed"
        case .invalidResponse(let reason):
            return "gRPC invalid response: \(reason)"
        case .compressedMessageUnsupported:
            return "gRPC compressed messages are not supported"
        case .callFailed(let status, let name, let message):
            if let message, !message.isEmpty {
                return "gRPC call failed: \(name) (\(status)) — \(message)"
            }
            return "gRPC call failed: \(name) (\(status))"
        }
    }
}
