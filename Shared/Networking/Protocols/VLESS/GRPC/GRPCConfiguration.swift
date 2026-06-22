//
//  GRPCConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 4/23/26.
//

import Foundation

struct GRPCConfiguration: Codable, Equatable, Hashable {
    static let defaultServiceName = "xray.transport.internet.grpc.encoding.GRPCService"

    /// gRPC service name. A plain name maps to `/<name>/Tun` (or `/TunMulti`); a leading
    /// `/` marks a full custom path whose final segment is the stream name.
    let serviceName: String

    /// HTTP/2 `:authority` value; when empty, derived from SNI / server address at dial time.
    let authority: String

    /// When `true`, uses the `TunMulti` stream. A single-element `MultiHunk` is
    /// wire-compatible with `Hunk`, so encoding is identical in both modes.
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

    /// Returns the `:authority` to advertise: explicit config → TLS SNI → Reality SNI → server address.
    func resolvedAuthority(tlsServerName: String?, realityServerName: String?, serverAddress: String) -> String {
        if !authority.isEmpty { return authority }
        if let tlsServerName, !tlsServerName.isEmpty { return tlsServerName }
        if let realityServerName, !realityServerName.isEmpty { return realityServerName }
        return serverAddress
    }

    /// Returns the HTTP/2 `:path`: `/<escaped serviceName>/Tun[Multi]`, or the custom
    /// path when `serviceName` starts with `/`. Components are URL-path-escaped.
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
            // `|` splits the Tun name (before) from the TunMulti name (after); without it one name serves both.
            streamName = parts.count >= 2 ? parts[1] : parts[0]
        } else {
            streamName = parts[0]
        }

        let prefix = servicePart.isEmpty ? "" : "/\(servicePart)"
        return "\(prefix)/\(urlPathEscape(streamName))"
    }

    private func urlPathEscape(_ value: String) -> String {
        return value.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? value
    }
}

enum GRPCError: Error, LocalizedError {
    case setupFailed(String)
    case invalidResponse(String)
    case compressedMessageUnsupported
    /// Server closed the stream with a non-OK gRPC status code in trailer headers.
    case callFailed(status: Int, name: String, message: String?)
    case connectionClosed
    /// Transport reached a clean EOF at an HTTP/2 frame boundary.
    case streamEnded
    
    var errorDescription: String? {
        switch self {
        case .setupFailed(let reason):
            return "gRPC setup failed: \(reason)"
        case .invalidResponse(let reason):
            return "gRPC invalid response: \(reason)"
        case .compressedMessageUnsupported:
            return "gRPC compressed messages are not supported"
        case .callFailed(let status, let name, let message):
            if let message, !message.isEmpty {
                return "gRPC call failed: \(name) (\(status)) — \(message)"
            }
            return "gRPC call failed: \(name) (\(status))"
        case .connectionClosed:
            return "gRPC connection closed"
        case .streamEnded:
            return "gRPC stream ended"
        }
    }
}
