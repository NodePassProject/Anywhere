//
//  TunnelMessage.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

/// Typed envelope for IPC between the main app and the network extension.
///
/// The same envelope is used by `startVPNTunnel(options:)` (initial bring-up)
/// and `sendProviderMessage(_:)` (live updates and queries). Each message
/// either expects a typed response struct (see this file) or no response.
enum TunnelMessage: Codable, Sendable {
    /// Key used in `startVPNTunnel(options:)` to carry an encoded
    /// ``TunnelMessage`` (always a ``setConfiguration``).
    static let optionKey = "tunnelMessage"

    /// Apply the configuration to the tunnel. Used both as the initial
    /// configuration on startup and to switch to a different proxy while
    /// the tunnel is running.
    case setConfiguration(ProxyConfiguration)

    /// Run a latency test against the given configuration. Independent of
    /// the active tunnel — the extension dials the proxy directly. Reply:
    /// ``LatencyTestResponse``.
    case testLatency(ProxyConfiguration)

    /// Query current byte counters. Reply: ``StatsResponse``.
    case fetchStats

    /// Query the recent log buffer. Reply: ``LogsResponse``.
    case fetchLogs
}

// MARK: - Responses

struct StatsResponse: Codable, Sendable {
    var bytesIn: Int64
    var bytesOut: Int64
}

struct LogsResponse: Codable, Sendable {
    var logs: [TunnelLogEntry]
}

struct LatencyTestResponse: Codable, Sendable {
    enum Kind: String, Codable, Sendable {
        case success
        case failed
        case insecure
    }
    var result: Kind
    var ms: Int?
}

extension LatencyTestResponse {
    /// Convert from the in-process ``LatencyResult`` produced by ``LatencyTester``.
    /// `.testing` is collapsed to `.failed` since it's a UI-only state and
    /// shouldn't appear over the wire.
    init(_ result: LatencyResult) {
        switch result {
        case .success(let ms): self.init(result: .success, ms: ms)
        case .insecure: self.init(result: .insecure, ms: nil)
        case .failed, .testing: self.init(result: .failed, ms: nil)
        }
    }

    /// Convert back to the in-process ``LatencyResult`` for the UI layer.
    var asLatencyResult: LatencyResult {
        switch result {
        case .success: return .success(ms ?? 0)
        case .insecure: return .insecure
        case .failed: return .failed
        }
    }
}

// MARK: - Shared Types

/// Wire-format log entry. Also the in-memory record kept by ``LWIPStack``.
struct TunnelLogEntry: Codable, Sendable, Hashable {
    /// Seconds since CFAbsoluteTime reference date (Jan 1 2001 UTC).
    var timestamp: TimeInterval
    var level: TunnelLogLevel
    var message: String
}

enum TunnelLogLevel: String, Codable, Sendable, Hashable {
    case info
    case warning
    case error
}
