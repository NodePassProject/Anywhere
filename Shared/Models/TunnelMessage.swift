//
//  TunnelMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

/// Typed envelope for IPC between the main app and the network extension.
enum TunnelMessage: Codable, Sendable {
    /// Key in `startVPNTunnel(options:)` carrying an encoded `setConfiguration`.
    static let optionKey = "tunnelMessage"

    /// Apply the configuration; used at startup and to switch proxies while running.
    case setConfiguration(ProxyConfiguration)

    /// Latency-test the given configuration, independent of the active tunnel. Reply: `LatencyTestResponse`.
    case testLatency(ProxyConfiguration)

    /// Query current byte counters. Reply: `StatsResponse`.
    case fetchStats

    /// Query the recent log buffer. Reply: `LogsResponse`.
    case fetchLogs

    /// Query the recent request log. Reply: `RequestsResponse`.
    case fetchRequests
}

// MARK: - Responses

/// Per-route payload tally shipped inside `StatsResponse`.
struct RouteTrafficEntry: Codable, Sendable, Identifiable, Hashable {
    var target: RouteTarget
    var bytesIn: Int64
    var bytesOut: Int64

    var id: String { target.storageKey }
    var totalBytes: Int64 { bytesIn + bytesOut }
}

/// Point-in-time tunnel telemetry snapshot. Byte counters are cumulative
/// **payload** bytes since tunnel start (no IP/transport headers), split per route.
struct StatsResponse: Codable, Sendable {
    var bytesIn: Int64
    var bytesOut: Int64
    /// Per-route payload split, sorted by total bytes descending.
    var routes: [RouteTrafficEntry]
    var tcpConnectionCount: Int
    var udpConnectionCount: Int
    var memoryBytes: UInt64
    /// Cumulative seconds this session has been awake (excludes device sleep).
    var wakeSeconds: TimeInterval
    /// Cumulative seconds this session has spent in device sleep.
    var sleepSeconds: TimeInterval
    /// Most recent first-hop TCP dial time in ms; nil until a dial this session.
    var dialMs: Int?
    /// Most recent proxy handshake time (TCP-connected → tunnel ready) in ms.
    var handshakeMs: Int?
    /// Session-average first-hop TCP dial time in ms; nil until a dial this session.
    var avgDialMs: Int?
    /// Session-average proxy handshake time in ms.
    var avgHandshakeMs: Int?

    init(
        bytesIn: Int64,
        bytesOut: Int64,
        routes: [RouteTrafficEntry] = [],
        tcpConnectionCount: Int = 0,
        udpConnectionCount: Int = 0,
        memoryBytes: UInt64 = 0,
        wakeSeconds: TimeInterval = 0,
        sleepSeconds: TimeInterval = 0,
        dialMs: Int? = nil,
        handshakeMs: Int? = nil,
        avgDialMs: Int? = nil,
        avgHandshakeMs: Int? = nil
    ) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.routes = routes
        self.tcpConnectionCount = tcpConnectionCount
        self.udpConnectionCount = udpConnectionCount
        self.memoryBytes = memoryBytes
        self.wakeSeconds = wakeSeconds
        self.sleepSeconds = sleepSeconds
        self.dialMs = dialMs
        self.handshakeMs = handshakeMs
        self.avgDialMs = avgDialMs
        self.avgHandshakeMs = avgHandshakeMs
    }

    // Tolerant decoder: missing keys default to zero/nil so app and extension
    // can briefly skew versions across an update.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bytesIn = try c.decode(Int64.self, forKey: .bytesIn)
        bytesOut = try c.decode(Int64.self, forKey: .bytesOut)
        routes = try c.decodeIfPresent([RouteTrafficEntry].self, forKey: .routes) ?? []
        tcpConnectionCount = try c.decodeIfPresent(Int.self, forKey: .tcpConnectionCount) ?? 0
        udpConnectionCount = try c.decodeIfPresent(Int.self, forKey: .udpConnectionCount) ?? 0
        memoryBytes = try c.decodeIfPresent(UInt64.self, forKey: .memoryBytes) ?? 0
        wakeSeconds = try c.decodeIfPresent(TimeInterval.self, forKey: .wakeSeconds) ?? 0
        sleepSeconds = try c.decodeIfPresent(TimeInterval.self, forKey: .sleepSeconds) ?? 0
        dialMs = try c.decodeIfPresent(Int.self, forKey: .dialMs)
        handshakeMs = try c.decodeIfPresent(Int.self, forKey: .handshakeMs)
        avgDialMs = try c.decodeIfPresent(Int.self, forKey: .avgDialMs)
        avgHandshakeMs = try c.decodeIfPresent(Int.self, forKey: .avgHandshakeMs)
    }
}

struct LogsResponse: Codable, Sendable {
    var logs: [TunnelLogEntry]
}

struct RequestsResponse: Codable, Sendable {
    var requests: [TunnelRequestEntry]
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
    /// `.testing` collapses to `.failed`; it's a UI-only state that shouldn't appear over the wire.
    init(_ result: LatencyResult) {
        switch result {
        case .success(let ms): self.init(result: .success, ms: ms)
        case .insecure: self.init(result: .insecure, ms: nil)
        case .failed, .testing: self.init(result: .failed, ms: nil)
        }
    }

    var asLatencyResult: LatencyResult {
        switch result {
        case .success: return .success(ms ?? 0)
        case .insecure: return .insecure
        case .failed: return .failed
        }
    }
}

// MARK: - Shared Types

/// Wire-format log entry.
struct TunnelLogEntry: Codable, Sendable, Hashable {
    var id: UUID = UUID()
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

/// Wire-format record of one routing decision.
struct TunnelRequestEntry: Codable, Sendable, Hashable {
    var id: UUID = UUID()
    /// Seconds since CFAbsoluteTime reference date (Jan 1 2001 UTC).
    var timestamp: TimeInterval
    /// Transport: "TCP" or "UDP".
    var proto: String
    /// Destination host: resolved domain when known (fake-IP/SNI), else literal IP.
    var host: String
    var port: UInt16
    var routeTarget: RouteTarget
    /// True when no rule matched and the default outbound handled this connection.
    var viaDefault: Bool
}
