//
//  TunnelMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
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

    /// Query the recent request log (per-connection routing decisions).
    /// Reply: ``RequestsResponse``.
    case fetchRequests
}

// MARK: - Responses

/// Per-route payload tally shipped inside ``StatsResponse``. Carries the
/// ``RouteTarget`` identity only; the app resolves the display name from its own
/// configuration/chain stores, so no name is carried over IPC.
struct RouteTrafficEntry: Codable, Sendable, Identifiable, Hashable {
    var target: RouteTarget
    var bytesIn: Int64
    var bytesOut: Int64

    /// Stable identity key for `Identifiable` / `ForEach`.
    var id: String { target.storageKey }
    var totalBytes: Int64 { bytesIn + bytesOut }
}

/// A point-in-time snapshot of tunnel telemetry. The extension keeps only the
/// newest reading — no rolling history — and ships it on each ``fetchStats``
/// poll; the app renders it straight into the live stats cards and the
/// route-breakdown pie chart.
///
/// Byte counters are **payload** bytes (no IP/transport headers, ACKs, or
/// retransmits) tallied at the connection/flow layer and split by
/// ``RouteTarget``: one bucket per route (direct and each proxy/chain). The
/// totals reconcile — `bytesIn == Σ routes.bytesIn` (and likewise out).
/// Rejected traffic carries no payload and never appears.
struct StatsResponse: Codable, Sendable {
    /// Cumulative payload bytes received since the tunnel started
    /// (the sum of the routes' `bytesIn`).
    var bytesIn: Int64
    /// Cumulative payload bytes sent since the tunnel started
    /// (the sum of the routes' `bytesOut`).
    var bytesOut: Int64
    /// Per-route payload split, one entry per route (direct / each proxy /
    /// each chain) that carried traffic this session. Sorted by total bytes,
    /// descending.
    var routes: [RouteTrafficEntry]
    /// Active TCP connections right now.
    var tcpConnectionCount: Int
    /// Active UDP flows right now.
    var udpConnectionCount: Int
    /// Extension memory footprint right now, in bytes.
    var memoryBytes: UInt64
    /// Most recent first-hop TCP dial time, in milliseconds. `nil` until a
    /// connection has been dialed this session.
    var dialMs: Int?
    /// Most recent proxy handshake time (TCP-connected → tunnel ready), in
    /// milliseconds. `nil` until a tunnel has been established this session.
    var handshakeMs: Int?

    init(
        bytesIn: Int64,
        bytesOut: Int64,
        routes: [RouteTrafficEntry] = [],
        tcpConnectionCount: Int = 0,
        udpConnectionCount: Int = 0,
        memoryBytes: UInt64 = 0,
        dialMs: Int? = nil,
        handshakeMs: Int? = nil
    ) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.routes = routes
        self.tcpConnectionCount = tcpConnectionCount
        self.udpConnectionCount = udpConnectionCount
        self.memoryBytes = memoryBytes
        self.dialMs = dialMs
        self.handshakeMs = handshakeMs
    }

    // Tolerant decoder: lets a newer app survive briefly talking to an older
    // extension across an app update, and vice versa, without failing the
    // whole decode. Missing keys default to zero/nil — the next restart
    // populates real data.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bytesIn = try c.decode(Int64.self, forKey: .bytesIn)
        bytesOut = try c.decode(Int64.self, forKey: .bytesOut)
        routes = try c.decodeIfPresent([RouteTrafficEntry].self, forKey: .routes) ?? []
        tcpConnectionCount = try c.decodeIfPresent(Int.self, forKey: .tcpConnectionCount) ?? 0
        udpConnectionCount = try c.decodeIfPresent(Int.self, forKey: .udpConnectionCount) ?? 0
        memoryBytes = try c.decodeIfPresent(UInt64.self, forKey: .memoryBytes) ?? 0
        dialMs = try c.decodeIfPresent(Int.self, forKey: .dialMs)
        handshakeMs = try c.decodeIfPresent(Int.self, forKey: .handshakeMs)
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

/// Wire-format log entry. Also the in-memory record kept by ``TunnelStack``.
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

/// Wire-format record of one routing decision. Also the in-memory record
/// kept by the extension's request log.
struct TunnelRequestEntry: Codable, Sendable, Hashable {
    var id: UUID = UUID()
    /// Seconds since CFAbsoluteTime reference date (Jan 1 2001 UTC).
    var timestamp: TimeInterval
    /// Transport: "TCP" or "UDP".
    var proto: String
    /// Destination host. The resolved domain when a fake-IP entry or SNI
    /// is known; otherwise the literal IP address.
    var host: String
    /// Destination port.
    var port: UInt16
    /// Where this connection was routed. The app resolves the display name
    /// (the extension ships the id only).
    var routeTarget: RouteTarget
    /// True when no routing rule matched and the user-selected default outbound
    /// handled this connection (the route is still ``routeTarget``).
    var viaDefault: Bool
}
