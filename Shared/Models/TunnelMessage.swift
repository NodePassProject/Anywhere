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

/// One second of traffic telemetry. The extension owns the rolling 60-sample
/// window and ships the whole buffer in each ``StatsResponse`` so the app can
/// render the time-series view without having to stitch successive polls.
struct StatsSample: Codable, Identifiable, Hashable, Sendable {
    /// Monotonic sequence number, restarted on each tunnel session; also the
    /// natural chart x-position.
    let id: UInt64
    /// Bytes received during this second (throughput, not a running total).
    let bytesIn: Int64
    /// Bytes sent during this second.
    let bytesOut: Int64
    /// Active TCP connections at sample time.
    let tcpConnectionCount: Int
    /// Active UDP flows at sample time.
    let udpConnectionCount: Int
    /// Extension memory footprint at sample time, in bytes.
    let memoryBytes: UInt64
}

struct StatsResponse: Codable, Sendable {
    /// Cumulative bytes received since the tunnel started.
    var bytesIn: Int64
    /// Cumulative bytes sent since the tunnel started.
    var bytesOut: Int64
    /// Rolling per-second window. The extension drops the oldest entry once
    /// the buffer is full; current TCP/UDP/memory gauges are
    /// `samples.last`'s fields.
    var samples: [StatsSample]

    init(bytesIn: Int64, bytesOut: Int64, samples: [StatsSample] = []) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.samples = samples
    }

    // Tolerant decoder: lets a newer app survive briefly talking to an older
    // extension across an app update, and vice versa, without failing the
    // whole decode. Missing keys default to empty/zero — the next restart
    // populates real data.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bytesIn = try c.decode(Int64.self, forKey: .bytesIn)
        bytesOut = try c.decode(Int64.self, forKey: .bytesOut)
        samples = try c.decodeIfPresent([StatsSample].self, forKey: .samples) ?? []
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
    /// Final routing action for this connection.
    var action: TunnelRequestAction
    /// Optional display name of the proxy configuration used. Set for
    /// ``proxy`` and ``default`` actions when a chain/configuration is
    /// involved; nil for ``direct`` / ``reject``.
    var configurationName: String?
}

enum TunnelRequestAction: String, Codable, Sendable, Hashable {
    /// Matched a routing rule with the `.direct` action.
    case direct
    /// Matched a routing rule with the `.reject` action.
    case reject
    /// Matched a routing rule with the `.proxy(...)` action.
    case proxy
    /// No routing rule matched; the user-selected default chain handled
    /// this connection.
    case `default`
}
