//
//  TunnelMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

nonisolated enum TunnelMessage: Codable, Sendable {
    static let optionKey = "tunnelMessage"
    
    case setConfiguration(ProxyConfiguration)
    case testLatency(ProxyConfiguration)
    case fetchStats
    case resetStats
    case fetchLogs
    case fetchRequests
}

// MARK: - Responses

nonisolated struct RouteTrafficEntry: Codable, Sendable, Identifiable, Hashable {
    var target: RouteTarget
    var bytesIn: Int64
    var bytesOut: Int64

    var id: String { target.storageKey }
    var totalBytes: Int64 { bytesIn + bytesOut }
}

nonisolated struct StatsResponse: Codable, Sendable {
    var bytesIn: Int64
    var bytesOut: Int64
    var routes: [RouteTrafficEntry]
    var tcpConnectionCount: Int
    var udpConnectionCount: Int
    var memoryBytes: UInt64
    var wakeSeconds: TimeInterval
    var sleepSeconds: TimeInterval
    var dialMs: Int?
    var handshakeMs: Int?
    var avgDialMs: Int?
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

nonisolated struct LogsResponse: Codable, Sendable {
    var logs: [TunnelLogEntry]
}

nonisolated struct RequestsResponse: Codable, Sendable {
    var requests: [TunnelRequestEntry]
}

nonisolated struct LatencyTestResponse: Codable, Sendable {
    enum Kind: String, Codable, Sendable {
        case success
        case failed
        case insecure
    }
    var result: Kind
    var ms: Int?
}

nonisolated extension LatencyTestResponse {
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

nonisolated struct TunnelLogEntry: Codable, Sendable, Hashable {
    var id: UUID = UUID()
    var timestamp: TimeInterval
    var level: TunnelLogLevel
    var message: String
}

nonisolated enum TunnelLogLevel: String, Codable, Sendable, Hashable {
    case info
    case warning
    case error
}

nonisolated struct TunnelRequestEntry: Codable, Sendable, Hashable {
    var id: UUID = UUID()
    var timestamp: TimeInterval
    var `protocol`: TunnelRequestProtocol
    var host: String
    var port: UInt16
    var routeTarget: RouteTarget
    var ruleSetName: String? = nil
    var defaultRouteTarget: RouteTarget? = nil
}

nonisolated enum TunnelRequestProtocol: String, Codable, Sendable, Hashable {
    case tcp
    case udp
    case unknown
}
