//
//  ConnectionStatsModel.swift
//  Anywhere
//
//  Created by NodePassProject on 3/29/26.
//

import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
class ConnectionStatsModel {
    static let shared = ConnectionStatsModel()

    /// Cumulative session byte totals; each equals the sum across `routes`.
    private(set) var bytesIn: Int64 = 0
    private(set) var bytesOut: Int64 = 0

    /// Per-route payload split, sorted by total bytes descending; rejected
    /// traffic carries no payload and never appears.
    private(set) var routes: [RouteTrafficEntry] = []

    /// Latest instantaneous gauges, refreshed wholesale on every poll.
    private(set) var tcpConnectionCount: Int = 0
    private(set) var udpConnectionCount: Int = 0
    private(set) var memoryBytes: UInt64 = 0

    /// Most recent connection-establishment timings (ms); nil until first measured.
    private(set) var dialMs: Int?
    private(set) var handshakeMs: Int?

    @ObservationIgnored private var statsTask: Task<Void, Never>?
    @ObservationIgnored private weak var session: NETunnelProviderSession?

    func startPolling(session: NETunnelProviderSession) {
        self.session = session
        guard statsTask == nil else { return }
        statsTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, !Task.isCancelled else { break }
                await self.pollStats()
            }
        }
    }

    func stopPolling() {
        statsTask?.cancel()
        statsTask = nil
        session = nil
    }

    func reset() {
        bytesIn = 0
        bytesOut = 0
        routes = []
        tcpConnectionCount = 0
        udpConnectionCount = 0
        memoryBytes = 0
        dialMs = nil
        handshakeMs = nil
    }

    private func pollStats() async {
        guard let session else { return }
        guard let data = try? JSONEncoder().encode(TunnelMessage.fetchStats) else { return }

        let response: Data? = await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }

        guard let response,
              let stats = try? JSONDecoder().decode(StatsResponse.self, from: response) else { return }
        self.bytesIn = stats.bytesIn
        self.bytesOut = stats.bytesOut
        self.routes = stats.routes
        self.tcpConnectionCount = stats.tcpConnectionCount
        self.udpConnectionCount = stats.udpConnectionCount
        self.memoryBytes = stats.memoryBytes
        self.dialMs = stats.dialMs
        self.handshakeMs = stats.handshakeMs
    }
}

#if DEBUG
extension ConnectionStatsModel {
    /// Preview-seeded model; lives here because the `private(set)` setters are file-scoped.
    static func previewSeeded() -> ConnectionStatsModel {
        let model = ConnectionStatsModel()
        model.routes = [
            RouteTrafficEntry(target: .proxy(UUID()), bytesIn: 1_600_000_000, bytesOut: 280_000_000),
            RouteTrafficEntry(target: .direct, bytesIn: 240_000_000, bytesOut: 40_000_000),
        ]
        model.bytesIn = model.routes.reduce(0) { $0 + $1.bytesIn }
        model.bytesOut = model.routes.reduce(0) { $0 + $1.bytesOut }
        model.tcpConnectionCount = 5
        model.udpConnectionCount = 64
        model.memoryBytes = 31_000_000
        model.dialMs = 62
        model.handshakeMs = 200
        return model
    }
}
#endif
