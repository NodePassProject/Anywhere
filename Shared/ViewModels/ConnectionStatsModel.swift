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
    
    private(set) var bytesIn: Int64 = 0
    private(set) var bytesOut: Int64 = 0
    
    private(set) var routes: [RouteTrafficEntry] = []
    
    private(set) var tcpConnectionCount: Int = 0
    private(set) var udpConnectionCount: Int = 0
    
    private(set) var memoryBytes: UInt64 = 0
    
    private(set) var wakeSeconds: TimeInterval = 0
    private(set) var sleepSeconds: TimeInterval = 0
    
    private(set) var dialMs: Int?
    private(set) var handshakeMs: Int?
    
    private(set) var avgDialMs: Int?
    private(set) var avgHandshakeMs: Int?
    
    private(set) var uploadBytesPerSecond: Int64?
    private(set) var downloadBytesPerSecond: Int64?

    @ObservationIgnored private var statsTask: Task<Void, Never>?
    @ObservationIgnored private weak var session: NETunnelProviderSession?
    @ObservationIgnored private var lastRateSample: (bytesIn: Int64, bytesOut: Int64, at: ContinuousClock.Instant)?

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
        lastRateSample = nil
    }

    func reset() {
        bytesIn = 0
        bytesOut = 0
        routes = []
        tcpConnectionCount = 0
        udpConnectionCount = 0
        memoryBytes = 0
        wakeSeconds = 0
        sleepSeconds = 0
        dialMs = nil
        handshakeMs = nil
        avgDialMs = nil
        avgHandshakeMs = nil
        uploadBytesPerSecond = nil
        downloadBytesPerSecond = nil
        lastRateSample = nil
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
        updateRates(bytesIn: stats.bytesIn, bytesOut: stats.bytesOut)
        self.bytesIn = stats.bytesIn
        self.bytesOut = stats.bytesOut
        self.routes = stats.routes
        self.tcpConnectionCount = stats.tcpConnectionCount
        self.udpConnectionCount = stats.udpConnectionCount
        self.memoryBytes = stats.memoryBytes
        self.wakeSeconds = stats.wakeSeconds
        self.sleepSeconds = stats.sleepSeconds
        self.dialMs = stats.dialMs
        self.handshakeMs = stats.handshakeMs
        self.avgDialMs = stats.avgDialMs
        self.avgHandshakeMs = stats.avgHandshakeMs
    }

    private func updateRates(bytesIn: Int64, bytesOut: Int64) {
        let now = ContinuousClock.now
        defer { lastRateSample = (bytesIn, bytesOut, now) }
        // A backwards counter means the tunnel restarted; rebaseline silently.
        guard let last = lastRateSample,
              bytesIn >= last.bytesIn, bytesOut >= last.bytesOut else {
            uploadBytesPerSecond = nil
            downloadBytesPerSecond = nil
            return
        }
        let elapsed = last.at.duration(to: now)
        let seconds = Double(elapsed.components.seconds)
            + Double(elapsed.components.attoseconds) / 1e18
        guard seconds > 0 else { return }
        downloadBytesPerSecond = Int64(Double(bytesIn - last.bytesIn) / seconds)
        uploadBytesPerSecond = Int64(Double(bytesOut - last.bytesOut) / seconds)
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
        model.wakeSeconds = 3 * 3600 + 24 * 60
        model.sleepSeconds = 47 * 60
        model.dialMs = 62
        model.handshakeMs = 200
        model.avgDialMs = 50
        model.avgHandshakeMs = 150
        model.uploadBytesPerSecond = 1_200_000
        model.downloadBytesPerSecond = 5_100_000
        return model
    }
}
#endif
