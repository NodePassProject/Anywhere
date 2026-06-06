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

    /// Cumulative byte totals for the session (shown on the home / TV screens).
    private(set) var bytesIn: Int64 = 0
    private(set) var bytesOut: Int64 = 0

    /// Latest instantaneous gauges, derived from `samples.last` on every poll.
    private(set) var tcpConnectionCount: Int = 0
    private(set) var udpConnectionCount: Int = 0
    private(set) var memoryBytes: UInt64 = 0

    /// Rolling window owned by the extension; replaced wholesale on each poll.
    private(set) var samples: [StatsSample] = []
    
    static let maxSamples = 130

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
        tcpConnectionCount = 0
        udpConnectionCount = 0
        memoryBytes = 0
        samples = []
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
        self.samples = stats.samples
        if let last = stats.samples.last {
            self.tcpConnectionCount = last.tcpConnectionCount
            self.udpConnectionCount = last.udpConnectionCount
            self.memoryBytes = last.memoryBytes
        }
    }
}

#if DEBUG
extension ConnectionStatsModel {
    /// A model pre-filled with a full 60-second synthetic window for SwiftUI
    /// previews and tests. The `private(set)` properties are file-scoped, so the
    /// seeder lives here alongside the model rather than in the view file.
    static func previewSeeded() -> ConnectionStatsModel {
        let model = ConnectionStatsModel()
        var samples: [StatsSample] = []
        for i in 0..<maxSamples {
            let t = Double(i)
            samples.append(StatsSample(
                id: UInt64(i + 1),
                bytesIn: Int64(400_000 + 350_000 * (sin(t / 6) + 1)),
                bytesOut: Int64(120_000 + 90_000 * (cos(t / 5) + 1)),
                tcpConnectionCount: Int(max(0, 8 + 6 * sin(t / 8))),
                udpConnectionCount: Int(max(0, 3 + 3 * cos(t / 7))),
                memoryBytes: UInt64(max(0, 28_000_000 + 4_000_000 * sin(t / 10)))
            ))
        }
        model.samples = samples
        model.bytesIn = 1_840_000_000
        model.bytesOut = 320_000_000
        model.tcpConnectionCount = samples.last?.tcpConnectionCount ?? 0
        model.udpConnectionCount = samples.last?.udpConnectionCount ?? 0
        model.memoryBytes = samples.last?.memoryBytes ?? 0
        return model
    }
}
#endif
