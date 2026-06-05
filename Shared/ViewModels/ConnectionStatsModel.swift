//
//  ConnectionStatsModel.swift
//  Anywhere
//
//  Created by NodePassProject on 3/29/26.
//

import Foundation
import NetworkExtension
import Observation

/// Isolated model for VPN traffic statistics.
///
/// Publishes `bytesIn`/`bytesOut` every second while connected.
@MainActor
@Observable
class ConnectionStatsModel {
    static let shared = ConnectionStatsModel()

    private(set) var bytesIn: Int64 = 0
    private(set) var bytesOut: Int64 = 0

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
    }
}
