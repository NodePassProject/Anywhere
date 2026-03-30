//
//  ConnectionStatsModel.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/29/26.
//

import Foundation
import NetworkExtension
import Combine

/// Isolated model for VPN traffic statistics.
///
/// Publishes `bytesIn`/`bytesOut` every second while connected.
@MainActor
class ConnectionStatsModel: ObservableObject {
    static let shared = ConnectionStatsModel()

    @Published private(set) var bytesIn: Int64 = 0
    @Published private(set) var bytesOut: Int64 = 0

    private var statsTask: Task<Void, Never>?
    private weak var session: NETunnelProviderSession?

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
        let message: [String: String] = ["type": "stats"]
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }

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
              let dict = try? JSONSerialization.jsonObject(with: response) as? [String: Any] else { return }
        self.bytesIn = (dict["bytesIn"] as? NSNumber)?.int64Value ?? 0
        self.bytesOut = (dict["bytesOut"] as? NSNumber)?.int64Value ?? 0
    }
}
