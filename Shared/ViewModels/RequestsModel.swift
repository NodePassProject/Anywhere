//
//  RequestsModel.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
class RequestsModel {
    static let shared = RequestsModel()

    struct Entry: Identifiable, Equatable {
        let id: UUID
        let timestamp: Date
        let proto: String
        let host: String
        let port: UInt16
        let routeTarget: RouteTarget
        let viaDefault: Bool
    }

    private(set) var requests: [Entry] = []

    @ObservationIgnored private var pollingTask: Task<Void, Never>?

    func startPolling() {
        guard pollingTask == nil else { return }
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, !Task.isCancelled else { break }
                await self.pollRequests()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopPolling(clearRequests: Bool = true) {
        pollingTask?.cancel()
        pollingTask = nil
        if clearRequests {
            requests = []
        }
    }

    private func resolveSession() async -> NETunnelProviderSession? {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        guard let connection = managers?.first?.connection as? NETunnelProviderSession,
              connection.status == .connected else { return nil }
        return connection
    }

    private func pollRequests() async {
        guard let session = await resolveSession() else { return }
        guard let data = try? JSONEncoder().encode(TunnelMessage.fetchRequests) else { return }

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
              let payload = try? JSONDecoder().decode(RequestsResponse.self, from: response) else { return }

        self.requests = payload.requests.map { entry in
            Entry(
                id: entry.id,
                timestamp: Date(timeIntervalSinceReferenceDate: entry.timestamp),
                proto: entry.proto,
                host: entry.host,
                port: entry.port,
                routeTarget: entry.routeTarget,
                viaDefault: entry.viaDefault
            )
        }
    }
}
