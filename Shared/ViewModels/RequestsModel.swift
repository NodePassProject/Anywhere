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
        enum `Protocol`: String {
            case tcp
            case udp
            case quic
            case http
        }
        
        let id: UUID
        let timestamp: Date
        let `protocol`: `Protocol`
        let host: String
        let port: UInt16
        let routeTarget: RouteTarget
        let viaDefault: Bool
        let ruleSetName: String?
    }

    private(set) var requests: [Entry] = []

    func clear() {
        requests = []
    }

    private func resolveSession() async -> NETunnelProviderSession? {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        guard let connection = managers?.first?.connection as? NETunnelProviderSession,
              connection.status == .connected else { return nil }
        return connection
    }
    
    func poll() async {
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

        guard !Task.isCancelled else { return }

        guard let response,
              let payload = try? JSONDecoder().decode(RequestsResponse.self, from: response) else { return }

        self.requests = payload.requests.map { entry in
            var `protocol`: Entry.`Protocol`
            switch entry.protocol {
            case .tcp:
                `protocol` = .tcp
            case .udp:
                if entry.port == 443 {
                    `protocol` = .quic
                } else {
                    `protocol` = .udp
                }
            case .http:
                `protocol` = .http
            }
            return Entry(
                id: entry.id,
                timestamp: Date(timeIntervalSinceReferenceDate: entry.timestamp),
                protocol: `protocol`,
                host: entry.host,
                port: entry.port,
                routeTarget: entry.routeTarget,
                viaDefault: entry.viaDefault,
                ruleSetName: entry.ruleSetName
            )
        }
    }
}
