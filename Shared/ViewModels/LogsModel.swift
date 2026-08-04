//
//  LogsModel.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
class LogsModel {
    enum LogLevel: String {
        case info
        case warning
        case error
    }

    struct LogEntry: Identifiable, Equatable {
        let id: UUID
        let timestamp: Date
        let level: LogLevel
        let message: String
    }

    private(set) var logs: [LogEntry] = []

    func clear() {
        logs = []
    }

    private func resolveSession() async -> NETunnelProviderSession? {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        guard let connection = managers?.first?.connection as? NETunnelProviderSession,
              connection.status == .connected else { return nil }
        return connection
    }
    
    func poll() async {
        guard let session = await resolveSession() else { return }
        guard let data = try? JSONEncoder().encode(TunnelMessage.fetchLogs) else { return }

        let response = await ProviderMessageConcurrencyBridge.send(data, over: session)

        guard !Task.isCancelled else { return }

        guard let response,
              let payload = try? JSONDecoder().decode(LogsResponse.self, from: response) else { return }

        self.logs = payload.logs.map { entry in
            LogEntry(
                id: entry.id,
                timestamp: Date(timeIntervalSinceReferenceDate: entry.timestamp),
                level: LogLevel(rawValue: entry.level.rawValue) ?? .info,
                message: entry.message
            )
        }
    }
}
