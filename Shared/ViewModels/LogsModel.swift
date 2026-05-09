//
//  LogsModel.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation
import NetworkExtension
import Combine

/// Polls the network extension for recent error log entries.
///
/// Fetches logs every second while polling is active.
@MainActor
class LogsModel: ObservableObject {
    static let shared = LogsModel()

    enum LogLevel: String {
        case info
        case warning
        case error
    }

    struct LogEntry: Identifiable {
        let id = UUID()
        let timestamp: Date
        let level: LogLevel
        let message: String
    }

    @Published private(set) var logs: [LogEntry] = []

    private var pollingTask: Task<Void, Never>?

    func startPolling() {
        guard pollingTask == nil else { return }
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, !Task.isCancelled else { break }
                await self.pollLogs()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopPolling(clearLogs: Bool = true) {
        pollingTask?.cancel()
        pollingTask = nil
        if clearLogs {
            logs = []
        }
    }

    private func resolveSession() async -> NETunnelProviderSession? {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        guard let connection = managers?.first?.connection as? NETunnelProviderSession,
              connection.status == .connected else { return nil }
        return connection
    }

    private func pollLogs() async {
        guard let session = await resolveSession() else { return }
        guard let data = try? JSONEncoder().encode(TunnelMessage.fetchLogs) else { return }

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
              let payload = try? JSONDecoder().decode(LogsResponse.self, from: response) else { return }

        self.logs = payload.logs.map { entry in
            LogEntry(
                timestamp: Date(timeIntervalSinceReferenceDate: entry.timestamp),
                level: LogLevel(rawValue: entry.level.rawValue) ?? .info,
                message: entry.message
            )
        }
    }
}
