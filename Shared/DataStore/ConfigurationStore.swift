//
//  ConfigurationStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine

@MainActor
class ConfigurationStore: ObservableObject {
    static let shared = ConfigurationStore()

    @Published private(set) var configurations: [ProxyConfiguration] = []

    private let fileURL: URL

    private init() {
        AWCore.migrateToAppGroup(fileName: "configurations.json")
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AWCore.suiteName)!
        fileURL = container.appendingPathComponent("configurations.json")
        configurations = loadFromDisk()
    }

    // MARK: - CRUD

    func add(_ configuration: ProxyConfiguration) {
        configurations.append(configuration)
        saveToDisk()
    }

    func update(_ configuration: ProxyConfiguration) {
        if let index = configurations.firstIndex(where: { $0.id == configuration.id }) {
            configurations[index] = configuration
            saveToDisk()
        }
    }

    func delete(_ configuration: ProxyConfiguration) {
        configurations.removeAll { $0.id == configuration.id }
        saveToDisk()
    }

    func deleteConfigurations(for subscriptionId: UUID) {
        configurations.removeAll { $0.subscriptionId == subscriptionId }
        saveToDisk()
    }

    /// Atomically replaces all configurations for a subscription in a single assignment,
    /// so the `@Published` publisher fires only once with the final state.
    func replaceConfigurations(for subscriptionId: UUID, with newConfigurations: [ProxyConfiguration]) {
        var updated = configurations.filter { $0.subscriptionId != subscriptionId }
        updated.append(contentsOf: newConfigurations)
        configurations = updated
        saveToDisk()
    }

    // MARK: - Persistence

    private func loadFromDisk() -> [ProxyConfiguration] {
        if FileManager.default.fileExists(atPath: fileURL.path),
           let data = try? Data(contentsOf: fileURL),
           let result = Self.decodeSkippingInvalid(data) {
            return result
        }
        return []
    }

    private static func decodeSkippingInvalid(_ data: Data) -> [ProxyConfiguration]? {
        guard let wrapped = try? JSONDecoder().decode([FailableDecodable<ProxyConfiguration>].self, from: data) else {
            return nil
        }
        return wrapped.compactMap(\.value)
    }

    private struct FailableDecodable<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws {
            value = try? T(from: decoder)
        }
    }

    private func saveToDisk() {
        let snapshot = configurations
        let url = fileURL
        Task.detached {
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                try data.write(to: url, options: .atomic)
            } catch {
                print("Failed to save configurations: \(error)")
            }
        }
    }
}
