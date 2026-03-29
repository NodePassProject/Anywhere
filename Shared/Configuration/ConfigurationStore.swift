//
//  ConfigurationStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine

@MainActor
class ConfigurationStore: ObservableObject, ConfigurationProviding {
    static let shared = ConfigurationStore()

    @Published private(set) var configurations: [ProxyConfiguration] = []

    private let fileURL: URL

    #if os(tvOS)
    private static let userDefaultsKey = "store.configurations"
    #endif

    private init() {
        AWCore.migrateToAppGroup(fileName: "configurations.json")
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AWCore.suiteName)!
        fileURL = container.appendingPathComponent("configurations.json")
        configurations = loadFromDisk()
    }

    // MARK: - ConfigurationProviding

    func loadConfigurations() -> [ProxyConfiguration] {
        configurations
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
           let result = try? JSONDecoder().decode([ProxyConfiguration].self, from: data) {
            return result
        }
        #if os(tvOS)
        if let data = AWCore.userDefaults.data(forKey: Self.userDefaultsKey),
           let result = try? JSONDecoder().decode([ProxyConfiguration].self, from: data) {
            return result
        }
        #endif
        return []
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
            #if os(tvOS)
            if let data = try? JSONEncoder().encode(snapshot) {
                AWCore.userDefaults.set(data, forKey: ConfigurationStore.userDefaultsKey)
            }
            #endif
        }
    }
}
