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

    @Published private(set) var configurations: [VLESSConfiguration] = []

    private let fileURL: URL

    private init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = documents.appendingPathComponent("configurations.json")
        configurations = loadFromDisk()
    }

    // MARK: - ConfigurationProviding

    func loadConfigurations() -> [VLESSConfiguration] {
        configurations
    }

    // MARK: - CRUD

    func add(_ configuration: VLESSConfiguration) {
        configurations.append(configuration)
        saveToDisk()
    }

    func update(_ configuration: VLESSConfiguration) {
        if let index = configurations.firstIndex(where: { $0.id == configuration.id }) {
            configurations[index] = configuration
            saveToDisk()
        }
    }

    func delete(_ configuration: VLESSConfiguration) {
        configurations.removeAll { $0.id == configuration.id }
        saveToDisk()
    }

    func deleteConfigurations(for subscriptionId: UUID) {
        configurations.removeAll { $0.subscriptionId == subscriptionId }
        saveToDisk()
    }

    // MARK: - Persistence

    private func loadFromDisk() -> [VLESSConfiguration] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        do {
            let data = try Data(contentsOf: fileURL)
            return try JSONDecoder().decode([VLESSConfiguration].self, from: data)
        } catch {
            print("Failed to load configurations: \(error)")
            return []
        }
    }

    private func saveToDisk() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(configurations)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            print("Failed to save configurations: \(error)")
        }
    }
}
