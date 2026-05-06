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

    private init() {
        configurations = Self.load()
    }

    // MARK: - CRUD

    func add(_ configuration: ProxyConfiguration) {
        configurations.append(configuration)
        save()
    }

    func update(_ configuration: ProxyConfiguration) {
        if let index = configurations.firstIndex(where: { $0.id == configuration.id }) {
            configurations[index] = configuration
            save()
        }
    }

    func delete(_ configuration: ProxyConfiguration) {
        configurations.removeAll { $0.id == configuration.id }
        save()
    }

    func deleteConfigurations(for subscriptionId: UUID) {
        configurations.removeAll { $0.subscriptionId == subscriptionId }
        save()
    }

    /// Atomically replaces all configurations for a subscription in a single assignment,
    /// so the `@Published` publisher fires only once with the final state.
    func replaceConfigurations(for subscriptionId: UUID, with newConfigurations: [ProxyConfiguration]) {
        var updated = configurations.filter { $0.subscriptionId != subscriptionId }
        updated.append(contentsOf: newConfigurations)
        configurations = updated
        save()
    }

    // MARK: - Persistence

    private static func load() -> [ProxyConfiguration] {
        guard let data = JSONBlobStore.shared.load(.configurations) else { return [] }
        return decodeSkippingInvalid(data) ?? []
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

    private func save() {
        let snapshot = configurations
        Task.detached {
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                JSONBlobStore.shared.save(.configurations, data: data)
            } catch {
                print("Failed to save configurations: \(error)")
            }
        }
    }
}
