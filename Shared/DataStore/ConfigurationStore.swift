//
//  ConfigurationStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
class ConfigurationStore {
    static let shared = ConfigurationStore()

    private(set) var configurations: [ProxyConfiguration] = []

    private init() {
        configurations = Self.load()
        // Coordinate dependent state once at launch (deferred so init finishes first).
        Task { @MainActor in self.coordinate() }
    }

    // MARK: - CRUD

    func add(_ configuration: ProxyConfiguration) {
        configurations.append(configuration)
        save()
        coordinate()
    }

    func update(_ configuration: ProxyConfiguration) {
        if let index = configurations.firstIndex(where: { $0.id == configuration.id }) {
            configurations[index] = configuration
            save()
            coordinate()
        }
    }

    func delete(_ configuration: ProxyConfiguration) {
        configurations.removeAll { $0.id == configuration.id }
        save()
        coordinate()
    }

    func deleteConfigurations(for subscriptionId: UUID) {
        configurations.removeAll { $0.subscriptionId == subscriptionId }
        save()
        coordinate()
    }

    /// Replaces a subscription's configurations in a single assignment so observers are notified once.
    func replaceConfigurations(for subscriptionId: UUID, with newConfigurations: [ProxyConfiguration]) {
        var updated = configurations.filter { $0.subscriptionId != subscriptionId }
        updated.append(contentsOf: newConfigurations)
        configurations = updated
        save()
        coordinate()
    }

    /// Reorders standalone configurations; subscription-owned ones keep their absolute positions.
    func moveStandaloneConfigurations(fromOffsets source: IndexSet, toOffset destination: Int) {
        let standaloneIndices = configurations.indices.filter { configurations[$0].subscriptionId == nil }
        var standalone = standaloneIndices.map { configurations[$0] }
        standalone.move(fromOffsets: source, toOffset: destination)
        var updated = configurations
        for (i, idx) in standaloneIndices.enumerated() {
            updated[idx] = standalone[i]
        }
        configurations = updated
        save()
        coordinate()
    }

    // MARK: - Coordination

    /// Keeps the VPN selection and routing-rule state consistent after any change to the proxy list.
    private func coordinate() {
        let chains = ChainStore.shared.chains
        VPNViewModel.shared.revalidateSelection(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.clearOrphans(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.scheduleSyncToAppGroup()
    }

    // MARK: - Persistence

    private static func load() -> [ProxyConfiguration] {
        guard let data = JSONBlobStore.shared.load(.configurations) else { return [] }
        return JSONDecoder().decodeSkippingInvalid([ProxyConfiguration].self, from: data) ?? []
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

extension ConfigurationStore {
    var hasConfigurations: Bool { !configurations.isEmpty }

    func configurations(for subscription: Subscription) -> [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == subscription.id }
    }

    var standalonePickerItems: [PickerItem] {
        configurations
            .filter { $0.subscriptionId == nil }
            .map { PickerItem(id: $0.id, name: $0.name) }
    }
}
