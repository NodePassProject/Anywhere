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
    private var tombstones: [ProxyConfiguration] = []

    private init() {
        let split = Self.loadSplit()
        configurations = split.live
        tombstones = split.tombstones
        // Must stay deferred: coordinate() reads ChainStore.shared, and the two stores reference
        // each other, so calling it synchronously here re-enters this type's `static let shared`
        // dispatch_once and deadlocks. Running it after init lets dispatch_once finish first.
        Task { @MainActor in self.coordinate() }
    }
    
    func reload() {
        let split = Self.loadSplit()
        configurations = split.live
        tombstones = split.tombstones
        coordinate()
    }

    // MARK: - CRUD

    func add(_ configuration: ProxyConfiguration) {
        tombstones.removeAll { $0.id == configuration.id }
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
        recordTombstones([configuration])
        save()
        coordinate()
    }

    func deleteConfigurations(for subscriptionId: UUID) {
        let removed = configurations.filter { $0.subscriptionId == subscriptionId }
        configurations.removeAll { $0.subscriptionId == subscriptionId }
        recordTombstones(removed)
        save()
        coordinate()
    }

    /// Replaces a subscription's configurations in a single assignment so observers are notified once.
    func replaceConfigurations(for subscriptionId: UUID, with newConfigurations: [ProxyConfiguration]) {
        let newIds = Set(newConfigurations.map { $0.id })
        // Configs that were owned by this subscription but are gone upstream must be tombstoned,
        // not merely dropped: a bare removal is undone by the cross-device union-merge, which
        // revives any id still live in another device's blob. Their ids are disjoint from newIds.
        let removed = configurations.filter { $0.subscriptionId == subscriptionId && !newIds.contains($0.id) }

        var updated = configurations.filter { $0.subscriptionId != subscriptionId }
        updated.append(contentsOf: newConfigurations)
        configurations = updated

        recordTombstones(removed)
        // An id coming back live must clear any stale tombstone so the merge won't suppress it elsewhere.
        tombstones.removeAll { newIds.contains($0.id) }
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

    private static func loadSplit() -> (live: [ProxyConfiguration], tombstones: [ProxyConfiguration]) {
        guard let data = JSONBlobStore.shared.load(.configurations) else { return ([], []) }
        let all = JSONDecoder().decodeSkippingInvalid([ProxyConfiguration].self, from: data) ?? []
        return Tombstone.split(all)
    }
    
    private func recordTombstones(_ removed: [ProxyConfiguration]) {
        guard !removed.isEmpty else { return }
        let now = Date.now
        let ids = Set(removed.map { $0.id })
        tombstones.removeAll { ids.contains($0.id) }
        for item in removed {
            var tomb = item
            tomb.deletedAt = now
            tombstones.append(tomb)
        }
    }
    
    @ObservationIgnored private var saveTask: Task<Void, Never>?

    private func save() {
        let snapshot = configurations + tombstones
        let previous = saveTask
        saveTask = Task.detached {
            await previous?.value
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
