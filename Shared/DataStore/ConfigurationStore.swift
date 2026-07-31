//
//  ConfigurationStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Observation
import SwiftUI

nonisolated private let logger = AnywhereLogger(category: "ConfigurationStore")

@MainActor
@Observable
class ConfigurationStore {
    static let shared = ConfigurationStore()

    private(set) var configurations: [ProxyConfiguration] = []
    private var tombstones: [ProxyConfiguration] = []

    private(set) var isLoaded = false

    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0
    
    @ObservationIgnored private var saveTask: Task<Void, Never>?

    private init() {
        Task { @MainActor in await self.loadInitial() }
    }

    private func loadInitial() async {
        while true {
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .userInitiated) {
                () -> (data: Data?, live: [ProxyConfiguration], tombstones: [ProxyConfiguration]) in
                let data = JSONBlobStore.shared.load(.configurations)
                let split = Self.decodeSplit(from: data)
                return (data, split.live, split.tombstones)
            }.value
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
            configurations = outcome.live
            tombstones = outcome.tombstones
            isLoaded = true
            coordinate()
            return
        }
    }

    func reload() async {
        while true {
            let previous = loadedBlob
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                () -> (data: Data?, live: [ProxyConfiguration], tombstones: [ProxyConfiguration])? in
                let data = JSONBlobStore.shared.load(.configurations)
                guard data != previous else { return nil }
                let split = Self.decodeSplit(from: data)
                return (data, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
            configurations = outcome.live
            tombstones = outcome.tombstones
            coordinate()
            return
        }
    }

    // MARK: - CRUD

    func add(_ configuration: ProxyConfiguration) {
        let tombstone = tombstones.first { $0.id == configuration.id }
        tombstones.removeAll { $0.id == configuration.id }
        var stamped = configuration
        stamped.updatedAt = SyncStamp.after(tombstone)
        configurations.append(stamped)
        save()
        coordinate()
    }

    func update(_ configuration: ProxyConfiguration) {
        if let index = configurations.firstIndex(where: { $0.id == configuration.id }) {
            var stamped = configuration
            stamped.updatedAt = SyncStamp.after(configurations[index])
            configurations[index] = stamped
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
    
    func replaceConfigurations(for subscriptionId: UUID, with newConfigurations: [ProxyConfiguration]) {
        let newIds = Set(newConfigurations.map { $0.id })
        let removed = configurations.filter { $0.subscriptionId == subscriptionId && !newIds.contains($0.id) }
        
        let previousById = Dictionary(
            configurations.filter { $0.subscriptionId == subscriptionId }.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let tombstonesById = Dictionary(
            tombstones.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let stamped = newConfigurations.map { configuration in
            var copy = configuration
            if let previous = previousById[configuration.id], previous.contentEquals(configuration) {
                copy.updatedAt = previous.updatedAt
            } else {
                copy.updatedAt = SyncStamp.after(previousById[configuration.id] ?? tombstonesById[configuration.id])
            }
            return copy
        }

        var updated = configurations.filter { $0.subscriptionId != subscriptionId }
        updated.append(contentsOf: stamped)
        configurations = updated

        recordTombstones(removed)
        tombstones.removeAll { newIds.contains($0.id) }
        save()
        coordinate()
    }
    
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
    
    private func coordinate() {
        let chains = ChainStore.shared.chains
        VPNViewModel.shared.revalidateSelection(configurations: configurations, chains: chains)
        VPNViewModel.shared.pruneLatencyState(liveConfigurationIds: Set(configurations.map(\.id)))
        RoutingRuleSetStore.shared.clearOrphans(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.scheduleSyncToAppGroup()
    }

    // MARK: - Persistence
    
    nonisolated private static func decodeSplit(from data: Data?) -> (live: [ProxyConfiguration], tombstones: [ProxyConfiguration]) {
        guard let data else { return ([], []) }
        guard let all = JSONDecoder().decodeSkippingInvalid([ProxyConfiguration].self, from: data) else {
            JSONBlobStore.quarantine(.configurations, data)
            return ([], [])
        }
        return Tombstone.split(all)
    }
    
    private func recordTombstones(_ removed: [ProxyConfiguration]) {
        guard !removed.isEmpty else { return }
        let now = Date.now
        let ids = Set(removed.map { $0.id })
        tombstones.removeAll { ids.contains($0.id) }
        for item in removed {
            var tomb = ProxyConfiguration(
                id: item.id,
                name: item.name,
                serverAddress: "",
                serverPort: 0,
                outbound: .socks5(username: nil, password: nil),
                updatedAt: item.updatedAt
            )
            tomb.deletedAt = now
            tombstones.append(tomb)
        }
    }

    private func save() {
        mutationEpoch += 1
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
                logger.report(AnywhereError.store(.saveFailed(.configurations, underlying: error)))
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
