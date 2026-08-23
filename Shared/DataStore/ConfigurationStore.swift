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
    private(set) var configurations: [ProxyConfiguration] = []
    private var tombstones: [ProxyConfiguration] = []

    private(set) var isLoaded = false

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?

    init(syncStore: SyncStore) {
        self.syncStore = syncStore
    }
    
    func loadInitial() async {
        while true {
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .userInitiated) {
                [syncStore] () -> (items: [Data], live: [ProxyConfiguration], tombstones: [ProxyConfiguration]) in
                let items = syncStore.loadItems(.configurations)
                let split = Self.decodeSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            configurations = outcome.live
            tombstones = outcome.tombstones
            isLoaded = true
            return
        }
    }

    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], live: [ProxyConfiguration], tombstones: [ProxyConfiguration])? in
                let items = syncStore.loadItems(.configurations)
                guard items != previous else { return nil }
                let split = Self.decodeSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            configurations = outcome.live
            tombstones = outcome.tombstones
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
    }

    func update(_ configuration: ProxyConfiguration) {
        if let index = configurations.firstIndex(where: { $0.id == configuration.id }) {
            var stamped = configuration
            stamped.updatedAt = SyncStamp.after(configurations[index])
            configurations[index] = stamped
            save()
        }
    }

    func delete(_ configuration: ProxyConfiguration) {
        configurations.removeAll { $0.id == configuration.id }
        recordTombstones([configuration])
        save()
    }

    func deleteConfigurations(for subscriptionId: UUID) {
        let removed = configurations.filter { $0.subscriptionId == subscriptionId }
        configurations.removeAll { $0.subscriptionId == subscriptionId }
        recordTombstones(removed)
        save()
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
    }
    
    func moveConfigurations(withIds ids: [UUID], fromOffsets source: IndexSet, toOffset destination: Int) {
        let idSet = Set(ids)
        configurations.moveSubsequence(where: { idSet.contains($0.id) }, fromOffsets: source, toOffset: destination)
        save()
    }

    func reorderConfigurations(for subscriptionId: UUID, to orderedIds: [UUID]) {
        let indices = configurations.indices.filter { configurations[$0].subscriptionId == subscriptionId }
        let byId = Dictionary(indices.map { (configurations[$0].id, configurations[$0]) }, uniquingKeysWith: { first, _ in first })
        let reordered = orderedIds.compactMap { byId[$0] }
        guard reordered.count == indices.count else { return }
        guard reordered.map(\.id) != indices.map({ configurations[$0].id }) else { return }
        for (offset, index) in indices.enumerated() {
            configurations[index] = reordered[offset]
        }
        save()
    }

    // MARK: - Persistence
    
    nonisolated private static func decodeSplit(from items: [Data]) -> (live: [ProxyConfiguration], tombstones: [ProxyConfiguration]) {
        Tombstone.split(SyncCodec.decodeItems(ProxyConfiguration.self, key: .configurations, payloads: items))
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
        let live = configurations
        let snapshot = live + tombstones
        let previous = saveTask
        saveTask = Task.detached { [syncStore] in
            await previous?.value
            syncStore.save(.configurations, items: SyncCodec.encodeItems(snapshot), order: SyncCodec.order(of: live))
        }
    }
}

extension ConfigurationStore {
    var hasConfigurations: Bool { !configurations.isEmpty }

    func configurations(for subscription: Subscription) -> [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == subscription.id }
    }
}
