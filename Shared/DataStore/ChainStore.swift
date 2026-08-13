//
//  ChainStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
class ChainStore {
    private(set) var chains: [ProxyChain] = []
    private var tombstones: [ProxyChain] = []

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private let configurationStore: ConfigurationStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?

    @ObservationIgnored var onDidMutate: (() -> Void)?

    init(syncStore: SyncStore, configurationStore: ConfigurationStore) {
        self.syncStore = syncStore
        self.configurationStore = configurationStore
        let items = syncStore.loadItems(.chains)
        loadedItems = items
        let split = Self.decodeSplit(from: items)
        chains = split.live
        tombstones = split.tombstones
    }

    // MARK: - CRUD

    func add(_ chain: ProxyChain) {
        let tombstone = tombstones.first { $0.id == chain.id }
        tombstones.removeAll { $0.id == chain.id }
        var stamped = chain
        stamped.updatedAt = SyncStamp.after(tombstone)
        chains.append(stamped)
        save()
        onDidMutate?()
    }

    func update(_ chain: ProxyChain) {
        if let index = chains.firstIndex(where: { $0.id == chain.id }) {
            var stamped = chain
            stamped.updatedAt = SyncStamp.after(chains[index])
            chains[index] = stamped
            save()
            onDidMutate?()
        }
    }

    func delete(_ chain: ProxyChain) {
        chains.removeAll { $0.id == chain.id }
        recordTombstone(chain)
        save()
        onDidMutate?()
    }
    
    func moveChains(withIds ids: [UUID], fromOffsets source: IndexSet, toOffset destination: Int) {
        let idSet = Set(ids)
        chains.moveSubsequence(where: { idSet.contains($0.id) }, fromOffsets: source, toOffset: destination)
        save()
    }

    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], live: [ProxyChain], tombstones: [ProxyChain])? in
                let items = syncStore.loadItems(.chains)
                guard items != previous else { return nil }
                let split = Self.decodeSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            chains = outcome.live
            tombstones = outcome.tombstones
            onDidMutate?()
            return
        }
    }

    // MARK: - Persistence

    nonisolated private static func decodeSplit(from items: [Data]) -> (live: [ProxyChain], tombstones: [ProxyChain]) {
        Tombstone.split(SyncCodec.decodeItems(ProxyChain.self, key: .chains, payloads: items))
    }

    private func recordTombstone(_ chain: ProxyChain) {
        var tomb = chain
        tomb.deletedAt = .now
        tomb.proxyIds = []
        tombstones.removeAll { $0.id == chain.id }
        tombstones.append(tomb)
    }

    private func save() {
        mutationEpoch += 1
        let live = chains
        let snapshot = live + tombstones
        let previous = saveTask
        saveTask = Task.detached { [syncStore] in
            await previous?.value
            syncStore.save(.chains, items: SyncCodec.encodeItems(snapshot), order: SyncCodec.order(of: live))
        }
    }
}

extension ChainStore {
    var pickerItems: [PickerItem] {
        let configurations = configurationStore.configurations
        return chains.compactMap { chain in
            let proxies = chain.resolveProxies(from: configurations)
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { return nil }
            return PickerItem(id: chain.id, name: chain.name)
        }
    }
}
