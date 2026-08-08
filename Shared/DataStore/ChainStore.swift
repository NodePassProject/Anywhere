//
//  ChainStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation
import Observation
import SwiftUI

nonisolated private let logger = AnywhereLogger(category: "ChainStore")

@MainActor
@Observable
class ChainStore {
    private(set) var chains: [ProxyChain] = []
    private var tombstones: [ProxyChain] = []

    @ObservationIgnored private let blobStore: JSONBlobStore
    @ObservationIgnored private let configurationStore: ConfigurationStore
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?
    
    @ObservationIgnored var onDidMutate: (() -> Void)?

    init(blobStore: JSONBlobStore, configurationStore: ConfigurationStore) {
        self.blobStore = blobStore
        self.configurationStore = configurationStore
        let data = blobStore.load(.chains)
        loadedBlob = data
        let split = Self.decodeSplit(from: data)
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
            let previous = loadedBlob
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [blobStore] () -> (data: Data?, live: [ProxyChain], tombstones: [ProxyChain])? in
                let data = blobStore.load(.chains)
                guard data != previous else { return nil }
                let split = Self.decodeSplit(from: data)
                return (data, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
            chains = outcome.live
            tombstones = outcome.tombstones
            onDidMutate?()
            return
        }
    }

    // MARK: - Persistence

    nonisolated private static func decodeSplit(from data: Data?) -> (live: [ProxyChain], tombstones: [ProxyChain]) {
        guard let data else { return ([], []) }
        guard let all = JSONDecoder().decodeSkippingInvalid([ProxyChain].self, from: data) else {
            JSONBlobStore.quarantine(.chains, data)
            return ([], [])
        }
        return Tombstone.split(all)
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
        let snapshot = chains + tombstones
        let previous = saveTask
        saveTask = Task.detached { [blobStore] in
            await previous?.value
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                blobStore.save(.chains, data: data)
            } catch {
                logger.report(AnywhereError.store(.saveFailed(.chains, underlying: error)))
            }
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
