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
    static let shared = ChainStore()

    private(set) var chains: [ProxyChain] = []
    private var tombstones: [ProxyChain] = []
    
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0

    private init() {
        let data = JSONBlobStore.shared.load(.chains)
        loadedBlob = data
        let split = Self.decodeSplit(from: data)
        chains = split.live
        tombstones = split.tombstones
        Task { @MainActor in self.coordinate() }
    }

    // MARK: - CRUD

    func add(_ chain: ProxyChain) {
        let tombstone = tombstones.first { $0.id == chain.id }
        tombstones.removeAll { $0.id == chain.id }
        var stamped = chain
        stamped.updatedAt = SyncStamp.after(tombstone)
        chains.append(stamped)
        save()
        coordinate()
    }

    func update(_ chain: ProxyChain) {
        if let index = chains.firstIndex(where: { $0.id == chain.id }) {
            var stamped = chain
            stamped.updatedAt = SyncStamp.after(chains[index])
            chains[index] = stamped
            save()
            coordinate()
        }
    }

    func delete(_ chain: ProxyChain) {
        chains.removeAll { $0.id == chain.id }
        recordTombstone(chain)
        save()
        coordinate()
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        chains.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Coordination
    
    private func coordinate() {
        guard ConfigurationStore.shared.isLoaded else { return }
        let configurations = ConfigurationStore.shared.configurations
        VPNViewModel.shared.revalidateSelection(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.clearOrphans(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.scheduleSyncToAppGroup()
    }
    
    func reload() async {
        while true {
            let previous = loadedBlob
            let epoch = mutationEpoch
            let outcome = await Task.detached(priority: .utility) {
                () -> (data: Data?, live: [ProxyChain], tombstones: [ProxyChain])? in
                let data = JSONBlobStore.shared.load(.chains)
                guard data != previous else { return nil }
                let split = Self.decodeSplit(from: data)
                return (data, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
            chains = outcome.live
            tombstones = outcome.tombstones
            coordinate()
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
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(chains + tombstones)
            JSONBlobStore.shared.save(.chains, data: data)
        } catch {
            logger.report(AnywhereError.store(.saveFailed(.chains, underlying: error)))
        }
    }
}

extension ChainStore {
    var pickerItems: [PickerItem] {
        let configurations = ConfigurationStore.shared.configurations
        return chains.compactMap { chain in
            let proxies = chain.resolveProxies(from: configurations)
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { return nil }
            return PickerItem(id: chain.id, name: chain.name)
        }
    }
}
