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
    static let shared = ChainStore()

    private(set) var chains: [ProxyChain] = []

    private init() {
        chains = Self.load()
        // Coordinate dependent state once at launch (deferred so init finishes first).
        Task { @MainActor in self.coordinate() }
    }

    // MARK: - CRUD

    func add(_ chain: ProxyChain) {
        chains.append(chain)
        save()
        coordinate()
    }

    func update(_ chain: ProxyChain) {
        if let index = chains.firstIndex(where: { $0.id == chain.id }) {
            chains[index] = chain
            save()
            coordinate()
        }
    }

    func delete(_ chain: ProxyChain) {
        chains.removeAll { $0.id == chain.id }
        save()
        coordinate()
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        chains.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Coordination

    /// Keeps the VPN selection and routing-rule state consistent after any change to the chain list.
    private func coordinate() {
        let configurations = ConfigurationStore.shared.configurations
        VPNViewModel.shared.revalidateSelection(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.clearOrphans(configurations: configurations, chains: chains)
        RoutingRuleSetStore.shared.scheduleSyncToAppGroup()
    }

    // MARK: - Persistence

    private static func load() -> [ProxyChain] {
        guard let data = JSONBlobStore.shared.load(.chains) else { return [] }
        return JSONDecoder().decodeSkippingInvalid([ProxyChain].self, from: data) ?? []
    }

    private func save() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(chains)
            JSONBlobStore.shared.save(.chains, data: data)
        } catch {
            print("Failed to save chains: \(error)")
        }
    }
}

extension ChainStore {
    /// Valid chains (those resolving to ≥2 proxies) as picker items.
    var pickerItems: [PickerItem] {
        let configurations = ConfigurationStore.shared.configurations
        return chains.compactMap { chain in
            let proxies = chain.resolveProxies(from: configurations)
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { return nil }
            return PickerItem(id: chain.id, name: chain.name)
        }
    }
}
