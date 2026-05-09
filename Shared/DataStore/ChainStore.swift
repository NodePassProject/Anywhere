//
//  ChainStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation
import Combine

@MainActor
class ChainStore: ObservableObject {
    static let shared = ChainStore()

    @Published private(set) var chains: [ProxyChain] = []

    private init() {
        chains = Self.load()
    }

    // MARK: - CRUD

    func add(_ chain: ProxyChain) {
        chains.append(chain)
        save()
    }

    func update(_ chain: ProxyChain) {
        if let index = chains.firstIndex(where: { $0.id == chain.id }) {
            chains[index] = chain
            save()
        }
    }

    func delete(_ chain: ProxyChain) {
        chains.removeAll { $0.id == chain.id }
        save()
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
