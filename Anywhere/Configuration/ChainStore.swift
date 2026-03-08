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

    private let fileURL: URL

    private init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = documents.appendingPathComponent("chains.json")
        chains = loadFromDisk()
    }

    // MARK: - CRUD

    func add(_ chain: ProxyChain) {
        chains.append(chain)
        saveToDisk()
    }

    func update(_ chain: ProxyChain) {
        if let index = chains.firstIndex(where: { $0.id == chain.id }) {
            chains[index] = chain
            saveToDisk()
        }
    }

    func delete(_ chain: ProxyChain) {
        chains.removeAll { $0.id == chain.id }
        saveToDisk()
    }

    // MARK: - Persistence

    private func loadFromDisk() -> [ProxyChain] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        do {
            let data = try Data(contentsOf: fileURL)
            return try JSONDecoder().decode([ProxyChain].self, from: data)
        } catch {
            print("Failed to load chains: \(error)")
            return []
        }
    }

    private func saveToDisk() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(chains)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            print("Failed to save chains: \(error)")
        }
    }
}
