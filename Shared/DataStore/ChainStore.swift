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

    #if os(tvOS)
    private static let userDefaultsKey = "store.chains"
    #endif

    private init() {
        AWCore.migrateToAppGroup(fileName: "chains.json")
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AWCore.suiteName)!
        fileURL = container.appendingPathComponent("chains.json")
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
        if FileManager.default.fileExists(atPath: fileURL.path),
           let data = try? Data(contentsOf: fileURL),
           let result = try? JSONDecoder().decode([ProxyChain].self, from: data) {
            return result
        }
        #if os(tvOS)
        if let data = AWCore.userDefaults.data(forKey: Self.userDefaultsKey),
           let result = try? JSONDecoder().decode([ProxyChain].self, from: data) {
            return result
        }
        #endif
        return []
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
        #if os(tvOS)
        if let data = try? JSONEncoder().encode(chains) {
            AWCore.userDefaults.set(data, forKey: Self.userDefaultsKey)
        }
        #endif
    }
}
