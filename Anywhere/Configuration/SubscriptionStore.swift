//
//  SubscriptionStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine

@MainActor
class SubscriptionStore: ObservableObject {
    static let shared = SubscriptionStore()

    @Published private(set) var subscriptions: [Subscription] = []

    private let fileURL: URL

    private init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = documents.appendingPathComponent("subscriptions.json")
        subscriptions = loadFromDisk()
    }

    // MARK: - CRUD

    func add(_ subscription: Subscription) {
        subscriptions.append(subscription)
        saveToDisk()
    }

    func update(_ subscription: Subscription) {
        if let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) {
            subscriptions[index] = subscription
            saveToDisk()
        }
    }

    func delete(_ subscription: Subscription, configurationStore: ConfigurationStore = .shared) {
        configurationStore.deleteConfigurations(for: subscription.id)
        subscriptions.removeAll { $0.id == subscription.id }
        saveToDisk()
    }

    // MARK: - Persistence

    private func loadFromDisk() -> [Subscription] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        do {
            let data = try Data(contentsOf: fileURL)
            return try JSONDecoder().decode([Subscription].self, from: data)
        } catch {
            print("Failed to load subscriptions: \(error)")
            return []
        }
    }

    private func saveToDisk() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(subscriptions)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            print("Failed to save subscriptions: \(error)")
        }
    }
}
