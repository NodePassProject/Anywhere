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

    #if os(tvOS)
    private static let userDefaultsKey = "store.subscriptions"
    #endif

    private init() {
        AWCore.migrateToAppGroup(fileName: "subscriptions.json")
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AWCore.suiteName)!
        fileURL = container.appendingPathComponent("subscriptions.json")
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
        if FileManager.default.fileExists(atPath: fileURL.path),
           let data = try? Data(contentsOf: fileURL),
           let result = try? JSONDecoder().decode([Subscription].self, from: data) {
            return result
        }
        #if os(tvOS)
        if let data = AWCore.userDefaults.data(forKey: Self.userDefaultsKey),
           let result = try? JSONDecoder().decode([Subscription].self, from: data) {
            return result
        }
        #endif
        return []
    }

    private func saveToDisk() {
        let snapshot = subscriptions
        let url = fileURL
        Task.detached {
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                try data.write(to: url, options: .atomic)
            } catch {
                print("Failed to save subscriptions: \(error)")
            }
            #if os(tvOS)
            if let data = try? JSONEncoder().encode(snapshot) {
                AWCore.userDefaults.set(data, forKey: SubscriptionStore.userDefaultsKey)
            }
            #endif
        }
    }
}
