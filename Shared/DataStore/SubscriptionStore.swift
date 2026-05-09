//
//  SubscriptionStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine
import SwiftUI

@MainActor
class SubscriptionStore: ObservableObject {
    static let shared = SubscriptionStore()

    @Published private(set) var subscriptions: [Subscription] = []

    private init() {
        subscriptions = Self.load()
    }

    // MARK: - CRUD

    func add(_ subscription: Subscription) {
        subscriptions.append(subscription)
        save()
    }

    func update(_ subscription: Subscription) {
        if let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) {
            subscriptions[index] = subscription
            save()
        }
    }

    func delete(_ subscription: Subscription, configurationStore: ConfigurationStore = .shared) {
        configurationStore.deleteConfigurations(for: subscription.id)
        subscriptions.removeAll { $0.id == subscription.id }
        save()
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        subscriptions.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Persistence

    private static func load() -> [Subscription] {
        guard let data = JSONBlobStore.shared.load(.subscriptions) else { return [] }
        return JSONDecoder().decodeSkippingInvalid([Subscription].self, from: data) ?? []
    }

    private func save() {
        let snapshot = subscriptions
        Task.detached {
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                JSONBlobStore.shared.save(.subscriptions, data: data)
            } catch {
                print("Failed to save subscriptions: \(error)")
            }
        }
    }
}
