//
//  SubscriptionStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
class SubscriptionStore {
    static let shared = SubscriptionStore()

    private(set) var subscriptions: [Subscription] = []
    private var tombstones: [Subscription] = []

    private init() {
        let split = Self.loadSplit()
        subscriptions = split.live
        tombstones = split.tombstones
    }

    func reload() {
        let split = Self.loadSplit()
        subscriptions = split.live
        tombstones = split.tombstones
    }

    // MARK: - CRUD

    func add(_ subscription: Subscription) {
        tombstones.removeAll { $0.id == subscription.id }
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
        recordTombstone(subscription)
        save()
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        subscriptions.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Persistence

    private static func loadSplit() -> (live: [Subscription], tombstones: [Subscription]) {
        guard let data = JSONBlobStore.shared.load(.subscriptions) else { return ([], []) }
        let all = JSONDecoder().decodeSkippingInvalid([Subscription].self, from: data) ?? []
        return Tombstone.split(all)
    }
    
    private func recordTombstone(_ subscription: Subscription) {
        var tomb = subscription
        tomb.deletedAt = .now
        tombstones.removeAll { $0.id == subscription.id }
        tombstones.append(tomb)
    }
    
    @ObservationIgnored private var saveTask: Task<Void, Never>?

    private func save() {
        let snapshot = subscriptions + tombstones
        let previous = saveTask
        saveTask = Task.detached {
            await previous?.value
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

extension SubscriptionStore {
    func subscription(for configuration: ProxyConfiguration) -> Subscription? {
        guard let subId = configuration.subscriptionId else { return nil }
        return subscriptions.first { $0.id == subId }
    }

    /// One picker section per non-empty subscription.
    var pickerSections: [PickerSection] {
        let configStore = ConfigurationStore.shared
        return subscriptions.compactMap { subscription in
            let configs = configStore.configurations(for: subscription)
            guard !configs.isEmpty else { return nil }
            return PickerSection(
                id: subscription.id,
                header: subscription.name,
                items: configs.map { PickerItem(id: $0.id, name: $0.name) }
            )
        }
    }

    func toggleCollapsed(_ subscription: Subscription) {
        var updated = subscription
        updated.collapsed.toggle()
        update(updated)
    }

    func rename(_ subscription: Subscription, to newName: String) {
        var updated = subscription
        updated.name = newName
        updated.isNameCustomized = true
        update(updated)
    }

    /// Adds a subscription and its configurations, tagging each config with the subscription's id.
    func add(_ subscription: Subscription, configurations newConfigurations: [ProxyConfiguration]) {
        // Persist subscription first so an interrupted import never leaves orphan proxies.
        add(subscription)
        let tagged = newConfigurations.map { configuration in
            ProxyConfiguration(
                id: configuration.id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscription.id,
                outbound: configuration.outbound
            )
        }
        ConfigurationStore.shared.replaceConfigurations(for: subscription.id, with: tagged)
    }

    /// Re-fetches a subscription and replaces its configurations, matching new configs to
    /// old ones by name to preserve IDs (and routing-rule assignments).
    func refresh(_ subscription: Subscription) async throws {
        let result = try await SubscriptionFetcher.fetch(url: subscription.url)

        // Configs sharing a name match positionally within that group.
        let oldConfigurations = ConfigurationStore.shared.configurations(for: subscription)
        var oldByName: [String: [ProxyConfiguration]] = [:]
        for old in oldConfigurations {
            oldByName[old.name, default: []].append(old)
        }
        var oldNameCursor: [String: Int] = [:]

        var newConfigurations: [ProxyConfiguration] = []
        for configuration in result.configurations {
            let name = configuration.name
            let cursor = oldNameCursor[name, default: 0]
            let id: UUID
            if let group = oldByName[name], cursor < group.count {
                id = group[cursor].id
                oldNameCursor[name] = cursor + 1
            } else {
                id = configuration.id
            }
            newConfigurations.append(ProxyConfiguration(
                id: id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscription.id,
                outbound: configuration.outbound
            ))
        }

        ConfigurationStore.shared.replaceConfigurations(for: subscription.id, with: newConfigurations)

        var updated = subscription
        updated.lastUpdate = Date()
        updated.upload = result.upload ?? subscription.upload
        updated.download = result.download ?? subscription.download
        updated.total = result.total ?? subscription.total
        updated.expire = result.expire ?? subscription.expire
        if let name = result.name, !updated.isNameCustomized {
            updated.name = name
        }
        update(updated)
    }
}
