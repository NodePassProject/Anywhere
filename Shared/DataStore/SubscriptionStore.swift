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
    private(set) var subscriptions: [Subscription] = []
    private var tombstones: [Subscription] = []

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private let configurationStore: ConfigurationStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?

    init(syncStore: SyncStore, configurationStore: ConfigurationStore) {
        self.syncStore = syncStore
        self.configurationStore = configurationStore
        let items = syncStore.loadItems(.subscriptions)
        loadedItems = items
        let split = Self.decodeSplit(from: items)
        subscriptions = split.live
        tombstones = split.tombstones
    }

    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], live: [Subscription], tombstones: [Subscription])? in
                let items = syncStore.loadItems(.subscriptions)
                guard items != previous else { return nil }
                let split = Self.decodeSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            subscriptions = outcome.live
            tombstones = outcome.tombstones
            return
        }
    }

    // MARK: - CRUD

    func add(_ subscription: Subscription) {
        let tombstone = tombstones.first { $0.id == subscription.id }
        tombstones.removeAll { $0.id == subscription.id }
        var stamped = subscription
        stamped.updatedAt = SyncStamp.after(tombstone)
        subscriptions.append(stamped)
        save()
    }
    
    private func mutate(id: UUID, _ apply: (inout Subscription) -> Void) {
        guard let index = subscriptions.firstIndex(where: { $0.id == id }) else { return }
        var record = subscriptions[index]
        apply(&record)
        record.updatedAt = SyncStamp.after(subscriptions[index])
        subscriptions[index] = record
        save()
    }
    
    func delete(_ subscription: Subscription) {
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
    
    nonisolated private static func decodeSplit(from items: [Data]) -> (live: [Subscription], tombstones: [Subscription]) {
        Tombstone.split(SyncCodec.decodeItems(Subscription.self, key: .subscriptions, payloads: items))
    }
    
    private func recordTombstone(_ subscription: Subscription) {
        var tomb = Subscription(
            id: subscription.id,
            name: subscription.name,
            url: "",
            updatedAt: subscription.updatedAt
        )
        tomb.deletedAt = .now
        tombstones.removeAll { $0.id == subscription.id }
        tombstones.append(tomb)
    }

    private func save() {
        mutationEpoch += 1
        let live = subscriptions
        let snapshot = live + tombstones
        let previous = saveTask
        saveTask = Task.detached { [syncStore] in
            await previous?.value
            syncStore.save(.subscriptions, items: SyncCodec.encodeItems(snapshot), order: SyncCodec.order(of: live))
        }
    }
}

extension SubscriptionStore {
    func subscription(for configuration: ProxyConfiguration) -> Subscription? {
        guard let subId = configuration.subscriptionId else { return nil }
        return subscriptions.first { $0.id == subId }
    }
    
    var pickerSections: [PickerSection] {
        let configStore = configurationStore
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

    func rename(_ subscription: Subscription, to newName: String) {
        mutate(id: subscription.id) {
            $0.name = newName
            $0.isNameCustomized = true
        }
    }

    func add(_ subscription: Subscription, configurations newConfigurations: [ProxyConfiguration]) {
        add(subscription)
        let tagged = newConfigurations.map { configuration in
            ProxyConfiguration(
                id: configuration.id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscription.id,
                outbound: configuration.outbound
            )
        }
        configurationStore.replaceConfigurations(for: subscription.id, with: tagged)
    }
    
    func applyRefreshResult(_ result: SubscriptionFetcher.Result, to subscriptionId: UUID) {
        mutate(id: subscriptionId) { record in
            record.lastUpdate = Date()
            record.upload = result.upload ?? record.upload
            record.download = result.download ?? record.download
            record.total = result.total ?? record.total
            record.expire = result.expire ?? record.expire
            record.iconLight = result.iconLight ?? record.iconLight
            record.iconDark = result.iconDark ?? record.iconDark
            if let name = result.name, !record.isNameCustomized {
                record.name = name
            }
        }
    }
}
