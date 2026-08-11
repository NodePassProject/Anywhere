//
//  SubscriptionStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Observation
import SwiftUI

nonisolated private let logger = AnywhereLogger(category: "SubscriptionStore")

@MainActor
@Observable
class SubscriptionStore {
    private(set) var subscriptions: [Subscription] = []
    private var tombstones: [Subscription] = []

    @ObservationIgnored private let blobStore: JSONBlobStore
    @ObservationIgnored private let configurationStore: ConfigurationStore
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?

    init(blobStore: JSONBlobStore, configurationStore: ConfigurationStore) {
        self.blobStore = blobStore
        self.configurationStore = configurationStore
        let data = blobStore.load(.subscriptions)
        loadedBlob = data
        let split = Self.decodeSplit(from: data)
        subscriptions = split.live
        tombstones = split.tombstones
    }

    func reload() async {
        while true {
            let previous = loadedBlob
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [blobStore] () -> (data: Data?, live: [Subscription], tombstones: [Subscription])? in
                let data = blobStore.load(.subscriptions)
                guard data != previous else { return nil }
                let split = Self.decodeSplit(from: data)
                return (data, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
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
    
    nonisolated private static func decodeSplit(from data: Data?) -> (live: [Subscription], tombstones: [Subscription]) {
        guard let data else { return ([], []) }
        guard let all = JSONDecoder().decodeSkippingInvalid([Subscription].self, from: data) else {
            JSONBlobStore.quarantine(.subscriptions, data)
            return ([], [])
        }
        return Tombstone.split(all)
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
        let snapshot = subscriptions + tombstones
        let previous = saveTask
        saveTask = Task.detached { [blobStore] in
            await previous?.value
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                blobStore.save(.subscriptions, data: data)
            } catch {
                logger.report(AnywhereError.store(.saveFailed(.subscriptions, underlying: error)))
            }
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

    func toggleCollapsed(_ subscription: Subscription) {
        mutate(id: subscription.id) { $0.collapsed.toggle() }
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
