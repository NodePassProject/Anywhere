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
    static let shared = SubscriptionStore()

    private(set) var subscriptions: [Subscription] = []
    private var tombstones: [Subscription] = []
    
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0
    
    @ObservationIgnored private var saveTask: Task<Void, Never>?

    private init() {
        let data = JSONBlobStore.shared.load(.subscriptions)
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
                () -> (data: Data?, live: [Subscription], tombstones: [Subscription])? in
                let data = JSONBlobStore.shared.load(.subscriptions)
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
    
    func delete(_ subscription: Subscription, configurationStore: ConfigurationStore? = nil) {
        let configurationStore = configurationStore ?? .shared
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
        saveTask = Task.detached {
            await previous?.value
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                JSONBlobStore.shared.save(.subscriptions, data: data)
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
        ConfigurationStore.shared.replaceConfigurations(for: subscription.id, with: tagged)
    }
    
    func refresh(_ subscription: Subscription) async throws {
        let subscriptionId = subscription.id
        let url = subscriptions.first { $0.id == subscriptionId }?.url ?? subscription.url
        let result = try await SubscriptionFetcher.fetch(url: url)
        
        guard let current = subscriptions.first(where: { $0.id == subscriptionId }) else { return }

        let oldConfigurations = ConfigurationStore.shared.configurations(for: current)
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
                subscriptionId: subscriptionId,
                outbound: configuration.outbound
            ))
        }

        ConfigurationStore.shared.replaceConfigurations(for: subscriptionId, with: newConfigurations)

        mutate(id: subscriptionId) { record in
            record.lastUpdate = Date()
            record.upload = result.upload ?? record.upload
            record.download = result.download ?? record.download
            record.total = result.total ?? record.total
            record.expire = result.expire ?? record.expire
            if let name = result.name, !record.isNameCustomized {
                record.name = name
            }
        }
    }
}
