//
//  BlobSync.swift
//  Anywhere
//
//  Created by NodePassProject on 6/13/26.
//

import Foundation
import CoreData

nonisolated private let logger = AnywhereLogger(category: "BlobSync")

nonisolated enum BlobMerge {
    static func register() {
        JSONBlobStore.installMergeResolver({ key, rows in
            switch key {
            case .configurations: return mergeArray(ProxyConfiguration.self, key, rows)
            case .subscriptions:  return mergeArray(Subscription.self, key, rows)
            case .chains:         return mergeArray(ProxyChain.self, key, rows)
            case .customRuleSets: return mergeArray(CustomRoutingRuleSet.self, key, rows)
            case .mitm:           return mergeMITM(key, rows)
            }
        }, canFullyDecode: { key, data in
            switch key {
            case .configurations: return decodesFully([ProxyConfiguration].self, data)
            case .subscriptions:  return decodesFully([Subscription].self, data)
            case .chains:         return decodesFully([ProxyChain].self, data)
            case .customRuleSets: return decodesFully([CustomRoutingRuleSet].self, data)
            case .mitm:           return decodesFully(MITMSnapshot.self, data)
            }
        })
    }
    
    private static func decodesFully<T: Decodable>(_ type: T.Type, _ data: Data) -> Bool {
        let tally = DecodeLossTally()
        let decoder = JSONDecoder()
        decoder.userInfo[DecodeLossTally.key] = tally
        guard (try? decoder.decode(T.self, from: data)) != nil else { return false }
        return tally.dropped == 0
    }

    static func prevails<T: Codable & SoftDeletable>(_ challenger: T, over incumbent: T) -> Bool {
        let challengerStamp = challenger.syncStamp, incumbentStamp = incumbent.syncStamp
        if challengerStamp != incumbentStamp { return challengerStamp > incumbentStamp }
        switch (challenger.deletedAt != nil, incumbent.deletedAt != nil) {
        case (true, false): return true
        case (false, true): return false
        default: break
        }
        guard let challengerData = encode(challenger), let incumbentData = encode(incumbent),
              challengerData != incumbentData else { return false }
        if challengerData.count != incumbentData.count {
            return incumbentData.count < challengerData.count
        }
        return incumbentData.lexicographicallyPrecedes(challengerData)
    }
    
    static func mergeItems<T: Codable & Identifiable & SoftDeletable>(_ blobs: [[T]]) -> [T] {
        var byId: [T.ID: T] = [:]
        for items in blobs {
            for item in items {
                if let existing = byId[item.id], !prevails(item, over: existing) { continue }
                byId[item.id] = item
            }
        }

        var order: [T.ID] = []
        var seen = Set<T.ID>()
        for items in blobs.reversed() {
            for item in items where seen.insert(item.id).inserted {
                order.append(item.id)
            }
        }

        return Tombstone.collected(order.compactMap { byId[$0] })
    }

    private static func mergeArray<T: Codable & Identifiable & SoftDeletable>(
        _ type: T.Type, _ key: JSONBlobStore.Key, _ rows: [(data: Data, updatedAt: Date)]
    ) -> Data {
        let decoder = JSONDecoder()
        let blobs: [[T]] = rows
            .sorted { $0.updatedAt < $1.updatedAt }
            .compactMap { row in
                if let items = decoder.decodeSkippingInvalid([T].self, from: row.data) { return items }
                JSONBlobStore.quarantine(key, row.data)
                return nil
            }
        return encode(mergeItems(blobs)) ?? newest(rows)
    }

    private static func mergeMITM(_ key: JSONBlobStore.Key, _ rows: [(data: Data, updatedAt: Date)]) -> Data {
        let decoder = JSONDecoder()
        let snapshots: [MITMSnapshot] = rows
            .sorted { $0.updatedAt < $1.updatedAt }
            .compactMap { row in
                if let snapshot = try? decoder.decode(MITMSnapshot.self, from: row.data) { return snapshot }
                JSONBlobStore.quarantine(key, row.data)
                return nil
            }

        let merged = MITMSnapshot(ruleSets: mergeItems(snapshots.map(\.ruleSets)))
        return encode(merged) ?? newest(rows)
    }

    private static func encode<T: Encodable>(_ value: T) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? encoder.encode(value)
    }

    private static func newest(_ rows: [(data: Data, updatedAt: Date)]) -> Data {
        rows.max { $0.updatedAt < $1.updatedAt }?.data ?? Data()
    }
}

nonisolated enum CloudBlobSync {
    @MainActor private static var remoteChangeObserver: (any NSObjectProtocol)?
    @MainActor private static var debounce: Task<Void, Never>?

    @MainActor
    static func start() {
        BlobMerge.register()
        guard remoteChangeObserver == nil else { return }
        remoteChangeObserver = NotificationCenter.default.addObserver(
            forName: .NSPersistentStoreRemoteChange, object: nil, queue: nil
        ) { _ in
            logger.info("[iCloud] Store changed remotely; reloading synced stores")
            Task { @MainActor in scheduleRefresh() }
        }
        Task.detached(priority: .utility) { JSONBlobStore.shared.reconcile() }
    }

    @MainActor
    private static func scheduleRefresh() {
        guard AWCore.getICloudSyncEnabled() else { return }
        debounce?.cancel()
        debounce = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled else { return }
            await refresh()
        }
    }

    @MainActor
    private static func refresh() async {
        await SubscriptionStore.shared.reload()
        await ChainStore.shared.reload()
        await ConfigurationStore.shared.reload()   // after chains: coordinate() reads configs + chains
        await RoutingRuleSetStore.shared.reload()
        await MITMRuleSetStore.shared.reload()
        Task.detached(priority: .utility) { JSONBlobStore.shared.reconcile() }
    }
}
