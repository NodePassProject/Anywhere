//
//  BlobSync.swift
//  Anywhere
//
//  Created by NodePassProject on 6/13/26.
//

import Foundation
import CoreData

private let logger = AnywhereLogger(category: "CloudBlobSync")

protocol SoftDeletable {
    var deletedAt: Date? { get }
}

extension ProxyConfiguration: SoftDeletable {}
extension Subscription: SoftDeletable {}
extension ProxyChain: SoftDeletable {}
extension CustomRoutingRuleSet: SoftDeletable {}
extension MITMRuleSet: SoftDeletable {}

enum Tombstone {
    static let lifetime: TimeInterval = 7 * 24 * 60 * 60

    /// Drops tombstones older than `lifetime`; live records always pass.
    static func collected<T: SoftDeletable>(_ items: [T], now: Date = .now) -> [T] {
        items.filter { item in
            guard let deletedAt = item.deletedAt else { return true }
            return now.timeIntervalSince(deletedAt) < lifetime
        }
    }

    /// Garbage-collects, then partitions into live records and the tombstones still worth syncing.
    static func split<T: SoftDeletable>(_ items: [T], now: Date = .now) -> (live: [T], tombstones: [T]) {
        let kept = collected(items, now: now)
        return (kept.filter { $0.deletedAt == nil }, kept.filter { $0.deletedAt != nil })
    }
}

enum BlobMerge {
    static func register() {
        JSONBlobStore.mergeResolver = { key, rows in
            switch key {
            case .configurations: return mergeArray(ProxyConfiguration.self, rows)
            case .subscriptions:  return mergeArray(Subscription.self, rows)
            case .chains:         return mergeArray(ProxyChain.self, rows)
            case .customRuleSets: return mergeArray(CustomRoutingRuleSet.self, rows)
            case .mitm:           return mergeMITM(rows)
            }
        }
    }
    
    private static func mergeArray<T: Codable & Identifiable & SoftDeletable>(
        _ type: T.Type, _ rows: [(data: Data, updatedAt: Date)]
    ) -> Data {
        let decoder = JSONDecoder()
        // Oldest → newest, so the value merge below lets the newest blob's copy win per id.
        let blobs: [[T]] = rows
            .sorted { $0.updatedAt < $1.updatedAt }
            .compactMap { try? decoder.decode([T].self, from: $0.data) }

        var byId: [T.ID: T] = [:]
        for items in blobs {
            for item in items {
                // Sticky delete: once any blob tombstones an id, a live copy from another blob
                // can't revive it. Among two live or two tombstoned copies, newest still wins.
                if let existing = byId[item.id], existing.deletedAt != nil, item.deletedAt == nil {
                    continue
                }
                byId[item.id] = item
            }
        }

        // Order follows the newest blob that contains each id, so a reorder on the most
        // recently-saving device wins instead of reverting to an older blob's order. Ids
        // present only in older blobs trail, most-recent first.
        var order: [T.ID] = []
        var seen = Set<T.ID>()
        for items in blobs.reversed() {
            for item in items where seen.insert(item.id).inserted {
                order.append(item.id)
            }
        }

        return encode(order.compactMap { byId[$0] }) ?? newest(rows)
    }
    
    private static func mergeMITM(_ rows: [(data: Data, updatedAt: Date)]) -> Data {
        let decoder = JSONDecoder()
        let snapshots: [MITMSnapshot] = rows
            .sorted { $0.updatedAt < $1.updatedAt }
            .compactMap { try? decoder.decode(MITMSnapshot.self, from: $0.data) }

        var byId: [MITMRuleSet.ID: MITMRuleSet] = [:]
        var enabled = false
        for snapshot in snapshots {
            enabled = snapshot.enabled   // oldest → newest, so the newest snapshot wins the master toggle
            for set in snapshot.ruleSets {
                // Sticky delete, same as mergeArray: a tombstoned set isn't revived by a live copy.
                if let existing = byId[set.id], existing.deletedAt != nil, set.deletedAt == nil {
                    continue
                }
                byId[set.id] = set
            }
        }

        // Order follows the newest snapshot that contains each set (see mergeArray).
        var order: [MITMRuleSet.ID] = []
        var seen = Set<MITMRuleSet.ID>()
        for snapshot in snapshots.reversed() {
            for set in snapshot.ruleSets where seen.insert(set.id).inserted {
                order.append(set.id)
            }
        }

        let merged = MITMSnapshot(enabled: enabled, ruleSets: order.compactMap { byId[$0] })
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

enum CloudBlobSync {
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
    }
    
    @MainActor
    private static func scheduleRefresh() {
        guard AWCore.getICloudSyncEnabled() else { return }
        debounce?.cancel()
        debounce = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled else { return }
            refresh()
        }
    }

    @MainActor
    private static func refresh() {
        SubscriptionStore.shared.reload()
        ChainStore.shared.reload()
        ConfigurationStore.shared.reload()   // after chains: coordinate() reads configs + chains
        RoutingRuleSetStore.shared.reload()
        MITMRuleSetStore.shared.reload()
    }
}
