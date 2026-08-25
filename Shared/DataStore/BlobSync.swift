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
    
    private static func encode<T: Encodable>(_ value: T) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? encoder.encode(value)
    }
}

nonisolated enum LegacyBlobBridge {
    static func importAll(into store: SyncStore) {
        importArray(ProxyConfiguration.self, .configurations, store)
        importArray(ProxyChain.self, .chains, store)
        importArray(ProxyGroup.self, .groups, store)
        importArray(Subscription.self, .subscriptions, store)
        importArray(CustomRoutingRuleSet.self, .customRuleSets, store)
        importMITM(store)
    }
    
    private static func rowsNeedingImport(_ key: SyncStore.Key, _ store: SyncStore) -> [SyncStore.LegacyBlobRow]? {
        let fingerprint = store.legacyBlobFingerprint(key)
        guard !fingerprint.isEmpty, store.lastImportFingerprint(key) != fingerprint else { return nil }
        let rows = store.legacyBlobRows(key)
        guard !rows.isEmpty else { return nil }
        return rows
    }

    private static func importArray<T: Codable & Identifiable & SoftDeletable>(
        _ type: T.Type, _ key: SyncStore.Key, _ store: SyncStore
    ) where T.ID == UUID {
        guard let rows = rowsNeedingImport(key, store) else { return }
        let decoder = JSONDecoder()
        let sorted = rows.sorted { $0.updatedAt < $1.updatedAt }
        let blobs: [[T]] = sorted.compactMap { row in
            if let items = decoder.decodeSkippingInvalid([T].self, from: row.data) { return items }
            SyncStore.quarantine(key, row.data)
            return nil
        }
        guard !blobs.isEmpty else { return }
        apply(BlobMerge.mergeItems(blobs), key, stamp: sorted.last?.updatedAt ?? .distantPast, store)
        store.setLastImportFingerprint(key, SyncStore.legacyFingerprint(of: rows))
    }

    private static func importMITM(_ store: SyncStore) {
        guard let rows = rowsNeedingImport(.mitm, store) else { return }
        let decoder = JSONDecoder()
        let sorted = rows.sorted { $0.updatedAt < $1.updatedAt }
        let snapshots: [MITMSnapshot] = sorted.compactMap { row in
            if let snapshot = try? decoder.decode(MITMSnapshot.self, from: row.data) { return snapshot }
            SyncStore.quarantine(.mitm, row.data)
            return nil
        }
        guard !snapshots.isEmpty else { return }
        apply(BlobMerge.mergeItems(snapshots.map(\.ruleSets)), .mitm, stamp: sorted.last?.updatedAt ?? .distantPast, store)
        store.setLastImportFingerprint(.mitm, SyncStore.legacyFingerprint(of: rows))
    }

    private static func apply<T: Codable & Identifiable & SoftDeletable>(
        _ merged: [T], _ key: SyncStore.Key, stamp: Date, _ store: SyncStore
    ) where T.ID == UUID {
        let order = SyncCodec.order(of: merged.filter { $0.deletedAt == nil })
        store.applyImported(key, items: SyncCodec.encodeItems(merged), order: order, orderStamp: stamp)
    }
}

nonisolated enum CloudBlobSync {
    @MainActor private static var remoteChangeObserver: (any NSObjectProtocol)?
    @MainActor private static var debounce: Task<Void, Never>?
    @MainActor private static var onRemoteChange: (@MainActor () async -> Void)?

    @MainActor
    static func start(onRemoteChange: @escaping @MainActor () async -> Void) {
        Self.onRemoteChange = onRemoteChange
        guard remoteChangeObserver == nil else { return }
        remoteChangeObserver = NotificationCenter.default.addObserver(
            forName: .NSPersistentStoreRemoteChange, object: nil, queue: nil
        ) { _ in
            Task { @MainActor in scheduleRefresh() }
        }
        Task.detached(priority: .utility) {
            SyncStore.shared.reconcile()
            SyncStore.shared.resumeLegacyExports()
        }
    }

    @MainActor
    private static func scheduleRefresh() {
        guard AWCore.getICloudSyncEnabled() else { return }
        debounce?.cancel()
        debounce = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(2000))
            guard !Task.isCancelled else { return }
            logger.info("[iCloud] Store changed remotely; reloading synced stores")
            await Task.detached(priority: .utility) {
                LegacyBlobBridge.importAll(into: .shared)
                SyncStore.shared.reconcile()
            }.value
            guard !Task.isCancelled else { return }
            await onRemoteChange?()
        }
    }
}
