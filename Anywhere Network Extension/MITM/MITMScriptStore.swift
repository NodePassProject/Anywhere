//
//  MITMScriptStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import Synchronization

/// Backs `Anywhere.store`; namespaced per rule set, stale scopes reclaimed by purgeExcept on reload.
nonisolated final class MITMScriptStore: Sendable {

    static let shared = MITMScriptStore()

    /// Sized to leave the NE's ~50 MiB budget intact even with many active rule sets.
    static let maxBytesPerScope: Int = 1 * 1024 * 1024

    /// Process-wide ceiling so many rule sets can't pin tens of MiB between reloads.
    static let maxTotalBytes: Int = 16 * 1024 * 1024

    private struct State {
        var buckets: [UUID: [String: Data]] = [:]
        /// Incremental sum of all scopes' bytes for O(1) aggregate-cap checks in `set`.
        var totalBytes: Int = 0
        /// Per-scope byte totals (key.utf8.count + value.count per entry), kept incrementally.
        var bucketSizes: [UUID: Int] = [:]
    }
    private let state = Mutex(State())

    private init() {}

    func get(scope: UUID, key: String, onDisk: Bool = false) -> Data? {
        if onDisk { return MITMScriptDiskStore.shared.get(scope: scope, key: key) }
        return state.withLock { $0.buckets[scope]?[key] }
    }

    /// Upserts `key` within `scope`; throws without modifying state if the write would exceed either cap.
    func set(scope: UUID, key: String, value: Data, onDisk: Bool = false) throws(AnywhereError) {
        if onDisk { return try MITMScriptDiskStore.shared.set(scope: scope, key: key, value: value) }
        try state.withLock { (state) throws(AnywhereError) in
            // Mutate via subscript to stay in-place; aliasing COW storage copies the whole bucket per write.
            let keyBytes = key.utf8.count
            let oldEntryBytes = state.buckets[scope]?[key].map { $0.count + keyBytes } ?? 0
            let newEntryBytes = value.count + keyBytes
            let delta = newEntryBytes - oldEntryBytes
            let projected = (state.bucketSizes[scope] ?? 0) + delta
            if projected > Self.maxBytesPerScope {
                throw AnywhereError.mitm(.scriptStoreCapacityExceeded)
            }
            let projectedTotal = state.totalBytes + delta
            if projectedTotal > Self.maxTotalBytes {
                throw AnywhereError.mitm(.scriptStoreCapacityExceeded)
            }
            state.buckets[scope, default: [:]][key] = value
            state.bucketSizes[scope] = projected
            state.totalBytes = projectedTotal
        }
    }

    func delete(scope: UUID, key: String, onDisk: Bool = false) {
        if onDisk { return MITMScriptDiskStore.shared.delete(scope: scope, key: key) }
        state.withLock { state in
            // Mutate via subscript to stay in-place (no COW copy).
            guard let existing = state.buckets[scope]?[key] else { return }
            let delta = existing.count + key.utf8.count
            state.bucketSizes[scope] = (state.bucketSizes[scope] ?? 0) - delta
            state.totalBytes -= delta
            state.buckets[scope]?.removeValue(forKey: key)
            if state.buckets[scope]?.isEmpty == true {
                state.buckets.removeValue(forKey: scope)
                state.bucketSizes.removeValue(forKey: scope)
            }
        }
    }

    func keys(scope: UUID, onDisk: Bool = false) -> [String] {
        if onDisk { return MITMScriptDiskStore.shared.keys(scope: scope) }
        return state.withLock { $0.buckets[scope].map { Array($0.keys) } ?? [] }
    }

    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        let staleCount = state.withLock { state -> Int in
            let stale = state.buckets.keys.filter { !activeIDs.contains($0) }
            for id in stale {
                state.totalBytes -= (state.bucketSizes[id] ?? 0)
                state.buckets.removeValue(forKey: id)
                state.bucketSizes.removeValue(forKey: id)
            }
            return stale.count
        }
        let diskPurged = MITMScriptDiskStore.shared.purgeExcept(activeIDs: activeIDs)
        return staleCount + diskPurged
    }
}
