//
//  MITMScriptStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

/// Key/value store backing `Anywhere.store`, namespaced per rule set and reclaimed by
/// purgeExcept on reload.
final class MITMScriptStore {

    static let shared = MITMScriptStore()

    /// Sized to leave the NE's ~50 MiB budget intact even with many active rule sets.
    static let maxBytesPerScope: Int = 1 * 1024 * 1024

    /// Process-wide ceiling so many rule sets can't pin tens of MiB between reloads.
    static let maxTotalBytes: Int = 16 * 1024 * 1024

    enum StoreError: Error {
        case capacityExceeded
        /// On-disk backing only: the atomic file write (or serialization) failed.
        case writeFailed
    }

    private let lock = NSLock()
    private var buckets: [UUID: [String: Data]] = [:]
    /// Incremental sum of all scopes' bytes; allows O(1) aggregate-cap checks in `set`.
    private var totalBytes: Int = 0
    /// Per-scope byte totals (key.utf8.count + value.count per entry), kept incrementally.
    private var bucketSizes: [UUID: Int] = [:]

    private init() {}

    func get(scope: UUID, key: String, onDisk: Bool = false) -> Data? {
        if onDisk { return MITMScriptDiskStore.shared.get(scope: scope, key: key) }
        lock.lock(); defer { lock.unlock() }
        return buckets[scope]?[key]
    }

    /// Upserts `key` within `scope`; throws without modifying state if the write would exceed either cap.
    func set(scope: UUID, key: String, value: Data, onDisk: Bool = false) throws {
        if onDisk { return try MITMScriptDiskStore.shared.set(scope: scope, key: key, value: value) }
        lock.lock(); defer { lock.unlock() }
        // Avoid `var bucket = buckets[scope]`: aliasing the COW storage makes every write
        // copy the whole bucket; mutating through `buckets[scope, default:]` stays in-place.
        let keyBytes = key.utf8.count
        let oldEntryBytes = buckets[scope]?[key].map { $0.count + keyBytes } ?? 0
        let newEntryBytes = value.count + keyBytes
        let delta = newEntryBytes - oldEntryBytes
        let projected = (bucketSizes[scope] ?? 0) + delta
        if projected > Self.maxBytesPerScope {
            throw StoreError.capacityExceeded
        }
        let projectedTotal = totalBytes + delta
        if projectedTotal > Self.maxTotalBytes {
            throw StoreError.capacityExceeded
        }
        buckets[scope, default: [:]][key] = value
        bucketSizes[scope] = projected
        totalBytes = projectedTotal
    }

    func delete(scope: UUID, key: String, onDisk: Bool = false) {
        if onDisk { return MITMScriptDiskStore.shared.delete(scope: scope, key: key) }
        lock.lock(); defer { lock.unlock() }
        // Mutate through the subscript (not `var bucket = buckets[scope]` + reassign), so removing a
        // key doesn't COW-copy the whole bucket — matching `set`'s in-place discipline.
        guard let existing = buckets[scope]?[key] else { return }
        let delta = existing.count + key.utf8.count
        bucketSizes[scope] = (bucketSizes[scope] ?? 0) - delta
        totalBytes -= delta
        buckets[scope]?.removeValue(forKey: key)
        if buckets[scope]?.isEmpty == true {
            buckets.removeValue(forKey: scope)
            bucketSizes.removeValue(forKey: scope)
        }
    }

    func keys(scope: UUID, onDisk: Bool = false) -> [String] {
        if onDisk { return MITMScriptDiskStore.shared.keys(scope: scope) }
        lock.lock(); defer { lock.unlock() }
        return buckets[scope].map { Array($0.keys) } ?? []
    }
    
    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        lock.lock()
        let stale = buckets.keys.filter { !activeIDs.contains($0) }
        for id in stale {
            totalBytes -= (bucketSizes[id] ?? 0)
            buckets.removeValue(forKey: id)
            bucketSizes.removeValue(forKey: id)
        }
        lock.unlock()
        let diskPurged = MITMScriptDiskStore.shared.purgeExcept(activeIDs: activeIDs)
        return stale.count + diskPurged
    }
}
