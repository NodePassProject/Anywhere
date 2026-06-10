//
//  MITMScriptStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

/// In-memory key/value store backing `Anywhere.store`, namespaced per rule set and reclaimed by
/// purgeExcept on reload. No disk persistence — the NE exits when the tunnel stops, so scripts
/// must handle missing keys. Writes past the per-scope or process-wide cap throw capacityExceeded.
final class MITMScriptStore {

    static let shared = MITMScriptStore()

    /// Sized to leave the NE's ~50 MiB budget intact even with many active rule sets.
    static let maxBytesPerScope: Int = 1 * 1024 * 1024

    /// Process-wide ceiling so many rule sets can't pin tens of MiB between reloads.
    static let maxTotalBytes: Int = 16 * 1024 * 1024

    enum StoreError: Error {
        case capacityExceeded
    }

    private let lock = NSLock()
    private var buckets: [UUID: [String: Data]] = [:]
    /// Incremental sum of all scopes' bytes; allows O(1) aggregate-cap checks in `set`.
    private var totalBytes: Int = 0
    /// Per-scope byte totals (key.utf8.count + value.count per entry), kept incrementally.
    private var bucketSizes: [UUID: Int] = [:]

    private init() {}

    func get(scope: UUID, key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return buckets[scope]?[key]
    }

    /// Upserts `key` within `scope`; throws without modifying state if the write would exceed either cap.
    func set(scope: UUID, key: String, value: Data) throws {
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

    func delete(scope: UUID, key: String) {
        lock.lock(); defer { lock.unlock() }
        guard var bucket = buckets[scope] else { return }
        if let existing = bucket[key] {
            let delta = existing.count + key.utf8.count
            bucketSizes[scope] = (bucketSizes[scope] ?? 0) - delta
            totalBytes -= delta
        }
        bucket.removeValue(forKey: key)
        if bucket.isEmpty {
            buckets.removeValue(forKey: scope)
            bucketSizes.removeValue(forKey: scope)
        } else {
            buckets[scope] = bucket
        }
    }

    func keys(scope: UUID) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return buckets[scope].map { Array($0.keys) } ?? []
    }

    /// Drops every bucket not in `activeIDs` — the store's only GC trigger. Returns the dropped count.
    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        lock.lock(); defer { lock.unlock() }
        let stale = buckets.keys.filter { !activeIDs.contains($0) }
        for id in stale {
            totalBytes -= (bucketSizes[id] ?? 0)
            buckets.removeValue(forKey: id)
            bucketSizes.removeValue(forKey: id)
        }
        return stale.count
    }
}
