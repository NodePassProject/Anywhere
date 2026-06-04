//
//  MITMScriptStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

/// In-memory key/value store backing `Anywhere.store` in script rules.
/// Keyed by ``CompiledMITMRuleSet/id`` so each imported rule set has
/// its own namespace. Buckets for deleted rule sets are reclaimed by
/// ``purgeExcept(activeIDs:)``, which ``MITMRewritePolicy/load`` calls
/// after every rule-set reload.
///
/// Scoping is per-rule-set (not per-rule): the runtime fires at most
/// one ``.script`` and one ``.streamScript`` rule per message in a
/// given rule set (see ``MITMScriptTransform``), so a single shared
/// bucket per set is the natural unit. Authors who compose multiple
/// effects do so inside one `process(ctx)`, and that function gets the
/// whole bucket without contention.
///
/// Lifetime: process-singleton, no disk persistence. The Network
/// Extension process exits when the user stops the tunnel, taking the
/// store with it. The OS may also recycle the NE under memory
/// pressure; scripts that depend on store contents have to handle a
/// missing key anyway.
///
/// Capacity: a hard per-scope cap of ``maxBytesPerScope`` *and* a
/// process-wide aggregate cap of ``maxTotalBytes`` across all scopes.
/// Either ceiling rejects a write with ``StoreError/capacityExceeded``;
/// the engine surfaces that as a JS `Error` so user code can catch and
/// shed entries via ``delete(scope:key:)``. The aggregate cap bounds the
/// store's total footprint between rule-set reloads: a bundle of many rule
/// sets (each filling its own 1 MiB scope) could otherwise pin tens of MiB
/// until the next ``purgeExcept(activeIDs:)``.
final class MITMScriptStore {

    static let shared = MITMScriptStore()

    /// 1 MiB of key+value bytes per rule set. Sized to leave the
    /// Network Extension's ~50 MiB budget intact even with many active
    /// rule sets.
    static let maxBytesPerScope: Int = 1 * 1024 * 1024

    /// Process-wide ceiling on the sum of every scope's bytes. Generous
    /// versus the per-scope cap (room for many full scopes) while bounding
    /// the store's worst-case footprint so a bundle of many rule sets can't
    /// accumulate unboundedly against the NE memory budget between reloads.
    static let maxTotalBytes: Int = 16 * 1024 * 1024

    enum StoreError: Error {
        case capacityExceeded
    }

    private let lock = NSLock()
    private var buckets: [UUID: [String: Data]] = [:]
    /// Running sum of every scope's bytes (``bucketSizes.values``), kept
    /// incrementally so ``set`` can check the aggregate cap in O(1).
    private var totalBytes: Int = 0
    /// Running per-scope size in bytes (sum of key.utf8.count + value.count
    /// over every entry). Mirrors ``buckets`` so ``set`` can compute the
    /// cap-check projection in O(1) instead of rescanning the bucket on
    /// every write — a script that stores hundreds of keys per request
    /// would otherwise pay O(N²) over the request's lifetime.
    private var bucketSizes: [UUID: Int] = [:]

    private init() {}

    func get(scope: UUID, key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return buckets[scope]?[key]
    }

    /// Replaces (or inserts) the value for ``key`` within ``scope``.
    /// Throws when the write would exceed the per-scope cap or the process-wide
    /// aggregate cap; the prior value is left untouched in that case.
    func set(scope: UUID, key: String, value: Data) throws {
        lock.lock(); defer { lock.unlock() }
        // Read the prior entry's byte cost without binding the bucket to a
        // local: `var bucket = buckets[scope]` would alias the bucket's COW
        // storage, so the later `bucket[key] = value` would copy the *whole*
        // bucket — O(N) per write, O(N²) for a script storing N keys over a
        // request. Computing the delta from a transient read and then mutating
        // through `buckets[scope, default:]` keeps the write in-place (O(1)).
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

    /// Drops every bucket whose scope is not in ``activeIDs``. Called
    /// from ``MITMRewritePolicy/load`` when the user edits their rule
    /// set list — the store's only GC trigger, so a user churning rule
    /// sets while debugging would otherwise accumulate dead scopes
    /// (1 MiB each) until the NE recycles.
    /// Returns the number of buckets dropped so the caller can log
    /// the reclaim.
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
