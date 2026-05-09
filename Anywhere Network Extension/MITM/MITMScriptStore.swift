//
//  MITMScriptStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

/// In-memory key/value store backing `Anywhere.store` in script rules.
/// Keyed by ``CompiledMITMRuleSet/id`` so each imported rule set has
/// its own namespace; deletion of a rule set drops its bucket the next
/// time the store is consulted (we never reach in to clean it).
///
/// Lifetime: process-singleton, no disk persistence. The Network
/// Extension process exits when the user stops the tunnel, taking the
/// store with it. The OS may also recycle the NE under memory
/// pressure; scripts that depend on store contents have to handle a
/// missing key anyway.
///
/// Capacity: a hard per-scope cap of ``maxBytesPerScope``. Writes that
/// would push a scope over the cap throw ``StoreError/capacityExceeded``;
/// the engine surfaces that as a JS `Error` so user code can catch and
/// shed entries via ``delete(scope:key:)``.
final class MITMScriptStore {

    static let shared = MITMScriptStore()

    /// 1 MiB of key+value bytes per rule set. Sized to leave the
    /// Network Extension's ~50 MiB budget intact even with many active
    /// rule sets.
    static let maxBytesPerScope: Int = 1 * 1024 * 1024

    enum StoreError: Error {
        case capacityExceeded
    }

    private let lock = NSLock()
    private var buckets: [UUID: [String: Data]] = [:]

    private init() {}

    func get(scope: UUID, key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return buckets[scope]?[key]
    }

    /// Replaces (or inserts) the value for ``key`` within ``scope``.
    /// Throws when the post-write byte total would exceed the per-scope
    /// cap; the prior value is left untouched in that case.
    func set(scope: UUID, key: String, value: Data) throws {
        lock.lock(); defer { lock.unlock() }
        var bucket = buckets[scope] ?? [:]
        let existing = bucket[key]
        let oldEntryBytes = (existing?.count ?? 0) + (existing == nil ? 0 : key.utf8.count)
        let newEntryBytes = value.count + key.utf8.count
        let currentTotal = bucket.reduce(0) { $0 + $1.key.utf8.count + $1.value.count }
        let projected = currentTotal - oldEntryBytes + newEntryBytes
        if projected > Self.maxBytesPerScope {
            throw StoreError.capacityExceeded
        }
        bucket[key] = value
        buckets[scope] = bucket
    }

    func delete(scope: UUID, key: String) {
        lock.lock(); defer { lock.unlock() }
        guard var bucket = buckets[scope] else { return }
        bucket.removeValue(forKey: key)
        if bucket.isEmpty {
            buckets.removeValue(forKey: scope)
        } else {
            buckets[scope] = bucket
        }
    }

    func keys(scope: UUID) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return buckets[scope].map { Array($0.keys) } ?? []
    }
}
