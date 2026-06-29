//
//  MITMParamStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/29/26.
//

import Foundation

final class MITMParamStore {
    static let shared = MITMParamStore()

    /// scope (rule-set id) → (parameter name → resolved value).
    private var table: [UUID: [String: String]] = [:]
    private let lock = UnfairLock()

    private init() {}

    /// Replaces the whole table (load rebuilds everything); drops empty maps.
    func replaceAll(_ entries: [(scope: UUID, values: [String: String])]) {
        lock.withLock {
            table.removeAll(keepingCapacity: true)
            for entry in entries where !entry.values.isEmpty {
                table[entry.scope] = entry.values
            }
        }
    }

    func get(scope: UUID, key: String) -> String? {
        lock.withLock { table[scope]?[key] }
    }

    func keys(scope: UUID) -> [String] {
        lock.withLock { Array(table[scope]?.keys ?? Dictionary<String, String>().keys) }
    }

    func all(scope: UUID) -> [String: String] {
        lock.withLock { table[scope] ?? [:] }
    }
}
