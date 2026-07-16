//
//  MITMParamStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/29/26.
//

import Foundation
import Synchronization

nonisolated final class MITMParamStore {
    static let shared = MITMParamStore()

    /// scope (rule-set id) → (parameter name → resolved value).
    private let table = Mutex<[UUID: [String: String]]>([:])

    private init() {}

    /// Replaces the whole table (load rebuilds everything); drops empty maps.
    func replaceAll(_ entries: [(scope: UUID, values: [String: String])]) {
        table.withLock { table in
            table.removeAll(keepingCapacity: true)
            for entry in entries where !entry.values.isEmpty {
                table[entry.scope] = entry.values
            }
        }
    }

    func get(scope: UUID, key: String) -> String? {
        table.withLock { $0[scope]?[key] }
    }

    func keys(scope: UUID) -> [String] {
        table.withLock { Array($0[scope]?.keys ?? Dictionary<String, String>().keys) }
    }

    func all(scope: UUID) -> [String: String] {
        table.withLock { $0[scope] ?? [:] }
    }
}
