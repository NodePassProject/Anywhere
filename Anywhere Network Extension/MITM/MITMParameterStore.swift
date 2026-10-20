//
//  MITMParameterStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/29/26.
//

import Foundation
import Synchronization

nonisolated final class MITMParameterStore: Sendable {
    static let shared = MITMParameterStore()

    private let table = Mutex<[UUID: [String: String]]>([:])

    private init() {}

    func replaceAll(_ entries: [(scope: UUID, values: [String: String])]) {
        table.withLock { table in
            table.removeAll(keepingCapacity: true)
            for entry in entries where !entry.values.isEmpty {
                table[entry.scope] = entry.values
            }
        }
    }

    func value(forKey key: String, scope: UUID) -> String? {
        table.withLock { $0[scope]?[key] }
    }

    func keys(scope: UUID) -> [String] {
        table.withLock { $0[scope].map { Array($0.keys) } ?? [] }
    }

    func values(scope: UUID) -> [String: String] {
        table.withLock { $0[scope] ?? [:] }
    }
}
