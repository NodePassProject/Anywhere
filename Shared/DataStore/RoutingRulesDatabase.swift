//
//  RoutingRulesDatabase.swift
//  Anywhere
//
//  Created by NodePassProject on 4/5/26.
//

import Foundation
import SQLite3

nonisolated private let logger = AnywhereLogger(category: "RoutingRulesDatabase")

/// Read-only SQLite over bundled `rules(source, type, value)` and `metadata(key, value)`; metadata values are JSON.
final class RoutingRulesDatabase {
    static let shared = RoutingRulesDatabase()

    private var databaseHandle: OpaquePointer?

    private init() {
        guard let url = Bundle.main.url(forResource: "Rules", withExtension: "db") else {
            logger.error("[RoutingRulesDatabase] Rules.db not found in bundle")
            return
        }
        if sqlite3_open_v2(url.path, &databaseHandle, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) != SQLITE_OK {
            logger.error("[RoutingRulesDatabase] Failed to open Rules.db")
            databaseHandle = nil
        }
    }

    // MARK: - Queries

    func loadRules(for source: String) -> [RoutingRule] {
        guard let databaseHandle else { return [] }

        var statementHandle: OpaquePointer?
        defer { sqlite3_finalize(statementHandle) }

        guard sqlite3_prepare_v2(databaseHandle, "SELECT type, value FROM rules WHERE source = ?", -1, &statementHandle, nil) == SQLITE_OK else {
            return []
        }
        sqlite3_bind_text(statementHandle, 1, source, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        var rules: [RoutingRule] = []
        while sqlite3_step(statementHandle) == SQLITE_ROW {
            let type = Int(sqlite3_column_int(statementHandle, 0))
            guard let columnTextPointer = sqlite3_column_text(statementHandle, 1),
                  let ruleType = RoutingRuleType(rawValue: type) else { continue }
            rules.append(RoutingRule(type: ruleType, value: String(cString: columnTextPointer)))
        }
        return rules
    }

    func loadMetadata(_ key: String) -> String? {
        guard let databaseHandle else { return nil }

        var statementHandle: OpaquePointer?
        defer { sqlite3_finalize(statementHandle) }

        guard sqlite3_prepare_v2(databaseHandle, "SELECT value FROM metadata WHERE key = ?", -1, &statementHandle, nil) == SQLITE_OK else {
            return nil
        }
        sqlite3_bind_text(statementHandle, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        guard sqlite3_step(statementHandle) == SQLITE_ROW,
              let columnTextPointer = sqlite3_column_text(statementHandle, 0) else { return nil }
        return String(cString: columnTextPointer)
    }

    func loadStringArray(_ key: String) -> [String] {
        guard let json = loadMetadata(key),
              let data = json.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [String] else {
            return []
        }
        return array
    }

    func loadStringDictionary(_ key: String) -> [String: String] {
        guard let json = loadMetadata(key),
              let data = json.data(using: .utf8),
              let dictionary = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
            return [:]
        }
        return dictionary
    }
}
