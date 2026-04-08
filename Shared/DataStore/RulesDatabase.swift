//
//  RulesDatabase.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/5/26.
//

import Foundation
import SQLite3

private let logger = AnywhereLogger(category: "RulesDatabase")

/// Read-only SQLite database for bundled routing rules (replaces JSON resource files).
///
/// Tables:
/// - `rules(source, type, value)` — domain/IP rules keyed by source name
/// - `metadata(key, value)` — JSON-encoded lists and mappings
final class RulesDatabase {
    static let shared = RulesDatabase()

    private var db: OpaquePointer?

    private init() {
        guard let url = Bundle.main.url(forResource: "Rules", withExtension: "db") else {
            logger.error("[RulesDatabase] Rules.db not found in bundle")
            return
        }
        if sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) != SQLITE_OK {
            logger.error("[RulesDatabase] Failed to open Rules.db")
            db = nil
        }
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    // MARK: - Queries

    /// Returns all rules for a given source (e.g. "Direct", "ADBlock", "Telegram", "CN").
    func loadRules(for source: String) -> [DomainRule] {
        guard let db else { return [] }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_prepare_v2(db, "SELECT type, value FROM rules WHERE source = ?", -1, &stmt, nil) == SQLITE_OK else {
            return []
        }
        sqlite3_bind_text(stmt, 1, source, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        var rules: [DomainRule] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let type = Int(sqlite3_column_int(stmt, 0))
            guard let cValue = sqlite3_column_text(stmt, 1),
                  let ruleType = DomainRuleType(rawValue: type) else { continue }
            rules.append(DomainRule(type: ruleType, value: String(cString: cValue)))
        }
        return rules
    }

    /// Returns a metadata value (JSON string) for the given key.
    func loadMetadata(_ key: String) -> String? {
        guard let db else { return nil }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_prepare_v2(db, "SELECT value FROM metadata WHERE key = ?", -1, &stmt, nil) == SQLITE_OK else {
            return nil
        }
        sqlite3_bind_text(stmt, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        guard sqlite3_step(stmt) == SQLITE_ROW,
              let cValue = sqlite3_column_text(stmt, 0) else { return nil }
        return String(cString: cValue)
    }

    /// Convenience: decodes a metadata value as a JSON array of strings.
    func loadStringArray(_ key: String) -> [String] {
        guard let json = loadMetadata(key),
              let data = json.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [String] else {
            return []
        }
        return array
    }

    /// Convenience: decodes a metadata value as a JSON dictionary of string→string.
    func loadStringDictionary(_ key: String) -> [String: String] {
        guard let json = loadMetadata(key),
              let data = json.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
            return [:]
        }
        return dict
    }
}
