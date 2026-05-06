//
//  JSONBlobStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import Foundation
import SwiftData

private let logger = AnywhereLogger(category: "JSONBlobStore")

/// Single SwiftData model storing opaque JSON blobs by key. Domain types
/// stay as plain `Codable` structs; SwiftData is only the byte-level
/// container so we keep the existing JSON wire format and decoders.
@Model
final class JSONBlob {
    @Attribute(.unique) var key: String
    var data: Data
    var updatedAt: Date

    init(key: String, data: Data, updatedAt: Date = .now) {
        self.key = key
        self.data = data
        self.updatedAt = updatedAt
    }
}

/// Process-wide singleton owning the SwiftData ``ModelContainer`` for the
/// JSON blob store, located in the App Group container so the host app
/// and the Network Extension share a single SQLite database.
///
/// All public operations are synchronous and serialised through an internal
/// queue. Each call creates a fresh ``ModelContext`` so cross-process reads
/// always observe the latest committed state via SQLite WAL.
///
/// The host app is the only writer. The Network Extension reads MITM data
/// on demand and never mutates the store.
final class JSONBlobStore: @unchecked Sendable {
    static let shared = JSONBlobStore()

    enum Key: String, CaseIterable {
        case configurations
        case subscriptions
        case chains
        case customRuleSets
        case mitm
    }

    private let container: ModelContainer
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.jsonblobstore")

    private init() {
        let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AWCore.Identifier.appGroupSuite)!
        let config = ModelConfiguration(groupContainer: .identifier("group.com.argsment.Anywhere"))
        do {
            container = try ModelContainer(for: JSONBlob.self, configurations: config)
        } catch {
            logger.error("Failed to open JSONBlob store: \(error)")
            fatalError("Failed to open JSONBlob store: \(error)")
        }
        // Migration is host-only. The Network Extension is a read-only
        // consumer and must not delete legacy data the host hasn't migrated.
        if Bundle.main.bundleIdentifier == AWCore.Identifier.bundle {
            migrateLegacyDataIfNeeded(containerURL: containerURL)
        }
    }

    // MARK: - Public API

    func load(_ key: Key) -> Data? {
        queue.sync {
            let context = ModelContext(container)
            let raw = key.rawValue
            let predicate = #Predicate<JSONBlob> { $0.key == raw }
            var descriptor = FetchDescriptor<JSONBlob>(predicate: predicate)
            descriptor.fetchLimit = 1
            return (try? context.fetch(descriptor))?.first?.data
        }
    }

    func save(_ key: Key, data: Data) {
        queue.sync {
            let context = ModelContext(container)
            let raw = key.rawValue
            let predicate = #Predicate<JSONBlob> { $0.key == raw }
            var descriptor = FetchDescriptor<JSONBlob>(predicate: predicate)
            descriptor.fetchLimit = 1
            do {
                if let existing = try context.fetch(descriptor).first {
                    existing.data = data
                    existing.updatedAt = .now
                } else {
                    context.insert(JSONBlob(key: raw, data: data))
                }
                try context.save()
            } catch {
                logger.error("Failed to save JSON blob \(raw): \(error)")
            }
        }
    }

    // MARK: - Migration

    /// Idempotent migration from the pre-SwiftData blobs:
    /// - `configurations.json`, `subscriptions.json`, `chains.json` files in
    ///   the App Group container (and from the per-app documents directory
    ///   for very old installs, via ``AWCore/migrateToAppGroup(fileName:)``)
    /// - `customRuleSets`, `mitmData` UserDefaults entries in the App Group
    ///   suite
    ///
    /// For each blob, the legacy source is read first, written to SwiftData,
    /// and verified by re-reading; only then is the source removed. If any
    /// step fails the legacy source is left in place so the next launch can
    /// retry. If SwiftData already has the blob, the legacy source is just
    /// cleaned up.
    private func migrateLegacyDataIfNeeded(containerURL: URL) {
        // Pull JSON files in from the per-app documents directory if they
        // were left there by very old builds.
        AWCore.migrateToAppGroup(fileName: "configurations.json")
        AWCore.migrateToAppGroup(fileName: "subscriptions.json")
        AWCore.migrateToAppGroup(fileName: "chains.json")

        let legacyFiles: [(Key, URL)] = [
            (.configurations, containerURL.appendingPathComponent("configurations.json")),
            (.subscriptions, containerURL.appendingPathComponent("subscriptions.json")),
            (.chains, containerURL.appendingPathComponent("chains.json")),
        ]
        for (key, url) in legacyFiles {
            migrateFileIfNeeded(key: key, url: url)
        }

        let userDefaults = UserDefaults(suiteName: AWCore.Identifier.appGroupSuite)!
        let legacyDefaults: [(Key, String)] = [
            (.customRuleSets, "customRuleSets"),
            (.mitm, "mitmData"),
        ]
        for (key, defaultsKey) in legacyDefaults {
            migrateUserDefaultsIfNeeded(key: key, userDefaults: userDefaults, defaultsKey: defaultsKey)
        }
    }

    private func migrateFileIfNeeded(key: Key, url: URL) {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: url.path) else { return }
        if load(key) != nil {
            try? fileManager.removeItem(at: url)
            return
        }
        guard let data = try? Data(contentsOf: url) else { return }
        save(key, data: data)
        guard load(key) != nil else { return }
        try? fileManager.removeItem(at: url)
    }

    private func migrateUserDefaultsIfNeeded(key: Key, userDefaults: UserDefaults, defaultsKey: String) {
        guard let data = userDefaults.data(forKey: defaultsKey) else { return }
        if load(key) != nil {
            userDefaults.removeObject(forKey: defaultsKey)
            return
        }
        save(key, data: data)
        guard load(key) != nil else { return }
        userDefaults.removeObject(forKey: defaultsKey)
    }
}
