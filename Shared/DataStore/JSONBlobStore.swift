//
//  JSONBlobStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/6/26.
//

import Foundation
import SwiftData

private let logger = AnywhereLogger(category: "JSONBlobStore")

/// Opaque JSON blob keyed by name; SwiftData is only the byte-level container,
/// preserving the existing JSON wire format and decoders.
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

/// Blob store in the App Group container, shared by the host app (sole writer) and the
/// Network Extension (read-only). Calls are serialised through an internal queue, and each
/// uses a fresh `ModelContext` so cross-process reads observe the latest committed state.
final class JSONBlobStore: @unchecked Sendable {
    static let shared = JSONBlobStore()

    enum Key: String, CaseIterable {
        case configurations
        case subscriptions
        case chains
        case customRuleSets
        case mitm
    }

    private let container: ModelContainer?
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.jsonblobstore")

    private init() {
        let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AWCore.Identifier.appGroupSuite)!
        let config = ModelConfiguration(groupContainer: .identifier("group.com.argsment.Anywhere"))
        do {
            container = try ModelContainer(for: JSONBlob.self, configurations: config)
        } catch {
            logger.error("Failed to open JSONBlob store: \(error)")
            container = nil
        }
        // Migration is host-only — the NE must not delete legacy data the host hasn't migrated.
        if container != nil, Bundle.main.bundleIdentifier == AWCore.Identifier.bundle {
            migrateLegacyDataIfNeeded(containerURL: containerURL)
        }
    }

    // MARK: - Public API

    func load(_ key: Key) -> Data? {
        queue.sync {
            guard let container else { return nil }
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
            guard let container else { return }
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

    /// Idempotent migration from pre-SwiftData JSON files and UserDefaults blobs. Each source
    /// is written to SwiftData and verified by re-read before removal, so a failure leaves the
    /// legacy source in place for retry on the next launch.
    private func migrateLegacyDataIfNeeded(containerURL: URL) {
        // Very old builds left JSON files in the per-app documents directory.
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
