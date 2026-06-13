//
//  JSONBlobStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/6/26.
//

import Foundation
import SwiftData

private let logger = AnywhereLogger(category: "JSONBlobStore")

@Model
final class JSONBlob {
    var key: String = ""
    @Attribute(.externalStorage) var data: Data = Data()
    var updatedAt: Date = Date()

    init(key: String, data: Data, updatedAt: Date = .now) {
        self.key = key
        self.data = data
        self.updatedAt = updatedAt
    }
}

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
    let usesCloudKit: Bool

    static var mergeResolver: ((Key, [(data: Data, updatedAt: Date)]) -> Data)?

    private init() {
        let wantsCloudKit = AWCore.isHostApp && AWCore.getICloudSyncEnabled()
        if wantsCloudKit, let cloudContainer = Self.makeContainer(cloudKit: true) {
            container = cloudContainer
            usesCloudKit = true
        } else {
            container = Self.makeContainer(cloudKit: false)
            usesCloudKit = false
        }
    }

    private static func makeContainer(cloudKit: Bool) -> ModelContainer? {
        let database: ModelConfiguration.CloudKitDatabase =
            cloudKit ? .private(AWCore.Identifier.iCloudContainer) : .none
        let config = ModelConfiguration(
            groupContainer: .identifier(AWCore.Identifier.appGroupSuite),
            cloudKitDatabase: database
        )
        do {
            return try ModelContainer(for: JSONBlob.self, configurations: config)
        } catch {
            logger.error("Failed to open JSONBlob store (cloudKit: \(cloudKit)): \(error)")
            return nil
        }
    }

    // MARK: - Public API

    func load(_ key: Key) -> Data? {
        guard let container else { return nil }
        let context = ModelContext(container)
        let raw = key.rawValue
        let predicate = #Predicate<JSONBlob> { $0.key == raw }
        let rows = (try? context.fetch(FetchDescriptor<JSONBlob>(predicate: predicate))) ?? []
        guard rows.count > 1 else { return rows.first?.data }

        let pairs = rows.map { (data: $0.data, updatedAt: $0.updatedAt) }
        guard let resolver = Self.mergeResolver else {
            return pairs.max { $0.updatedAt < $1.updatedAt }?.data
        }

        let merged = resolver(key, pairs)
        // CloudKit can't enforce key uniqueness, so devices accumulate duplicate rows per key.
        // We just merged all of them losslessly, so collapse them back into one row; the deletion
        // propagates through CloudKit and keeps every device converging on a single row.
        compact(rows, into: merged, context: context)
        return merged
    }

    /// Collapses the duplicate `rows` for a key into their newest row carrying `merged`, deleting
    /// the rest. Host-only: the cloud-backed store is the single writer that owns this cleanup.
    private func compact(_ rows: [JSONBlob], into merged: Data, context: ModelContext) {
        guard usesCloudKit, rows.count > 1 else { return }
        let ordered = rows.sorted { $0.updatedAt > $1.updatedAt }
        guard let survivor = ordered.first else { return }
        if survivor.data != merged { survivor.data = merged }
        for loser in ordered.dropFirst() {
            context.delete(loser)
        }
        do {
            try context.save()
        } catch {
            logger.error("Failed to compact duplicate JSON blobs: \(error)")
        }
    }

    func save(_ key: Key, data: Data) {
        guard let container else { return }
        let context = ModelContext(container)
        let raw = key.rawValue
        let predicate = #Predicate<JSONBlob> { $0.key == raw }
        let descriptor = FetchDescriptor<JSONBlob>(
            predicate: predicate,
            sortBy: [SortDescriptor(\.updatedAt, order: .reverse)]
        )
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
