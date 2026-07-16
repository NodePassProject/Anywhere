//
//  JSONBlobStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/6/26.
//

import Foundation
import SwiftData
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "JSONBlobStore")

@Model
nonisolated final class JSONBlob {
    var key: String = ""
    @Attribute(.externalStorage) var data: Data = Data()
    var updatedAt: Date = Date()

    init(key: String, data: Data, updatedAt: Date = .now) {
        self.key = key
        self.data = data
        self.updatedAt = updatedAt
    }
}

nonisolated final class JSONBlobStore: Sendable {
    static let shared = JSONBlobStore()

    enum Key: String, CaseIterable {
        case configurations
        case subscriptions
        case chains
        case customRuleSets
        case mitm
    }

    let usesCloudKit: Bool
    
    private let context: Mutex<ModelContext?>
    private let container: ModelContainer?

    typealias MergeResolver = @Sendable (Key, [(data: Data, updatedAt: Date)]) -> Data
    
    private static let mergeResolverBox = Mutex<MergeResolver?>(nil)
    static var mergeResolver: MergeResolver? {
        get { mergeResolverBox.withLock { $0 } }
        set { mergeResolverBox.withLock { $0 = newValue } }
    }

    private init() {
        let wantsCloudKit = AWCore.isHostApp && AWCore.getICloudSyncEnabled()
        if wantsCloudKit, let cloudContainer = Self.makeContainer(cloudKit: true) {
            container = cloudContainer
            usesCloudKit = true
        } else {
            container = Self.makeContainer(cloudKit: false)
            usesCloudKit = false
        }
        context = Mutex(container.map { ModelContext($0) })
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
        context.withLock { context in
            guard let context else { return nil }
            let raw = key.rawValue
            let predicate = #Predicate<JSONBlob> { $0.key == raw }
            let rows = (try? context.fetch(FetchDescriptor<JSONBlob>(predicate: predicate))) ?? []
            guard rows.count > 1 else { return rows.first?.data }

            let pairs = rows.map { (data: $0.data, updatedAt: $0.updatedAt) }
            guard let resolver = Self.mergeResolver else {
                return pairs.max { $0.updatedAt < $1.updatedAt }?.data
            }
            return resolver(key, pairs)
        }
    }
    
    func compactDuplicates() {
        guard usesCloudKit, let resolver = Self.mergeResolver else { return }
        context.withLock { context in
            guard let context else { return }
            var didChange = false
            for key in Key.allCases {
                let raw = key.rawValue
                let predicate = #Predicate<JSONBlob> { $0.key == raw }
                let rows = (try? context.fetch(FetchDescriptor<JSONBlob>(predicate: predicate))) ?? []
                guard rows.count > 1 else { continue }

                let pairs = rows.map { (data: $0.data, updatedAt: $0.updatedAt) }
                let merged = resolver(key, pairs)
                let ordered = rows.sorted { $0.updatedAt > $1.updatedAt }
                guard let survivor = ordered.first else { continue }
                if survivor.data != merged { survivor.data = merged }
                for loser in ordered.dropFirst() { context.delete(loser) }
                didChange = true
            }
            guard didChange else { return }
            do {
                try context.save()
            } catch {
                logger.error("Failed to compact duplicate JSON blobs: \(error)")
            }
        }
    }

    func save(_ key: Key, data: Data) {
        context.withLock { context in
            guard let context else { return }
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
}
