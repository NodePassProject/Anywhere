//
//  SyncStore.swift
//  Anywhere
//
//  Created by NodePassProject on 8/13/26.
//

import Foundation
import SwiftData
import Synchronization
import CryptoKit

nonisolated private let logger = AnywhereLogger(category: "SyncStore")

@Model
nonisolated final class JSONBlob {
    var key: String = ""
    @Attribute(.externalStorage) var data: Data = Data()
    var updatedAt: Date = Date()
    var deviceID: String = ""

    init(key: String, data: Data, updatedAt: Date = .now, deviceID: String = "") {
        self.key = key
        self.data = data
        self.updatedAt = updatedAt
        self.deviceID = deviceID
    }
}

@Model
nonisolated final class SyncItem {
    var collection: String = ""
    var itemID: String = ""
    @Attribute(.externalStorage) var payload: Data = Data()
    var updatedAt: Date = Date()
    var deletedAt: Date?

    init(collection: String, itemID: String, payload: Data, updatedAt: Date, deletedAt: Date? = nil) {
        self.collection = collection
        self.itemID = itemID
        self.payload = payload
        self.updatedAt = updatedAt
        self.deletedAt = deletedAt
    }
}

nonisolated struct SyncPayloadItem: Sendable, Equatable {
    let id: String
    let payload: Data
    let updatedAt: Date
    let deletedAt: Date?
}

nonisolated final class SyncStore: Sendable {
    static let shared = SyncStore()

    enum Key: String, CaseIterable {
        case configurations
        case chains
        case groups
        case subscriptions
        case customRuleSets
        case mitm
    }

    let usesCloudKit: Bool

    private let store: Mutex<ModelContainer?>

    private let deviceID = AWCore.getSyncDeviceID()
    
    private static let orderItemID = "#order"

    private static let legacyExportDelay: Duration = .seconds(2)

    private let persistsImportState: Bool
    private let importFingerprints = Mutex<[Key: [String]]>([:])
    private let legacyExportTasks = Mutex<[Key: Task<Void, Never>]>([:])

    private init(container: ModelContainer?, usesCloudKit: Bool, persistsImportState: Bool) {
        self.usesCloudKit = usesCloudKit
        self.persistsImportState = persistsImportState
        store = Mutex(container)
    }

    private convenience init() {
        let wantsCloudKit = AWCore.isHostApp && AWCore.getICloudSyncEnabled()
        if wantsCloudKit, let cloudContainer = Self.makeContainer(cloudKit: true) {
            self.init(container: cloudContainer, usesCloudKit: true, persistsImportState: true)
        } else {
            self.init(container: Self.makeContainer(cloudKit: false), usesCloudKit: false, persistsImportState: true)
        }
    }

    static func ephemeral() -> SyncStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("SyncStore-\(UUID().uuidString).store")
        let config = ModelConfiguration(url: url, cloudKitDatabase: .none)
        let container = try? ModelContainer(for: Self.schema, configurations: config)
        return SyncStore(container: container, usesCloudKit: false, persistsImportState: false)
    }

    private static let schema = Schema([JSONBlob.self, SyncItem.self])

    private static func makeContainer(cloudKit: Bool) -> ModelContainer? {
        let database: ModelConfiguration.CloudKitDatabase =
            cloudKit ? .private(AWCore.Identifier.iCloudContainer) : .none
        let config: ModelConfiguration
        #if os(tvOS)
        config = ModelConfiguration(
            groupContainer: .identifier(AWCore.Identifier.appGroupSuite),
            cloudKitDatabase: database
        )
        #else
        if let url = relocatedStoreURL() {
            config = ModelConfiguration(url: url, cloudKitDatabase: database)
        } else {
            config = ModelConfiguration(
                groupContainer: .identifier(AWCore.Identifier.appGroupSuite),
                cloudKitDatabase: database
            )
        }
        #endif
        do {
            return try ModelContainer(for: schema, configurations: config)
        } catch {
            logger.report("Failed to open sync store (cloudKit: \(cloudKit))", error: error)
            return nil
        }
    }

    #if !os(tvOS)
    private static func relocatedStoreURL() -> URL? {
        let fileManager = FileManager.default
        let directory = URL.applicationSupportDirectory
        let storeURL = directory.appendingPathComponent("default.store")
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            try migrateLegacyStoreIfNeeded(to: storeURL, in: directory, fileManager: fileManager)
            return storeURL
        } catch {
            try? fileManager.removeItem(at: storeURL)
            logger.report("Failed to migrate sync store", error: error)
            return nil
        }
    }

    // MARK: - Legacy group-container store migration

    private static func migrateLegacyStoreIfNeeded(to storeURL: URL, in directory: URL, fileManager: FileManager) throws {
        guard !fileManager.fileExists(atPath: storeURL.path),
              let oldDirectory = legacyStoreDirectory(fileManager) else { return }
        let related = try fileManager.contentsOfDirectory(at: oldDirectory, includingPropertiesForKeys: nil)
            .filter { item in
                let name = item.lastPathComponent
                return name.hasPrefix("default.store") || name.hasPrefix("default_") || name == ".default_SUPPORT"
            }
            .sorted { ($0.lastPathComponent == "default.store" ? 1 : 0) < ($1.lastPathComponent == "default.store" ? 1 : 0) }
        for item in related {
            let destination = directory.appendingPathComponent(item.lastPathComponent)
            if fileManager.fileExists(atPath: destination.path) {
                try fileManager.removeItem(at: destination)
            }
            try fileManager.copyItem(at: item, to: destination)
        }
        logger.info("Migrated sync store out of the app group container")
    }

    private static func legacyStoreDirectory(_ fileManager: FileManager) -> URL? {
        guard let group = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: AWCore.Identifier.appGroupSuite
        ) else { return nil }
        return [
            group.appendingPathComponent("Library/Application Support", isDirectory: true),
            group,
        ].first { fileManager.fileExists(atPath: $0.appendingPathComponent("default.store").path) }
    }
    #endif

    // MARK: - Quarantine

    static func quarantine(_ key: Key, _ data: Data) {
        guard !data.isEmpty else { return }
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AWCore.Identifier.appGroupSuite
        ) else { return }
        let digest = SHA256.hash(data: data).prefix(8).map { String(format: "%02x", $0) }.joined()
        let directory = container.appendingPathComponent("SyncQuarantine", isDirectory: true)
        let file = directory.appendingPathComponent("\(key.rawValue)-\(digest).json")
        guard !FileManager.default.fileExists(atPath: file.path) else { return }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(to: file)
            logger.error("Quarantined undecodable \(key.rawValue) payload (\(data.count) bytes) to \(file.lastPathComponent)")
        } catch {
            logger.report("Failed to quarantine undecodable \(key.rawValue) payload", error: error)
        }
    }

    // MARK: - Items
    
    func loadItems(_ key: Key) -> [Data] {
        store.withLock { container in
            guard let container else { return [] }
            let context = ModelContext(container)
            return Self.orderedWinners(key, in: context).map(\.payload)
        }
    }

    func save(_ key: Key, items: [SyncPayloadItem], order: [String]) {
        apply(key, items: items, order: order, importedOrderStamp: nil)
    }
    
    func applyImported(_ key: Key, items: [SyncPayloadItem], order: [String], orderStamp: Date) {
        apply(key, items: items, order: order, importedOrderStamp: orderStamp)
    }

    private func apply(_ key: Key, items: [SyncPayloadItem], order: [String], importedOrderStamp: Date?) {
        let changed = store.withLock { container -> Bool in
            guard let container else { return false }
            let context = ModelContext(container)
            let rows = Self.fetchItems(key, in: context)
            var changed = Self.upsert(key, items: items, rows: rows, in: context)
            changed = Self.updateOrder(key, order, importedStamp: importedOrderStamp, rows: rows, in: context) || changed
            guard changed else { return false }
            do {
                try context.save()
            } catch {
                logger.report("Failed to save \(key.rawValue) items", error: error)
                return false
            }
            return true
        }
        if changed { scheduleLegacyExport(key) }
    }
    
    func reconcile() {
        let changedKeys = store.withLock { container -> [Key] in
            guard let container else { return [] }
            let context = ModelContext(container)
            let cutoff = Date.now.addingTimeInterval(-Tombstone.lifetime)
            var changedKeys: [Key] = []
            for key in Key.allCases {
                var changed = false
                var winners: [String: SyncItem] = [:]
                for row in Self.fetchItems(key, in: context) {
                    guard let incumbent = winners[row.itemID] else {
                        winners[row.itemID] = row
                        continue
                    }
                    let loser: SyncItem
                    if Self.prevails(stamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload,
                                     overStamp: incumbent.updatedAt, deleted: incumbent.deletedAt != nil, payload: incumbent.payload) {
                        winners[row.itemID] = row
                        loser = incumbent
                    } else {
                        loser = row
                    }
                    context.delete(loser)
                    changed = true
                }
                for row in winners.values where row.itemID != Self.orderItemID {
                    if let deletedAt = row.deletedAt, deletedAt < cutoff {
                        context.delete(row)
                        changed = true
                    }
                }
                if changed { changedKeys.append(key) }
            }
            guard !changedKeys.isEmpty else { return [] }
            do {
                try context.save()
            } catch {
                logger.report("Failed to reconcile sync items", error: error)
                return []
            }
            return changedKeys
        }
        for key in changedKeys { scheduleLegacyExport(key) }
    }

    // MARK: - Item internals

    private static func fetchItems(_ key: Key, in context: ModelContext) -> [SyncItem] {
        let raw = key.rawValue
        let predicate = #Predicate<SyncItem> { $0.collection == raw }
        return (try? context.fetch(FetchDescriptor<SyncItem>(predicate: predicate))) ?? []
    }
    
    private static func prevails(
        stamp: Date, deleted: Bool, payload: @autoclosure () -> Data,
        overStamp incumbentStamp: Date, deleted incumbentDeleted: Bool, payload incumbentPayload: @autoclosure () -> Data
    ) -> Bool {
        if stamp != incumbentStamp { return stamp > incumbentStamp }
        switch (deleted, incumbentDeleted) {
        case (true, false): return true
        case (false, true): return false
        default: break
        }
        let challenger = payload(), incumbent = incumbentPayload()
        guard challenger != incumbent else { return false }
        if challenger.count != incumbent.count {
            return incumbent.count < challenger.count
        }
        return incumbent.lexicographicallyPrecedes(challenger)
    }

    private static func upsert(_ key: Key, items: [SyncPayloadItem], rows: [SyncItem], in context: ModelContext) -> Bool {
        guard !items.isEmpty else { return false }
        var winners: [String: SyncItem] = [:]
        for row in rows where row.itemID != orderItemID {
            guard let incumbent = winners[row.itemID] else {
                winners[row.itemID] = row
                continue
            }
            if prevails(stamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload,
                        overStamp: incumbent.updatedAt, deleted: incumbent.deletedAt != nil, payload: incumbent.payload) {
                winners[row.itemID] = row
            }
        }
        var changed = false
        for item in items where item.id != orderItemID {
            guard let row = winners[item.id] else {
                context.insert(SyncItem(
                    collection: key.rawValue, itemID: item.id,
                    payload: item.payload, updatedAt: item.updatedAt, deletedAt: item.deletedAt
                ))
                changed = true
                continue
            }
            if row.updatedAt == item.updatedAt, (row.deletedAt != nil) == (item.deletedAt != nil) { continue }
            guard prevails(stamp: item.updatedAt, deleted: item.deletedAt != nil, payload: item.payload,
                           overStamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload) else { continue }
            row.payload = item.payload
            row.updatedAt = item.updatedAt
            row.deletedAt = item.deletedAt
            changed = true
        }
        return changed
    }

    private static func updateOrder(_ key: Key, _ order: [String], importedStamp: Date?, rows: [SyncItem], in context: ModelContext) -> Bool {
        var row: SyncItem?
        for candidate in rows where candidate.itemID == orderItemID {
            guard let incumbent = row else {
                row = candidate
                continue
            }
            if prevails(stamp: candidate.updatedAt, deleted: false, payload: candidate.payload,
                        overStamp: incumbent.updatedAt, deleted: false, payload: incumbent.payload) {
                row = candidate
            }
        }
        let payload = (try? JSONEncoder().encode(order)) ?? Data("[]".utf8)
        if let row {
            if let importedStamp {
                guard importedStamp > row.updatedAt else { return false }
                row.updatedAt = importedStamp
            } else {
                guard row.payload != payload else { return false }
                row.updatedAt = SyncStamp.after(row.updatedAt)
            }
            if row.payload != payload { row.payload = payload }
            return true
        }
        guard !order.isEmpty else { return false }
        context.insert(SyncItem(
            collection: key.rawValue, itemID: Self.orderItemID,
            payload: payload, updatedAt: importedStamp ?? .now
        ))
        return true
    }

    private static func orderedWinners(_ key: Key, in context: ModelContext) -> [SyncItem] {
        var orderRow: SyncItem?
        var winners: [String: SyncItem] = [:]
        for row in fetchItems(key, in: context) {
            if row.itemID == orderItemID {
                guard let incumbent = orderRow else {
                    orderRow = row
                    continue
                }
                if prevails(stamp: row.updatedAt, deleted: false, payload: row.payload,
                            overStamp: incumbent.updatedAt, deleted: false, payload: incumbent.payload) {
                    orderRow = row
                }
                continue
            }
            guard let incumbent = winners[row.itemID] else {
                winners[row.itemID] = row
                continue
            }
            if prevails(stamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload,
                        overStamp: incumbent.updatedAt, deleted: incumbent.deletedAt != nil, payload: incumbent.payload) {
                winners[row.itemID] = row
            }
        }
        let order = orderRow.flatMap { try? JSONDecoder().decode([String].self, from: $0.payload) } ?? []
        let position = Dictionary(order.enumerated().map { ($1, $0) }, uniquingKeysWith: { first, _ in first })
        return winners.values.sorted { a, b in
            switch (position[a.itemID], position[b.itemID]) {
            case let (first?, second?): return first < second
            case (.some, .none): return true
            case (.none, .some): return false
            case (.none, .none):
                if a.updatedAt != b.updatedAt { return a.updatedAt < b.updatedAt }
                return a.itemID < b.itemID
            }
        }
    }

    // MARK: - Legacy blobs

    struct LegacyBlobRow: Sendable {
        let data: Data
        let updatedAt: Date
        let deviceID: String
    }

    func legacyBlobRows(_ key: Key) -> [LegacyBlobRow] {
        store.withLock { container in
            guard let container else { return [] }
            let context = ModelContext(container)
            return Self.fetchBlobs(key, in: context)
                .map { LegacyBlobRow(data: $0.data, updatedAt: $0.updatedAt, deviceID: $0.deviceID) }
        }
    }
    
    func legacyBlobFingerprint(_ key: Key) -> [String] {
        store.withLock { container in
            guard let container else { return [] }
            let context = ModelContext(container)
            let raw = key.rawValue
            var descriptor = FetchDescriptor<JSONBlob>(predicate: #Predicate { $0.key == raw })
            descriptor.propertiesToFetch = [\.updatedAt, \.deviceID]
            let rows = (try? context.fetch(descriptor)) ?? []
            return rows.map { "\($0.deviceID)#\($0.updatedAt.timeIntervalSinceReferenceDate)" }.sorted()
        }
    }

    func legacyNewestBlobData(_ key: Key) -> Data? {
        store.withLock { container in
            guard let container else { return nil }
            let context = ModelContext(container)
            return Self.fetchBlobs(key, in: context).max { $0.updatedAt < $1.updatedAt }?.data
        }
    }

    static func legacyFingerprint(of rows: [LegacyBlobRow]) -> [String] {
        rows.map { "\($0.deviceID)#\($0.updatedAt.timeIntervalSinceReferenceDate)" }.sorted()
    }

    func lastImportFingerprint(_ key: Key) -> [String]? {
        if persistsImportState {
            return UserDefaults(suiteName: AWCore.Identifier.appGroupSuite)?
                .stringArray(forKey: Self.importFingerprintDefaultsKey(key))
        }
        return importFingerprints.withLock { $0[key] }
    }

    func setLastImportFingerprint(_ key: Key, _ fingerprint: [String]) {
        if persistsImportState {
            UserDefaults(suiteName: AWCore.Identifier.appGroupSuite)?
                .set(fingerprint, forKey: Self.importFingerprintDefaultsKey(key))
        } else {
            importFingerprints.withLock { $0[key] = fingerprint }
        }
    }

    private static func importFingerprintDefaultsKey(_ key: Key) -> String {
        "SyncStore.importedBlobFingerprint.\(key.rawValue)"
    }

    private static func fetchBlobs(_ key: Key, in context: ModelContext) -> [JSONBlob] {
        let raw = key.rawValue
        let predicate = #Predicate<JSONBlob> { $0.key == raw }
        return (try? context.fetch(FetchDescriptor<JSONBlob>(predicate: predicate))) ?? []
    }

    // MARK: - Legacy blob export

    private func scheduleLegacyExport(_ key: Key) {
        legacyExportTasks.withLock { tasks in
            tasks[key]?.cancel()
            tasks[key] = Task.detached(priority: .utility) { [weak self] in
                try? await Task.sleep(for: Self.legacyExportDelay)
                guard !Task.isCancelled else { return }
                self?.performLegacyExport(key)
            }
        }
    }
    
    func resumeLegacyExports() {
        for key in Key.allCases { scheduleLegacyExport(key) }
    }
    
    private func performLegacyExport(_ key: Key) {
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            let blobs = Self.fetchBlobs(key, in: context)
            guard !blobs.isEmpty else { return }
            let payloads = Self.orderedWinners(key, in: context).map(\.payload)
            let composed = Self.composeLegacyBlob(key, payloads)
            let own = blobs.filter { $0.deviceID == deviceID }.max { $0.updatedAt < $1.updatedAt }
            guard own?.data != composed else { return }
            let newest = blobs.map(\.updatedAt).max() ?? .distantPast
            let stamp = max(Date.now, newest.addingTimeInterval(0.001))
            if let own {
                own.data = composed
                own.updatedAt = stamp
            } else {
                context.insert(JSONBlob(key: key.rawValue, data: composed, updatedAt: stamp, deviceID: deviceID))
            }
            do {
                try context.save()
            } catch {
                logger.report("Failed to export legacy \(key.rawValue) blob", error: error)
                return
            }
            let ownEntry = "\(deviceID)#\(stamp.timeIntervalSinceReferenceDate)"
            let previous = lastImportFingerprint(key) ?? []
            let updated = (previous.filter { !$0.hasPrefix("\(deviceID)#") } + [ownEntry]).sorted()
            setLastImportFingerprint(key, updated)
        }
    }
    
    static func composeLegacyBlob(_ key: Key, _ payloads: [Data]) -> Data {
        var body = Data("[".utf8)
        for (index, payload) in payloads.enumerated() {
            if index > 0 { body.append(UInt8(ascii: ",")) }
            body.append(payload)
        }
        body.append(UInt8(ascii: "]"))
        guard key == .mitm else { return body }
        var wrapped = Data("{\"ruleSets\":".utf8)
        wrapped.append(body)
        wrapped.append(UInt8(ascii: "}"))
        return wrapped
    }
    
    func insertLegacyBlobRow(_ key: Key, data: Data, updatedAt: Date, deviceID: String) {
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            context.insert(JSONBlob(key: key.rawValue, data: data, updatedAt: updatedAt, deviceID: deviceID))
            try? context.save()
        }
    }
}

// MARK: - Payload codec

nonisolated enum SyncCodec {
    static func encodeItems<T: Codable & Identifiable & SoftDeletable>(_ items: [T]) -> [SyncPayloadItem] where T.ID == UUID {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return items.compactMap { item in
            do {
                let payload = try encoder.encode(item)
                return SyncPayloadItem(id: item.id.uuidString, payload: payload, updatedAt: item.syncStamp, deletedAt: item.deletedAt)
            } catch {
                logger.report("Failed to encode \(T.self) \(item.id)", error: error)
                return nil
            }
        }
    }

    static func decodeItems<T: Decodable>(_ type: T.Type, key: SyncStore.Key, payloads: [Data]) -> [T] {
        let decoder = JSONDecoder()
        return payloads.compactMap { payload in
            if let item = try? decoder.decode(T.self, from: payload) { return item }
            SyncStore.quarantine(key, payload)
            return nil
        }
    }

    static func order<T: Identifiable>(of live: [T]) -> [String] where T.ID == UUID {
        live.map { $0.id.uuidString }
    }
}
