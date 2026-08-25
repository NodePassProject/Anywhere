//
//  SyncStore.swift
//  Anywhere
//
//  Created by NodePassProject on 8/13/26.
//

import Foundation
import Synchronization
import CryptoKit
import SwiftData

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
    var systemFields: Data?

    init(collection: String, itemID: String, payload: Data, updatedAt: Date, deletedAt: Date? = nil, systemFields: Data? = nil) {
        self.collection = collection
        self.itemID = itemID
        self.payload = payload
        self.updatedAt = updatedAt
        self.deletedAt = deletedAt
        self.systemFields = systemFields
    }
}

nonisolated struct SyncPayloadItem: Sendable, Equatable {
    let id: String
    let payload: Data
    let updatedAt: Date
    let deletedAt: Date?
}

nonisolated struct SyncItemRef: Hashable, Sendable {
    let key: SyncStore.Key
    let itemID: String
}

nonisolated enum SyncChange: Sendable {
    case save(SyncItemRef)
    case delete(SyncItemRef)
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

    struct ItemSnapshot: Sendable {
        let payload: Data
        let updatedAt: Date
        let deletedAt: Date?
        let systemFields: Data?
    }

    struct RemoteItem: Sendable {
        let ref: SyncItemRef
        let payload: Data
        let updatedAt: Date
        let deletedAt: Date?
        let systemFields: Data
    }
    
    static let maxSyncedPayloadBytes = 900_000

    private let store: Mutex<ModelContainer?>

    private static let orderItemID = "#order"

    private let persistsImportState: Bool
    private let importFingerprints = Mutex<[Key: [String]]>([:])
    private let changeObserver = Mutex<(@Sendable ([SyncChange]) -> Void)?>(nil)

    private init(container: ModelContainer?, persistsImportState: Bool) {
        self.persistsImportState = persistsImportState
        store = Mutex(container)
    }

    private convenience init() {
        self.init(container: Self.makeContainer(), persistsImportState: true)
    }

    static func ephemeral() -> SyncStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("SyncStore-\(UUID().uuidString).store")
        let config = ModelConfiguration(url: url, cloudKitDatabase: .none)
        let container = try? ModelContainer(for: Self.schema, configurations: config)
        return SyncStore(container: container, persistsImportState: false)
    }

    private static let schema = Schema([JSONBlob.self, SyncItem.self])

    private static func makeContainer() -> ModelContainer? {
        let config: ModelConfiguration
        #if os(tvOS)
        config = ModelConfiguration(
            groupContainer: .identifier(AWCore.Identifier.appGroupSuite),
            cloudKitDatabase: .none
        )
        #else
        if let url = relocatedStoreURL() {
            config = ModelConfiguration(url: url, cloudKitDatabase: .none)
        } else {
            config = ModelConfiguration(
                groupContainer: .identifier(AWCore.Identifier.appGroupSuite),
                cloudKitDatabase: .none
            )
        }
        #endif
        do {
            return try ModelContainer(for: schema, configurations: config)
        } catch {
            logger.report("Failed to open sync store", error: error)
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

    // MARK: - Change observation

    func setChangeObserver(_ observer: (@Sendable ([SyncChange]) -> Void)?) {
        changeObserver.withLock { $0 = observer }
    }

    private func notify(_ changes: [SyncChange]) {
        guard !changes.isEmpty else { return }
        changeObserver.withLock { $0 }?(changes)
    }

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
        for item in items where item.payload.count > Self.maxSyncedPayloadBytes {
            logger.warning("\(key.rawValue) item \(item.id) is \(item.payload.count) bytes and exceeds the sync size limit; it will not sync to other devices")
        }
        let changes = store.withLock { container -> [SyncChange] in
            guard let container else { return [] }
            let context = ModelContext(container)
            let rows = Self.fetchItems(key, in: context)
            let changedIDs = Self.upsert(key, items: items, rows: rows, in: context)
            let orderChanged = Self.updateOrder(key, order, importedStamp: importedOrderStamp, rows: rows, in: context)
            guard !changedIDs.isEmpty || orderChanged else { return [] }
            do {
                try context.save()
            } catch {
                logger.report("Failed to save \(key.rawValue) items", error: error)
                return []
            }
            var changes = changedIDs.map { SyncChange.save(SyncItemRef(key: key, itemID: $0)) }
            if orderChanged { changes.append(.save(SyncItemRef(key: key, itemID: Self.orderItemID))) }
            return changes
        }
        notify(changes)
    }

    func reconcile() {
        let deletions = store.withLock { container -> [SyncChange] in
            guard let container else { return [] }
            let context = ModelContext(container)
            let cutoff = Date.now.addingTimeInterval(-Tombstone.lifetime)
            var deletions: [SyncChange] = []
            var changed = false
            for key in Key.allCases {
                let winners = Self.winners(of: Self.fetchItems(key, in: context)) { loser in
                    context.delete(loser)
                    changed = true
                }
                for row in winners.values where row.itemID != Self.orderItemID {
                    if let deletedAt = row.deletedAt, deletedAt < cutoff {
                        context.delete(row)
                        deletions.append(.delete(SyncItemRef(key: key, itemID: row.itemID)))
                        changed = true
                    }
                }
            }
            guard changed else { return [] }
            do {
                try context.save()
            } catch {
                logger.report("Failed to reconcile sync items", error: error)
                return []
            }
            return deletions
        }
        notify(deletions)
    }

    // MARK: - Cloud bridge

    func allItemRefs() -> [SyncItemRef] {
        store.withLock { container in
            guard let container else { return [] }
            let context = ModelContext(container)
            var descriptor = FetchDescriptor<SyncItem>()
            descriptor.propertiesToFetch = [\.collection, \.itemID]
            let rows = (try? context.fetch(descriptor)) ?? []
            var refs: Set<SyncItemRef> = []
            for row in rows {
                guard let key = Key(rawValue: row.collection) else { continue }
                refs.insert(SyncItemRef(key: key, itemID: row.itemID))
            }
            return Array(refs)
        }
    }
    
    func refsNeedingUpload() -> [SyncItemRef] {
        store.withLock { container in
            guard let container else { return [] }
            let context = ModelContext(container)
            var descriptor = FetchDescriptor<SyncItem>(predicate: #Predicate { $0.systemFields == nil })
            descriptor.propertiesToFetch = [\.collection, \.itemID]
            let rows = (try? context.fetch(descriptor)) ?? []
            var refs: Set<SyncItemRef> = []
            for row in rows {
                guard let key = Key(rawValue: row.collection) else { continue }
                refs.insert(SyncItemRef(key: key, itemID: row.itemID))
            }
            return Array(refs)
        }
    }

    func snapshots(for refs: [SyncItemRef]) -> [SyncItemRef: ItemSnapshot] {
        guard !refs.isEmpty else { return [:] }
        return store.withLock { container in
            guard let container else { return [:] }
            let context = ModelContext(container)
            var result: [SyncItemRef: ItemSnapshot] = [:]
            for key in Set(refs.map(\.key)) {
                let winners = Self.winners(of: Self.fetchItems(key, in: context))
                for ref in refs where ref.key == key {
                    guard let row = winners[ref.itemID] else { continue }
                    result[ref] = ItemSnapshot(
                        payload: row.payload,
                        updatedAt: row.updatedAt,
                        deletedAt: row.deletedAt,
                        systemFields: row.systemFields
                    )
                }
            }
            return result
        }
    }

    func storeSystemFields(_ updates: [(ref: SyncItemRef, data: Data?)]) {
        guard !updates.isEmpty else { return }
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            var changed = false
            for key in Set(updates.map(\.ref.key)) {
                let winners = Self.winners(of: Self.fetchItems(key, in: context))
                for update in updates where update.ref.key == key {
                    guard let row = winners[update.ref.itemID], row.systemFields != update.data else { continue }
                    row.systemFields = update.data
                    changed = true
                }
            }
            guard changed else { return }
            try? context.save()
        }
    }

    func clearAllSystemFields() {
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            var changed = false
            for key in Key.allCases {
                for row in Self.fetchItems(key, in: context) where row.systemFields != nil {
                    row.systemFields = nil
                    changed = true
                }
            }
            guard changed else { return }
            try? context.save()
        }
    }

    func applyRemote(saves: [RemoteItem], deletes: [SyncItemRef]) -> Set<Key> {
        var changedKeys: Set<Key> = []
        var reuploads: [SyncChange] = []
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            var dirty = false
            let saveGroups = Dictionary(grouping: saves, by: { $0.ref.key })
            let deleteGroups = Dictionary(grouping: deletes, by: { $0.key })
            for key in Set(saveGroups.keys).union(deleteGroups.keys) {
                var rows = Self.winners(of: Self.fetchItems(key, in: context)) { loser in
                    context.delete(loser)
                    dirty = true
                }
                for item in saveGroups[key] ?? [] {
                    guard let row = rows[item.ref.itemID] else {
                        let inserted = SyncItem(
                            collection: key.rawValue,
                            itemID: item.ref.itemID,
                            payload: item.payload,
                            updatedAt: item.updatedAt,
                            deletedAt: item.deletedAt,
                            systemFields: item.systemFields
                        )
                        context.insert(inserted)
                        rows[item.ref.itemID] = inserted
                        changedKeys.insert(key)
                        dirty = true
                        continue
                    }
                    if Self.prevails(
                        stamp: item.updatedAt, deleted: item.deletedAt != nil, payload: item.payload,
                        overStamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload
                    ) {
                        row.payload = item.payload
                        row.updatedAt = item.updatedAt
                        row.deletedAt = item.deletedAt
                        row.systemFields = item.systemFields
                        changedKeys.insert(key)
                        dirty = true
                    } else {
                        if row.systemFields != item.systemFields {
                            row.systemFields = item.systemFields
                            dirty = true
                        }
                        if Self.prevails(
                            stamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload,
                            overStamp: item.updatedAt, deleted: item.deletedAt != nil, payload: item.payload
                        ) {
                            reuploads.append(.save(item.ref))
                        }
                    }
                }
                for ref in deleteGroups[key] ?? [] {
                    guard let row = rows[ref.itemID] else { continue }
                    if row.deletedAt != nil {
                        context.delete(row)
                        dirty = true
                    } else {
                        row.systemFields = nil
                        dirty = true
                        reuploads.append(.save(ref))
                    }
                }
            }
            guard dirty else { return }
            do {
                try context.save()
            } catch {
                logger.report("Failed to apply remote sync changes", error: error)
                changedKeys = []
                reuploads = saves.map { .save($0.ref) }
            }
        }
        notify(reuploads)
        return changedKeys
    }

    // MARK: - Item internals

    private static func fetchItems(_ key: Key, in context: ModelContext) -> [SyncItem] {
        let raw = key.rawValue
        let predicate = #Predicate<SyncItem> { $0.collection == raw }
        return (try? context.fetch(FetchDescriptor<SyncItem>(predicate: predicate))) ?? []
    }
    
    private static func winners(of rows: [SyncItem], onLoser: ((SyncItem) -> Void)? = nil) -> [String: SyncItem] {
        var winners: [String: SyncItem] = [:]
        for row in rows {
            guard let incumbent = winners[row.itemID] else {
                winners[row.itemID] = row
                continue
            }
            let loser: SyncItem
            if prevails(
                stamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload,
                overStamp: incumbent.updatedAt, deleted: incumbent.deletedAt != nil, payload: incumbent.payload
            ) {
                winners[row.itemID] = row
                loser = incumbent
            } else {
                loser = row
            }
            onLoser?(loser)
        }
        return winners
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

    private static func upsert(_ key: Key, items: [SyncPayloadItem], rows: [SyncItem], in context: ModelContext) -> [String] {
        guard !items.isEmpty else { return [] }
        let incumbents = winners(of: rows.filter { $0.itemID != orderItemID })
        var changed: [String] = []
        for item in items where item.id != orderItemID {
            guard let row = incumbents[item.id] else {
                context.insert(
                    SyncItem(
                        collection: key.rawValue,
                        itemID: item.id,
                        payload: item.payload,
                        updatedAt: item.updatedAt,
                        deletedAt: item.deletedAt
                    )
                )
                changed.append(item.id)
                continue
            }
            if row.updatedAt == item.updatedAt, (row.deletedAt != nil) == (item.deletedAt != nil) { continue }
            guard prevails(
                stamp: item.updatedAt, deleted: item.deletedAt != nil, payload: item.payload,
                overStamp: row.updatedAt, deleted: row.deletedAt != nil, payload: row.payload
            ) else { continue }
            row.payload = item.payload
            row.updatedAt = item.updatedAt
            row.deletedAt = item.deletedAt
            changed.append(item.id)
        }
        return changed
    }

    private static func updateOrder(_ key: Key, _ order: [String], importedStamp: Date?, rows: [SyncItem], in context: ModelContext) -> Bool {
        let row = winners(of: rows.filter { $0.itemID == orderItemID })[orderItemID]
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
        context.insert(
            SyncItem(
                collection: key.rawValue,
                itemID: Self.orderItemID,
                payload: payload,
                updatedAt: importedStamp ?? .now
            )
        )
        return true
    }

    private static func orderedWinners(_ key: Key, in context: ModelContext) -> [SyncItem] {
        var itemRows = winners(of: fetchItems(key, in: context))
        let orderRow = itemRows.removeValue(forKey: orderItemID)
        let order = orderRow.flatMap { try? JSONDecoder().decode([String].self, from: $0.payload) } ?? []
        let position = Dictionary(order.enumerated().map { ($1, $0) }, uniquingKeysWith: { first, _ in first })
        return itemRows.values.sorted { a, b in
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
