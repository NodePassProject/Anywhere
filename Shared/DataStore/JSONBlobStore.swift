//
//  JSONBlobStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/6/26.
//

import Foundation
import SwiftData
import Synchronization
import CryptoKit

nonisolated private let logger = AnywhereLogger(category: "JSONBlobStore")

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

nonisolated final class JSONBlobStore: Sendable {
    static let shared = JSONBlobStore()

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
    
    private struct Known {
        var ownData: Data?
        var foreignFingerprint: [String]?
    }

    private let lastKnown = Mutex<[Key: Known]>([:])
    
    private static func fingerprint(of rows: [JSONBlob], excludingDevice deviceID: String) -> [String] {
        rows.filter { $0.deviceID != deviceID }
            .map { "\($0.deviceID)#\($0.updatedAt.timeIntervalSinceReferenceDate)" }
            .sorted()
    }

    typealias MergeResolver = @Sendable (Key, [(data: Data, updatedAt: Date)]) -> Data
    typealias DecodeProbe = @Sendable (Key, Data) -> Bool

    private static let mergeResolver = Mutex<MergeResolver?>(nil)
    private static let decodeProbe = Mutex<DecodeProbe?>(nil)

    static func installMergeResolver(_ resolver: MergeResolver?, canFullyDecode probe: DecodeProbe?) {
        mergeResolver.withLock { $0 = resolver }
        decodeProbe.withLock { $0 = probe }
    }

    private init(container: ModelContainer?, usesCloudKit: Bool) {
        self.usesCloudKit = usesCloudKit
        store = Mutex(container)
    }

    private convenience init() {
        let wantsCloudKit = AWCore.isHostApp && AWCore.getICloudSyncEnabled()
        if wantsCloudKit, let cloudContainer = Self.makeContainer(cloudKit: true) {
            self.init(container: cloudContainer, usesCloudKit: true)
        } else {
            self.init(container: Self.makeContainer(cloudKit: false), usesCloudKit: false)
        }
    }
    
    static func ephemeral() -> JSONBlobStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("JSONBlobStore-\(UUID().uuidString).store")
        let config = ModelConfiguration(url: url, cloudKitDatabase: .none)
        let container = try? ModelContainer(for: JSONBlob.self, configurations: config)
        return JSONBlobStore(container: container, usesCloudKit: false)
    }

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
            return try ModelContainer(for: JSONBlob.self, configurations: config)
        } catch {
            logger.report("Failed to open JSONBlob store (cloudKit: \(cloudKit))", error: error)
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
            logger.report("Failed to migrate JSONBlob store", error: error)
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
        logger.info("Migrated JSONBlob store out of the app group container")
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

    // MARK: - Public API
    
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
            logger.error("Quarantined undecodable \(key.rawValue) blob (\(data.count) bytes) to \(file.lastPathComponent)")
        } catch {
            logger.report("Failed to quarantine undecodable \(key.rawValue) blob", error: error)
        }
    }

    func load(_ key: Key) -> Data? {
        store.withLock { container in
            guard let container else { return nil }
            let context = ModelContext(container)
            let raw = key.rawValue
            let predicate = #Predicate<JSONBlob> { $0.key == raw }
            let rows = (try? context.fetch(FetchDescriptor<JSONBlob>(predicate: predicate))) ?? []
            let result: Data?
            if rows.count > 1, let resolver = Self.mergeResolver.withLock({ $0 }) {
                result = resolver(key, rows.map { (data: $0.data, updatedAt: $0.updatedAt) })
            } else {
                result = rows.max { $0.updatedAt < $1.updatedAt }?.data
            }
            let own = rows.filter { $0.deviceID == deviceID }.max { $0.updatedAt < $1.updatedAt }
            lastKnown.withLock {
                $0[key] = Known(
                    ownData: own?.data,
                    foreignFingerprint: Self.fingerprint(of: rows, excludingDevice: deviceID)
                )
            }
            return result
        }
    }
    
    func reconcile() {
        guard let resolver = Self.mergeResolver.withLock({ $0 }),
              let probe = Self.decodeProbe.withLock({ $0 }) else { return }
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            var didChange = false
            for key in Key.allCases {
                let raw = key.rawValue
                let predicate = #Predicate<JSONBlob> { $0.key == raw }
                let rows = (try? context.fetch(FetchDescriptor<JSONBlob>(predicate: predicate))) ?? []
                let own = rows.filter { $0.deviceID == deviceID }.max { $0.updatedAt < $1.updatedAt }
                let cutoff = Date.now.addingTimeInterval(-Tombstone.lifetime)
                let doomed = rows.filter { row in
                    row !== own
                        && (row.deviceID.isEmpty || row.deviceID == deviceID || row.updatedAt < cutoff)
                        && probe(key, row.data)
                }
                guard !doomed.isEmpty else { continue }

                let merged = resolver(key, rows.map { (data: $0.data, updatedAt: $0.updatedAt) })
                if let own {
                    own.data = merged
                    own.updatedAt = .now
                } else {
                    context.insert(JSONBlob(key: raw, data: merged, deviceID: deviceID))
                }
                for row in doomed { context.delete(row) }
                lastKnown.withLock { $0[key] = Known(ownData: merged, foreignFingerprint: nil) }
                didChange = true
            }
            guard didChange else { return }
            do {
                try context.save()
            } catch {
                logger.report("Failed to reconcile JSON blob rows", error: error)
            }
        }
    }

    func save(_ key: Key, data: Data) {
        store.withLock { container in
            guard let container else { return }
            let context = ModelContext(container)
            let raw = key.rawValue
            let predicate = #Predicate<JSONBlob> { $0.key == raw }
            let descriptor = FetchDescriptor<JSONBlob>(
                predicate: predicate,
                sortBy: [SortDescriptor(\.updatedAt, order: .reverse)]
            )
            do {
                let rows = try context.fetch(descriptor)
                let own = rows.first { $0.deviceID == deviceID }
                let known = lastKnown.withLock { $0[key] }
                let fingerprint = Self.fingerprint(of: rows, excludingDevice: deviceID)
                
                let stamp = max(Date.now, (rows.first?.updatedAt ?? .distantPast).addingTimeInterval(0.001))
                
                let payload: Data
                if let known, known.foreignFingerprint == fingerprint, own?.data == known.ownData {
                    payload = data
                } else if let resolver = Self.mergeResolver.withLock({ $0 }), !rows.isEmpty {
                    var pairs = rows.map { (data: $0.data, updatedAt: $0.updatedAt) }
                    pairs.append((data: data, updatedAt: stamp))
                    payload = resolver(key, pairs)
                } else {
                    payload = data
                }

                if let own {
                    own.data = payload
                    own.updatedAt = stamp
                } else {
                    context.insert(JSONBlob(key: raw, data: payload, updatedAt: stamp, deviceID: deviceID))
                }
                lastKnown.withLock { known in
                    known[key] = Known(ownData: payload, foreignFingerprint: known[key]?.foreignFingerprint)
                }
                try context.save()
            } catch {
                logger.report("Failed to save JSON blob \(raw)", error: error)
            }
        }
    }
}
