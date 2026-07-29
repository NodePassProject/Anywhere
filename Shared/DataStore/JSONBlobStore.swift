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
        case subscriptions
        case chains
        case customRuleSets
        case mitm
    }

    let usesCloudKit: Bool

    private let context: Mutex<ModelContext?>
    private let container: ModelContainer?
    
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
            logger.report("Failed to open JSONBlob store (cloudKit: \(cloudKit))", error: error)
            return nil
        }
    }

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
        context.withLock { context in
            guard let context else { return nil }
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
        context.withLock { context in
            guard let context else { return }
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
        context.withLock { context in
            guard let context else { return }
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
