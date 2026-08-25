//
//  CloudSync.swift
//  Anywhere
//
//  Created by NodePassProject on 8/25/26.
//

import Foundation
import CloudKit

nonisolated private let logger = AnywhereLogger(category: "CloudSync")

actor CloudSync {
    static let shared = CloudSync()

    private static let zoneName = "AnywhereSync"
    private static let recordType: CKRecord.RecordType = "SyncItem"
    private static let recordNameSeparator: Character = ":"

    private static var zoneID: CKRecordZone.ID {
        CKRecordZone.ID(zoneName: zoneName, ownerName: CKCurrentUserDefaultName)
    }

    private enum Field {
        static let payload = "payload"
        static let updatedAt = "updatedAt"
        static let deletedAt = "deletedAt"
    }

    private let store: SyncStore
    private var engine: CKSyncEngine?
    private var deferredChanges: [SyncChange] = []
    private var pendingReloadKeys: Set<SyncStore.Key> = []
    private var reloadTask: Task<Void, Never>?
    private var onRemoteChange: (@MainActor (Set<SyncStore.Key>) async -> Void)?

    private init(store: SyncStore = .shared) {
        self.store = store
    }

    // MARK: - Lifecycle

    func start(onRemoteChange: @escaping @MainActor (Set<SyncStore.Key>) async -> Void) {
        self.onRemoteChange = onRemoteChange
        store.setChangeObserver { changes in
            Task { await CloudSync.shared.noteLocalChanges(changes) }
        }
        syncEnabledDidChange()
        Task.detached(priority: .utility) { [store] in
            store.reconcile()
        }
    }
    
    func syncEnabledDidChange() {
        if AWCore.getICloudSyncEnabled() {
            guard engine == nil else { return }
            startEngine()
        } else {
            engine = nil
            deferredChanges = []
            Self.deleteStateFile()
        }
    }

    private func startEngine() {
        let state = Self.loadState()
        let configuration = CKSyncEngine.Configuration(
            database: CKContainer(identifier: AWCore.Identifier.iCloudContainer).privateCloudDatabase,
            stateSerialization: state,
            delegate: self
        )
        let engine = CKSyncEngine(configuration)
        self.engine = engine
        if state == nil {
            requeueAllItems()
            Task {
                do {
                    try await engine.fetchChanges()
                } catch {
                    logger.report("Initial sync fetch failed", error: error)
                }
            }
        } else {
            let refs = store.refsNeedingUpload()
            if !refs.isEmpty {
                engine.state.add(pendingRecordZoneChanges: refs.map { .saveRecord(Self.recordID(for: $0)) })
            }
        }
        if !deferredChanges.isEmpty {
            let changes = deferredChanges
            deferredChanges = []
            noteLocalChanges(changes)
        }
    }

    private func requeueAllItems() {
        guard let engine else { return }
        engine.state.add(pendingDatabaseChanges: [.saveZone(CKRecordZone(zoneID: Self.zoneID))])
        engine.state.add(pendingRecordZoneChanges: store.allItemRefs().map { .saveRecord(Self.recordID(for: $0)) })
    }

    private func noteLocalChanges(_ changes: [SyncChange]) {
        guard let engine else {
            if AWCore.getICloudSyncEnabled() { deferredChanges += changes }
            return
        }
        engine.state.add(pendingRecordZoneChanges: changes.map { change in
            switch change {
            case .save(let ref): .saveRecord(Self.recordID(for: ref))
            case .delete(let ref): .deleteRecord(Self.recordID(for: ref))
            }
        })
    }

    // MARK: - Event handling

    private func handleAccountChange(_ event: CKSyncEngine.Event.AccountChange) {
        switch event.changeType {
        case .signIn:
            logger.info("iCloud account signed in; uploading local data")
            store.clearAllSystemFields()
            requeueAllItems()
        case .switchAccounts:
            logger.info("iCloud account switched; merging local data into the active account")
            store.clearAllSystemFields()
            requeueAllItems()
        case .signOut:
            logger.info("iCloud account signed out")
            store.clearAllSystemFields()
        @unknown default:
            break
        }
    }

    private func handleFetchedDatabaseChanges(_ event: CKSyncEngine.Event.FetchedDatabaseChanges) {
        let deletions = event.deletions.filter { $0.zoneID == Self.zoneID }
        guard !deletions.isEmpty else { return }
        store.clearAllSystemFields()
        if deletions.contains(where: { $0.reason == .purged }) {
            logger.error("Sync zone was purged from iCloud; disabling iCloud Sync")
            AWCore.setICloudSyncEnabled(false)
            syncEnabledDidChange()
            return
        }
        logger.info("Sync zone was deleted remotely; re-uploading local data")
        requeueAllItems()
    }

    private func handleFetchedRecordZoneChanges(_ event: CKSyncEngine.Event.FetchedRecordZoneChanges) {
        var saves: [SyncStore.RemoteItem] = []
        var deletes: [SyncItemRef] = []
        for modification in event.modifications {
            guard let item = Self.remoteItem(from: modification.record) else {
                logger.error("Ignoring unreadable record \(modification.record.recordID.recordName)")
                continue
            }
            saves.append(item)
        }
        for deletion in event.deletions {
            guard let ref = Self.itemRef(for: deletion.recordID) else { continue }
            deletes.append(ref)
        }
        guard !saves.isEmpty || !deletes.isEmpty else { return }
        scheduleReload(store.applyRemote(saves: saves, deletes: deletes))
    }

    private func handleSentRecordZoneChanges(_ event: CKSyncEngine.Event.SentRecordZoneChanges, engine: CKSyncEngine) {
        var fieldUpdates: [(ref: SyncItemRef, data: Data?)] = []
        for record in event.savedRecords {
            guard let ref = Self.itemRef(for: record.recordID) else { continue }
            fieldUpdates.append((ref, Self.encodeSystemFields(of: record)))
        }
        var conflicts: [SyncStore.RemoteItem] = []
        for failure in event.failedRecordSaves {
            let recordID = failure.record.recordID
            guard let ref = Self.itemRef(for: recordID) else { continue }
            switch failure.error.code {
            case .serverRecordChanged:
                guard let server = failure.error.serverRecord else { continue }
                if let item = Self.remoteItem(from: server) {
                    conflicts.append(item)
                } else {
                    fieldUpdates.append((ref, Self.encodeSystemFields(of: server)))
                    engine.state.add(pendingRecordZoneChanges: [.saveRecord(recordID)])
                }
            case .zoneNotFound:
                engine.state.add(pendingDatabaseChanges: [.saveZone(CKRecordZone(zoneID: Self.zoneID))])
                fieldUpdates.append((ref, nil))
                engine.state.add(pendingRecordZoneChanges: [.saveRecord(recordID)])
            case .unknownItem:
                fieldUpdates.append((ref, nil))
                engine.state.add(pendingRecordZoneChanges: [.saveRecord(recordID)])
            case .quotaExceeded:
                logger.error("iCloud storage is full; will retry \(recordID.recordName)")
                engine.state.add(pendingRecordZoneChanges: [.saveRecord(recordID)])
            case .networkFailure, .networkUnavailable, .zoneBusy, .serviceUnavailable,
                 .notAuthenticated, .accountTemporarilyUnavailable, .serverResponseLost, .changeTokenExpired:
                break
            default:
                logger.error("Failed to save record \(recordID.recordName): \(failure.error.localizedDescription)")
            }
        }
        store.storeSystemFields(fieldUpdates)
        if !event.failedRecordDeletes.isEmpty {
            logger.error("Failed to delete \(event.failedRecordDeletes.count) records")
        }
        guard !conflicts.isEmpty else { return }
        scheduleReload(store.applyRemote(saves: conflicts, deletes: []))
    }

    // MARK: - Reload coalescing

    private func scheduleReload(_ keys: Set<SyncStore.Key>) {
        guard !keys.isEmpty else { return }
        pendingReloadKeys.formUnion(keys)
        guard reloadTask == nil else { return }
        reloadTask = Task {
            try? await Task.sleep(for: .seconds(1))
            await flushReload()
        }
    }

    private func flushReload() async {
        reloadTask = nil
        let keys = pendingReloadKeys
        pendingReloadKeys = []
        guard !keys.isEmpty else { return }
        await onRemoteChange?(keys)
    }

    // MARK: - Record mapping

    private static func recordID(for ref: SyncItemRef) -> CKRecord.ID {
        CKRecord.ID(recordName: "\(ref.key.rawValue)\(recordNameSeparator)\(ref.itemID)", zoneID: zoneID)
    }

    private static func itemRef(for recordID: CKRecord.ID) -> SyncItemRef? {
        let name = recordID.recordName
        guard let separator = name.firstIndex(of: recordNameSeparator),
              let key = SyncStore.Key(rawValue: String(name[..<separator])) else { return nil }
        let itemID = String(name[name.index(after: separator)...])
        guard !itemID.isEmpty else { return nil }
        return SyncItemRef(key: key, itemID: itemID)
    }

    private static func makeRecord(id recordID: CKRecord.ID, snapshot: SyncStore.ItemSnapshot) -> CKRecord {
        let record = decodeSystemFields(snapshot.systemFields) ?? CKRecord(recordType: recordType, recordID: recordID)
        record.encryptedValues[Field.payload] = snapshot.payload
        record.encryptedValues[Field.updatedAt] = snapshot.updatedAt
        record.encryptedValues[Field.deletedAt] = snapshot.deletedAt
        return record
    }

    private static func remoteItem(from record: CKRecord) -> SyncStore.RemoteItem? {
        guard let ref = itemRef(for: record.recordID),
              let payload = record.encryptedValues[Field.payload] as? Data,
              let updatedAt = record.encryptedValues[Field.updatedAt] as? Date else { return nil }
        return SyncStore.RemoteItem(
            ref: ref, payload: payload, updatedAt: updatedAt,
            deletedAt: record.encryptedValues[Field.deletedAt] as? Date,
            systemFields: encodeSystemFields(of: record)
        )
    }

    private static func encodeSystemFields(of record: CKRecord) -> Data {
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: coder)
        coder.finishEncoding()
        return coder.encodedData
    }

    private static func decodeSystemFields(_ data: Data?) -> CKRecord? {
        guard let data, let coder = try? NSKeyedUnarchiver(forReadingFrom: data) else { return nil }
        defer { coder.finishDecoding() }
        return CKRecord(coder: coder)
    }

    // MARK: - Engine state persistence

    private static var stateFileURL: URL? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AWCore.Identifier.appGroupSuite
        ) else { return nil }
        let directory = container.appendingPathComponent("Library/Application Support/CloudSync", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("engine-state.data")
    }

    private static func loadState() -> CKSyncEngine.State.Serialization? {
        guard let url = stateFileURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(CKSyncEngine.State.Serialization.self, from: data)
    }

    private static func saveState(_ state: CKSyncEngine.State.Serialization) {
        guard let url = stateFileURL else { return }
        do {
            try JSONEncoder().encode(state).write(to: url, options: .atomic)
        } catch {
            logger.report("Failed to persist sync engine state", error: error)
        }
    }

    private static func deleteStateFile() {
        guard let url = stateFileURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

// MARK: - CKSyncEngineDelegate

extension CloudSync: CKSyncEngineDelegate {
    func handleEvent(_ event: CKSyncEngine.Event, syncEngine: CKSyncEngine) async {
        guard syncEngine === engine else { return }
        switch event {
        case .stateUpdate(let update):
            Self.saveState(update.stateSerialization)
        case .accountChange(let change):
            handleAccountChange(change)
        case .fetchedDatabaseChanges(let changes):
            handleFetchedDatabaseChanges(changes)
        case .fetchedRecordZoneChanges(let changes):
            handleFetchedRecordZoneChanges(changes)
        case .sentRecordZoneChanges(let sent):
            handleSentRecordZoneChanges(sent, engine: syncEngine)
        case .sentDatabaseChanges,
             .willFetchChanges, .didFetchChanges,
             .willFetchRecordZoneChanges, .didFetchRecordZoneChanges,
             .willSendChanges, .didSendChanges:
            break
        @unknown default:
            break
        }
    }

    func nextRecordZoneChangeBatch(_ context: CKSyncEngine.SendChangesContext, syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard syncEngine === engine else { return nil }
        let scope = context.options.scope
        let pending = syncEngine.state.pendingRecordZoneChanges.filter { scope.contains($0) }
        guard !pending.isEmpty else { return nil }
        let saveRefs = pending.compactMap { change -> (CKRecord.ID, SyncItemRef)? in
            guard case .saveRecord(let recordID) = change, let ref = Self.itemRef(for: recordID) else { return nil }
            return (recordID, ref)
        }
        let refByRecordID = Dictionary(saveRefs, uniquingKeysWith: { first, _ in first })
        let snapshots = store.snapshots(for: saveRefs.map(\.1))
        return await CKSyncEngine.RecordZoneChangeBatch(pendingChanges: pending) { recordID in
            guard let ref = refByRecordID[recordID], let snapshot = snapshots[ref] else {
                syncEngine.state.remove(pendingRecordZoneChanges: [.saveRecord(recordID)])
                return nil
            }
            guard snapshot.payload.count <= SyncStore.maxSyncedPayloadBytes else {
                logger.error("Skipping oversized \(ref.key.rawValue) payload (\(snapshot.payload.count) bytes) for \(ref.itemID)")
                syncEngine.state.remove(pendingRecordZoneChanges: [.saveRecord(recordID)])
                return nil
            }
            return Self.makeRecord(id: recordID, snapshot: snapshot)
        }
    }
}
