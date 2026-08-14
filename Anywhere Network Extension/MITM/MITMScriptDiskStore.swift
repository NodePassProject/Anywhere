//
//  MITMScriptDiskStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/10/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMScriptDiskStore")

nonisolated final class MITMScriptDiskStore: Sendable {

    static let shared = MITMScriptDiskStore()

    static let maxBytesPerScope: Int = 1 * 1024 * 1024
    static let maxTotalBytes: Int = 16 * 1024 * 1024

    private struct State {
        var cache: [UUID: [String: Data]] = [:]
        var loaded: Set<UUID> = []
        var fileSizes: [UUID: Int] = [:]
        var commitGenerations: [UUID: UInt64] = [:]
        var generationCounter: UInt64 = 0
        var totalBytes: Int = 0
        var didScan = false

        mutating func bumpCommitGeneration(for scope: UUID) -> UInt64 {
            generationCounter += 1
            commitGenerations[scope] = generationCounter
            return generationCounter
        }
    }

    private let state = Mutex(State())

    private let directory: URL?

    init(appGroup: String = AWCore.Identifier.appGroupSuite) {
        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) {
            directory = container.appendingPathComponent("MITMScriptStore", isDirectory: true)
        } else {
            directory = nil
        }
    }

    // MARK: - API

    func get(scope: UUID, key: String) -> Data? {
        ensureLoaded(scope)
        return state.withLock { $0.cache[scope]?[key] }
    }

    func set(scope: UUID, key: String, value: Data) throws(AnywhereError) {
        ensureLoaded(scope)
        struct Reservation {
            let serialized: Data
            let committedBucket: [String: Data]
            let generation: UInt64
        }
        let reservation: Reservation = try state.withLock { (state) throws(AnywhereError) -> Reservation in
            var bucket = state.cache[scope] ?? [:]
            bucket[key] = value
            guard let serialized = serialize(bucket) else {
                throw AnywhereError.mitm(.scriptStoreWriteFailed)
            }
            if serialized.count > Self.maxBytesPerScope {
                throw AnywhereError.mitm(.scriptStoreCapacityExceeded)
            }
            let oldSize = state.fileSizes[scope] ?? 0
            if state.totalBytes - oldSize + serialized.count > Self.maxTotalBytes {
                throw AnywhereError.mitm(.scriptStoreCapacityExceeded)
            }
            return Reservation(serialized: serialized, committedBucket: bucket,
                               generation: state.bumpCommitGeneration(for: scope))
        }
        guard writeToDisk(scope: scope, data: reservation.serialized) else {
            throw AnywhereError.mitm(.scriptStoreWriteFailed)
        }
        state.withLock { state in
            guard state.commitGenerations[scope] == reservation.generation else { return }
            state.cache[scope] = reservation.committedBucket
            state.totalBytes = state.totalBytes - (state.fileSizes[scope] ?? 0) + reservation.serialized.count
            state.fileSizes[scope] = reservation.serialized.count
        }
    }

    func delete(scope: UUID, key: String) {
        ensureLoaded(scope)
        enum Pending {
            case nothing
            case removeFile(generation: UInt64)
            case write(Data, bucket: [String: Data], generation: UInt64)
        }
        let pending: Pending = state.withLock { state in
            guard var bucket = state.cache[scope], bucket[key] != nil else { return .nothing }
            bucket.removeValue(forKey: key)
            if bucket.isEmpty {
                return .removeFile(generation: state.bumpCommitGeneration(for: scope))
            }
            guard let serialized = serialize(bucket) else { return .nothing }
            return .write(serialized, bucket: bucket, generation: state.bumpCommitGeneration(for: scope))
        }
        switch pending {
        case .nothing:
            return
        case .removeFile(let generation):
            removeFile(scope)
            state.withLock { state in
                guard state.commitGenerations[scope] == generation else { return }
                state.cache[scope] = [:]
                state.totalBytes -= state.fileSizes[scope] ?? 0
                state.fileSizes.removeValue(forKey: scope)
            }
        case .write(let serialized, let bucket, let generation):
            guard writeToDisk(scope: scope, data: serialized) else { return }
            state.withLock { state in
                guard state.commitGenerations[scope] == generation else { return }
                state.cache[scope] = bucket
                let oldSize = state.fileSizes[scope] ?? 0
                state.totalBytes = state.totalBytes - oldSize + serialized.count
                state.fileSizes[scope] = serialized.count
            }
        }
    }

    func keys(scope: UUID) -> [String] {
        ensureLoaded(scope)
        return state.withLock { $0.cache[scope].map { Array($0.keys) } ?? [] }
    }

    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        ensureScanned()
        let stale: [UUID] = state.withLock { state in
            let stale = state.fileSizes.keys.filter { !activeIDs.contains($0) }
            for scope in stale {
                state.totalBytes -= state.fileSizes[scope] ?? 0
                state.fileSizes.removeValue(forKey: scope)
                state.cache.removeValue(forKey: scope)
                state.loaded.remove(scope)
            }
            state.commitGenerations = state.commitGenerations.filter { activeIDs.contains($0.key) }
            return stale
        }
        for scope in stale {
            removeFile(scope)
        }
        return stale.count
    }

    // MARK: - Private

    private func ensureScanned() {
        let needsScan = state.withLock { !$0.didScan }
        guard needsScan else { return }

        var sizes: [UUID: Int] = [:]
        if let directory,
           let entries = try? FileManager.default.contentsOfDirectory(
             at: directory,
             includingPropertiesForKeys: [.fileSizeKey],
             options: [.skipsHiddenFiles]
           ) {
            for url in entries where url.pathExtension == "plist" {
                guard let scope = UUID(uuidString: url.deletingPathExtension().lastPathComponent) else { continue }
                sizes[scope] = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
            }
        }

        state.withLock { state in
            guard !state.didScan else { return }
            state.didScan = true
            state.fileSizes.merge(sizes) { current, _ in current }
            state.totalBytes = state.fileSizes.values.reduce(0, +)
        }
    }

    private func ensureLoaded(_ scope: UUID) {
        ensureScanned()
        let needsLoad = state.withLock { !$0.loaded.contains(scope) }
        guard needsLoad else { return }

        var bucket: [String: Data] = [:]
        if let url = fileURL(scope), let data = coordinatedRead(url) {
            do {
                let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                if let dictionary = object as? [String: Data] {
                    bucket = dictionary
                } else {
                    logger.report(AnywhereError.store(.corrupted(.scripts, detail: "\(scope): unexpected plist shape")))
                }
            } catch {
                logger.report(AnywhereError.store(.corrupted(.scripts, detail: "\(scope): \(AnywhereError.describe(error))")))
            }
        }

        state.withLock { state in
            guard !state.loaded.contains(scope) else { return }
            state.loaded.insert(scope)
            state.cache[scope] = bucket
        }
    }

    private func coordinatedRead(_ url: URL) -> Data? {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordError: NSError?
        var result: Data?
        var readError: Error?
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordError) { coordinatedURL in
            do {
                result = try Data(contentsOf: coordinatedURL)
            } catch {
                readError = error
            }
        }
        if let error = coordError ?? (readError as NSError?), !Self.isFileNotFound(error) {
            logger.report("[MITM][JS] Anywhere.store(onDisk): read failed for \(url.lastPathComponent)",
                          error: AnywhereError.store(.loadFailed(.scripts, underlying: error)))
        }
        return result
    }

    private static func isFileNotFound(_ error: NSError) -> Bool {
        error.domain == NSCocoaErrorDomain
            && (error.code == NSFileReadNoSuchFileError || error.code == NSFileNoSuchFileError)
    }

    private func writeToDisk(scope: UUID, data: Data) -> Bool {
        guard let directory, let url = fileURL(scope) else { return false }
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: directory.path) {
            try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        // Coordinate across App Group processes so concurrent writers can't clobber each other's
        // whole-bucket plist. FirstUserAuthentication file protection lets the background NE
        // read/write after the first unlock even while the device is later locked.
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordError: NSError?
        var writeError: Error?
        coordinator.coordinate(writingItemAt: url, options: .forReplacing, error: &coordError) { coordinatedURL in
            do {
                try data.write(to: coordinatedURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            } catch {
                writeError = error
            }
        }
        if let error = coordError ?? writeError {
            logger.error("[MITM][JS] Anywhere.store(onDisk): write failed for \(scope): \(AnywhereError.describe(error))")
            return false
        }
        return true
    }

    private func removeFile(_ scope: UUID) {
        guard let url = fileURL(scope) else { return }
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordError: NSError?
        coordinator.coordinate(writingItemAt: url, options: .forDeleting, error: &coordError) { coordinatedURL in
            try? FileManager.default.removeItem(at: coordinatedURL)
        }
    }

    private func fileURL(_ scope: UUID) -> URL? {
        directory?.appendingPathComponent("\(scope.uuidString).plist", isDirectory: false)
    }

    private func serialize(_ bucket: [String: Data]) -> Data? {
        try? PropertyListSerialization.data(fromPropertyList: bucket, format: .binary, options: 0)
    }
}
