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
        var totalBytes: Int = 0
        var didScan = false
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

    func set(scope: UUID, key: String, value: Data) throws {
        ensureLoaded(scope)
        let serialized: Data = try state.withLock { state in
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
            return serialized
        }
        guard writeToDisk(scope: scope, data: serialized) else {
            throw AnywhereError.mitm(.scriptStoreWriteFailed)
        }
        state.withLock { state in
            var bucket = state.cache[scope] ?? [:]
            bucket[key] = value
            state.cache[scope] = bucket
            let oldSize = state.fileSizes[scope] ?? 0
            state.totalBytes = state.totalBytes - oldSize + serialized.count
            state.fileSizes[scope] = serialized.count
        }
    }

    func delete(scope: UUID, key: String) {
        ensureLoaded(scope)
        enum Pending {
            case nothing
            case removeFile
            case write(Data, bucket: [String: Data])
        }
        let pending: Pending = state.withLock { state in
            guard var bucket = state.cache[scope], bucket[key] != nil else { return .nothing }
            bucket.removeValue(forKey: key)
            if bucket.isEmpty { return .removeFile }
            guard let serialized = serialize(bucket) else { return .nothing }
            return .write(serialized, bucket: bucket)
        }
        switch pending {
        case .nothing:
            return
        case .removeFile:
            removeFile(scope)
            state.withLock { state in
                state.cache[scope] = [:]
                state.totalBytes -= state.fileSizes[scope] ?? 0
                state.fileSizes.removeValue(forKey: scope)
            }
        case .write(let serialized, let bucket):
            guard writeToDisk(scope: scope, data: serialized) else { return }
            state.withLock { state in
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
        if let url = fileURL(scope),
           let data = coordinatedRead(url),
           let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let dictionary = object as? [String: Data] {
            bucket = dictionary
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
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordError) { coordinatedURL in
            result = try? Data(contentsOf: coordinatedURL)
        }
        return result
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
