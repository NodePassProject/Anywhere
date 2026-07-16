//
//  MITMScriptDiskStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/10/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMScriptDiskStore")

nonisolated final class MITMScriptDiskStore {

    static let shared = MITMScriptDiskStore()
    
    static let maxBytesPerScope: Int = 1 * 1024 * 1024
    static let maxTotalBytes: Int = 16 * 1024 * 1024
    
    private struct State {
        /// An empty dictionary means "loaded, no keys", distinct from a not-yet-loaded scope.
        var cache: [UUID: [String: Data]] = [:]
        var loaded: Set<UUID> = []

        /// Serialized file size per scope, the basis for both caps. Seeded by a one-time directory
        /// scan so the total cap counts scopes never loaded this session.
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
        state.withLock { state in
            ensureLoadedUnlocked(scope, &state)
            return state.cache[scope]?[key]
        }
    }
    
    func set(scope: UUID, key: String, value: Data) throws {
        try state.withLock { state in
            ensureLoadedUnlocked(scope, &state)

            var bucket = state.cache[scope] ?? [:]
            bucket[key] = value
            guard let serialized = serialize(bucket) else {
                throw MITMScriptStore.StoreError.writeFailed
            }
            if serialized.count > Self.maxBytesPerScope {
                throw MITMScriptStore.StoreError.capacityExceeded
            }
            let oldSize = state.fileSizes[scope] ?? 0
            let projectedTotal = state.totalBytes - oldSize + serialized.count
            if projectedTotal > Self.maxTotalBytes {
                throw MITMScriptStore.StoreError.capacityExceeded
            }
            guard writeUnlocked(scope: scope, data: serialized) else {
                throw MITMScriptStore.StoreError.writeFailed
            }
            state.cache[scope] = bucket
            state.fileSizes[scope] = serialized.count
            state.totalBytes = projectedTotal
        }
    }

    func delete(scope: UUID, key: String) {
        state.withLock { state in
            ensureLoadedUnlocked(scope, &state)
            guard var bucket = state.cache[scope], bucket[key] != nil else { return }
            bucket.removeValue(forKey: key)

            if bucket.isEmpty {
                // Last key gone: drop the file rather than persist an empty dictionary.
                removeFileUnlocked(scope, &state)
                state.cache[scope] = [:]
                return
            }
            guard let serialized = serialize(bucket), writeUnlocked(scope: scope, data: serialized) else {
                // Leave disk and cache as they were so the store stays consistent.
                return
            }
            state.cache[scope] = bucket
            let oldSize = state.fileSizes[scope] ?? 0
            state.totalBytes = state.totalBytes - oldSize + serialized.count
            state.fileSizes[scope] = serialized.count
        }
    }

    func keys(scope: UUID) -> [String] {
        state.withLock { state in
            ensureLoadedUnlocked(scope, &state)
            return state.cache[scope].map { Array($0.keys) } ?? []
        }
    }

    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        state.withLock { state in
            ensureScannedUnlocked(&state)
            let stale = state.fileSizes.keys.filter { !activeIDs.contains($0) }
            for scope in stale {
                removeFileUnlocked(scope, &state)
                state.cache.removeValue(forKey: scope)
                state.loaded.remove(scope)
            }
            return stale.count
        }
    }

    // MARK: - Private
    
    private func ensureScannedUnlocked(_ state: inout State) {
        guard !state.didScan else { return }
        state.didScan = true
        guard let directory,
              let entries = try? FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.fileSizeKey],
                options: [.skipsHiddenFiles]
              )
        else { return }
        for url in entries where url.pathExtension == "plist" {
            guard let scope = UUID(uuidString: url.deletingPathExtension().lastPathComponent) else { continue }
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
            state.fileSizes[scope] = size
            state.totalBytes += size
        }
    }

    private func ensureLoadedUnlocked(_ scope: UUID, _ state: inout State) {
        ensureScannedUnlocked(&state)
        guard !state.loaded.contains(scope) else { return }
        state.loaded.insert(scope)
        guard let url = fileURL(scope),
              let data = coordinatedRead(url),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dictionary = object as? [String: Data]
        else {
            state.cache[scope] = [:]
            return
        }
        state.cache[scope] = dictionary
    }

    /// Coordinated read so a concurrent writer in another App Group process can't be observed
    /// mid-write. (Cross-process cache coherence would also need an `NSFilePresenter`; only the
    /// serialized NE writes this store.)
    private func coordinatedRead(_ url: URL) -> Data? {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordError: NSError?
        var result: Data?
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordError) { coordinatedURL in
            result = try? Data(contentsOf: coordinatedURL)
        }
        return result
    }

    private func writeUnlocked(scope: UUID, data: Data) -> Bool {
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
            logger.error("[MITM][JS] Anywhere.store(onDisk): write failed for \(scope): \(error)")
            return false
        }
        return true
    }

    private func removeFileUnlocked(_ scope: UUID, _ state: inout State) {
        if let url = fileURL(scope) {
            let coordinator = NSFileCoordinator(filePresenter: nil)
            var coordError: NSError?
            coordinator.coordinate(writingItemAt: url, options: .forDeleting, error: &coordError) { coordinatedURL in
                try? FileManager.default.removeItem(at: coordinatedURL)
            }
        }
        state.totalBytes -= state.fileSizes[scope] ?? 0
        state.fileSizes.removeValue(forKey: scope)
    }

    private func fileURL(_ scope: UUID) -> URL? {
        directory?.appendingPathComponent("\(scope.uuidString).plist", isDirectory: false)
    }

    private func serialize(_ bucket: [String: Data]) -> Data? {
        try? PropertyListSerialization.data(fromPropertyList: bucket, format: .binary, options: 0)
    }
}
