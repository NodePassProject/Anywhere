//
//  MITMScriptDiskStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/10/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMScriptDiskStore")

final class MITMScriptDiskStore {

    static let shared = MITMScriptDiskStore()
    
    static let maxBytesPerScope: Int = 1 * 1024 * 1024
    static let maxTotalBytes: Int = 16 * 1024 * 1024

    private let lock = NSLock()
    
    private let directory: URL?

    /// An empty dictionary means "loaded, no keys", distinct from a not-yet-loaded scope.
    private var cache: [UUID: [String: Data]] = [:]
    private var loaded: Set<UUID> = []

    /// Serialized file size per scope, the basis for both caps. Seeded by a one-time directory
    /// scan so the total cap counts scopes never loaded this session.
    private var fileSizes: [UUID: Int] = [:]
    private var totalBytes: Int = 0
    private var didScan = false

    init(appGroup: String = AWCore.Identifier.appGroupSuite) {
        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) {
            directory = container.appendingPathComponent("MITMScriptStore", isDirectory: true)
        } else {
            directory = nil
        }
    }

    // MARK: - API

    func get(scope: UUID, key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        ensureLoadedUnlocked(scope)
        return cache[scope]?[key]
    }
    
    func set(scope: UUID, key: String, value: Data) throws {
        lock.lock(); defer { lock.unlock() }
        ensureLoadedUnlocked(scope)

        var bucket = cache[scope] ?? [:]
        bucket[key] = value
        guard let serialized = serialize(bucket) else {
            throw MITMScriptStore.StoreError.writeFailed
        }
        if serialized.count > Self.maxBytesPerScope {
            throw MITMScriptStore.StoreError.capacityExceeded
        }
        let oldSize = fileSizes[scope] ?? 0
        let projectedTotal = totalBytes - oldSize + serialized.count
        if projectedTotal > Self.maxTotalBytes {
            throw MITMScriptStore.StoreError.capacityExceeded
        }
        guard writeUnlocked(scope: scope, data: serialized) else {
            throw MITMScriptStore.StoreError.writeFailed
        }
        cache[scope] = bucket
        fileSizes[scope] = serialized.count
        totalBytes = projectedTotal
    }

    func delete(scope: UUID, key: String) {
        lock.lock(); defer { lock.unlock() }
        ensureLoadedUnlocked(scope)
        guard var bucket = cache[scope], bucket[key] != nil else { return }
        bucket.removeValue(forKey: key)

        if bucket.isEmpty {
            // Last key gone: drop the file rather than persist an empty dictionary.
            removeFileUnlocked(scope)
            cache[scope] = [:]
            return
        }
        guard let serialized = serialize(bucket), writeUnlocked(scope: scope, data: serialized) else {
            // Leave disk and cache as they were so the store stays consistent.
            return
        }
        cache[scope] = bucket
        let oldSize = fileSizes[scope] ?? 0
        totalBytes = totalBytes - oldSize + serialized.count
        fileSizes[scope] = serialized.count
    }

    func keys(scope: UUID) -> [String] {
        lock.lock(); defer { lock.unlock() }
        ensureLoadedUnlocked(scope)
        return cache[scope].map { Array($0.keys) } ?? []
    }
    
    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        lock.lock(); defer { lock.unlock() }
        ensureScannedUnlocked()
        let stale = fileSizes.keys.filter { !activeIDs.contains($0) }
        for scope in stale {
            removeFileUnlocked(scope)
            cache.removeValue(forKey: scope)
            loaded.remove(scope)
        }
        return stale.count
    }

    // MARK: - Private
    
    private func ensureScannedUnlocked() {
        guard !didScan else { return }
        didScan = true
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
            fileSizes[scope] = size
            totalBytes += size
        }
    }
    
    private func ensureLoadedUnlocked(_ scope: UUID) {
        ensureScannedUnlocked()
        guard !loaded.contains(scope) else { return }
        loaded.insert(scope)
        guard let url = fileURL(scope),
              let data = coordinatedRead(url),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = object as? [String: Data]
        else {
            cache[scope] = [:]
            return
        }
        cache[scope] = dict
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

    private func removeFileUnlocked(_ scope: UUID) {
        if let url = fileURL(scope) {
            let coordinator = NSFileCoordinator(filePresenter: nil)
            var coordError: NSError?
            coordinator.coordinate(writingItemAt: url, options: .forDeleting, error: &coordError) { coordinatedURL in
                try? FileManager.default.removeItem(at: coordinatedURL)
            }
        }
        totalBytes -= fileSizes[scope] ?? 0
        fileSizes.removeValue(forKey: scope)
    }

    private func fileURL(_ scope: UUID) -> URL? {
        directory?.appendingPathComponent("\(scope.uuidString).plist", isDirectory: false)
    }

    private func serialize(_ bucket: [String: Data]) -> Data? {
        try? PropertyListSerialization.data(fromPropertyList: bucket, format: .binary, options: 0)
    }
}
