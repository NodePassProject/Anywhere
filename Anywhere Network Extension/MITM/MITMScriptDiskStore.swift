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

    private static let writeDelay: DispatchTimeInterval = .seconds(1)

    private struct State {
        var cache: [UUID: [String: Data]] = [:]
        var loaded: Set<UUID> = []
        var scopeBytes: [UUID: Int] = [:]
        var totalBytes: Int = 0
        var dirty: Set<UUID> = []
        var isWriteScheduled = false
        var didScan = false
    }

    private let state = Mutex(State())

    private let directory: URL?

    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.MITMScriptDiskStore", qos: .utility)

    init(appGroup: String = AWCore.Identifier.appGroupSuite) {
        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) {
            directory = container.appendingPathComponent("MITMScriptStore", isDirectory: true)
        } else {
            directory = nil
        }
    }

    // MARK: - API

    func value(forKey key: String, scope: UUID) -> Data? {
        ensureLoaded(scope)
        return state.withLock { $0.cache[scope]?[key] }
    }

    func setValue(_ value: Data, forKey key: String, scope: UUID) throws(AnywhereError) {
        guard ensureLoaded(scope) else { throw AnywhereError.mitm(.scriptStoreWriteFailed) }
        let didChange = try state.withLock { (state) throws(AnywhereError) -> Bool in
            let current = state.cache[scope]?[key]
            if current == value { return false }
            let keyBytes = key.utf8.count
            let delta = value.count + keyBytes - (current.map { $0.count + keyBytes } ?? 0)
            let projected = (state.scopeBytes[scope] ?? 0) + delta
            if projected > Self.maxBytesPerScope {
                throw AnywhereError.mitm(.scriptStoreCapacityExceeded)
            }
            if state.totalBytes + delta > Self.maxTotalBytes {
                throw AnywhereError.mitm(.scriptStoreCapacityExceeded)
            }
            state.cache[scope, default: [:]][key] = value
            state.scopeBytes[scope] = projected
            state.totalBytes += delta
            state.dirty.insert(scope)
            return true
        }
        if didChange { scheduleWrite() }
    }

    func removeValue(forKey key: String, scope: UUID) {
        guard ensureLoaded(scope) else { return }
        let didChange = state.withLock { state -> Bool in
            guard let current = state.cache[scope]?.removeValue(forKey: key) else { return false }
            let delta = current.count + key.utf8.count
            state.scopeBytes[scope] = (state.scopeBytes[scope] ?? 0) - delta
            state.totalBytes -= delta
            state.dirty.insert(scope)
            return true
        }
        if didChange { scheduleWrite() }
    }

    func keys(scope: UUID) -> [String] {
        ensureLoaded(scope)
        return state.withLock { $0.cache[scope].map { Array($0.keys) } ?? [] }
    }

    @discardableResult
    func purgeExcept(activeIDs: Set<UUID>) -> Int {
        ensureScanned()
        let stale: [UUID] = state.withLock { state in
            let stale = state.scopeBytes.keys.filter { !activeIDs.contains($0) }
            for scope in stale {
                state.totalBytes -= state.scopeBytes[scope] ?? 0
                state.scopeBytes.removeValue(forKey: scope)
                state.cache.removeValue(forKey: scope)
                state.loaded.remove(scope)
                state.dirty.remove(scope)
            }
            return stale
        }
        guard !stale.isEmpty else { return 0 }
        writeQueue.sync {
            for scope in stale { removeFile(scope) }
        }
        return stale.count
    }

    func flush() {
        writeQueue.sync { writeDirtyScopes() }
    }

    // MARK: - Private

    private func scheduleWrite() {
        let shouldSchedule = state.withLock { state -> Bool in
            guard !state.isWriteScheduled else { return false }
            state.isWriteScheduled = true
            return true
        }
        guard shouldSchedule else { return }
        writeQueue.asyncAfter(deadline: .now() + Self.writeDelay) { [self] in
            writeDirtyScopes()
        }
    }

    private func writeDirtyScopes() {
        let pending: [(scope: UUID, bucket: [String: Data])] = state.withLock { state in
            state.isWriteScheduled = false
            defer { state.dirty.removeAll() }
            return state.dirty.map { (scope: $0, bucket: state.cache[$0] ?? [:]) }
        }
        for (scope, bucket) in pending {
            if bucket.isEmpty {
                removeFile(scope)
                continue
            }
            if let data = serialize(bucket), writeToDisk(scope: scope, data: data) { continue }
            state.withLock { state in
                if state.loaded.contains(scope) { state.dirty.insert(scope) }
            }
        }
    }

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
            state.scopeBytes.merge(sizes) { current, _ in current }
            state.totalBytes = state.scopeBytes.values.reduce(0, +)
        }
    }

    @discardableResult
    private func ensureLoaded(_ scope: UUID) -> Bool {
        ensureScanned()
        let needsLoad = state.withLock { !$0.loaded.contains(scope) }
        guard needsLoad else { return true }

        var bucket: [String: Data] = [:]
        if let url = fileURL(scope) {
            let read = readFile(url)
            if read.failed { return false }
            if let data = read.data {
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
        }
        let bucketBytes = bucket.reduce(0) { $0 + $1.key.utf8.count + $1.value.count }

        state.withLock { state in
            guard !state.loaded.contains(scope) else { return }
            state.loaded.insert(scope)
            state.cache[scope] = bucket
            state.totalBytes += bucketBytes - (state.scopeBytes[scope] ?? 0)
            state.scopeBytes[scope] = bucketBytes
        }
        return true
    }

    private func readFile(_ url: URL) -> (data: Data?, failed: Bool) {
        do {
            return (try Data(contentsOf: url), false)
        } catch {
            guard !Self.isFileNotFound(error as NSError) else { return (nil, false) }
            logger.report("[Script] Anywhere.store read failed", error: error)
            return (nil, true)
        }
    }

    private static func isFileNotFound(_ error: NSError) -> Bool {
        error.domain == NSCocoaErrorDomain
            && (error.code == NSFileReadNoSuchFileError || error.code == NSFileNoSuchFileError)
    }

    private func writeToDisk(scope: UUID, data: Data) -> Bool {
        guard let directory, let url = fileURL(scope) else { return false }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            return true
        } catch {
            logger.report("[Script] Anywhere.store write failed", error: error)
            return false
        }
    }

    private func removeFile(_ scope: UUID) {
        guard let url = fileURL(scope) else { return }
        try? FileManager.default.removeItem(at: url)
    }

    private func fileURL(_ scope: UUID) -> URL? {
        directory?.appendingPathComponent("\(scope.uuidString).plist", isDirectory: false)
    }

    private func serialize(_ bucket: [String: Data]) -> Data? {
        try? PropertyListSerialization.data(fromPropertyList: bucket, format: .binary, options: 0)
    }
}
