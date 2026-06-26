//
//  NowhereTCPConnectionPool.swift
//  Anywhere
//
//  Created by NodePassProject on 6/22/26.
//

import Foundation

nonisolated final class NowhereTCPConnectionPoolRegistry {

    static let shared = NowhereTCPConnectionPoolRegistry()

    private struct Key: Hashable {
        let configurationID: UUID
        let connectHost: String
        let proxyHost: String
        let proxyPort: UInt16
        let key: String
        let spec: String?
        let tlsServerName: String
        let tlsALPN: [String]?
        let tlsMinVersion: UInt16?
        let tlsMaxVersion: UInt16?
        let tlsECHEnabled: Bool
        let tlsECHConfig: String?
        let tlsFingerprint: String
    }

    private struct Entry {
        let key: Key
        let pool: NowhereTCPConnectionPool
    }

    private let lock = UnfairLock()
    private var entries: [UUID: Entry] = [:]

    private init() {}

    func acquire(
        configurationID: UUID,
        configuration: NowhereConfiguration,
        connectHost: String,
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let key = Key(
            configurationID: configurationID,
            connectHost: connectHost,
            proxyHost: configuration.proxyHost,
            proxyPort: configuration.proxyPort,
            key: configuration.key,
            spec: configuration.spec,
            tlsServerName: configuration.tls.serverName,
            tlsALPN: configuration.tls.alpn,
            tlsMinVersion: configuration.tls.minVersion?.rawValue,
            tlsMaxVersion: configuration.tls.maxVersion?.rawValue,
            tlsECHEnabled: configuration.tls.echEnabled,
            tlsECHConfig: configuration.tls.echConfig,
            tlsFingerprint: configuration.tls.fingerprint.rawValue
        )

        var replaced: NowhereTCPConnectionPool?
        let pool: NowhereTCPConnectionPool = lock.withLock {
            if let entry = entries[configurationID], entry.key == key {
                entry.pool.resize(to: configuration.pool)
                return entry.pool
            }
            replaced = entries.removeValue(forKey: configurationID)?.pool
            let pool = NowhereTCPConnectionPool(
                configuration: configuration,
                connectHost: connectHost,
                targetSize: configuration.pool
            )
            entries[configurationID] = Entry(key: key, pool: pool)
            return pool
        }
        replaced?.closeAll()
        pool.acquire(destination: destination, mode: mode, completion: completion)
    }

    func closeAll() {
        let pools: [NowhereTCPConnectionPool] = lock.withLock {
            let snapshot = entries.values.map(\.pool)
            entries.removeAll(keepingCapacity: false)
            return snapshot
        }
        for pool in pools { pool.closeAll() }
    }

    func disable(configurationID: UUID) {
        let pool = lock.withLock { entries.removeValue(forKey: configurationID)?.pool }
        pool?.closeAll()
    }
}

nonisolated private final class NowhereTCPConnectionPool {

    private static let warmConnectionTTL: DispatchTimeInterval = .seconds(30)
    private static let expiryQueue = DispatchQueue(
        label: "com.argsment.Anywhere.NowhereTCPPoolExpiry",
        qos: .utility
    )

    private let configuration: NowhereConfiguration
    private let connectHost: String
    private let lock = UnfairLock()
    private var idle: [NowhereTCPConnection] = []
    private var preparing: [ObjectIdentifier: NowhereTCPConnection] = [:]
    private var expirations: [ObjectIdentifier: DispatchWorkItem] = [:]
    private var targetSize: Int
    private var closed = false

    init(configuration: NowhereConfiguration, connectHost: String, targetSize: Int) {
        self.configuration = configuration
        self.connectHost = connectHost
        self.targetSize = targetSize
    }

    func resize(to newSize: Int) {
        var excess: [NowhereTCPConnection] = []
        lock.lock()
        targetSize = newSize
        while idle.count + preparing.count > newSize, let entry = preparing.first {
            preparing.removeValue(forKey: entry.key)
            cancelExpirationLocked(for: entry.value)
            excess.append(entry.value)
        }
        while idle.count > newSize {
            let connection = idle.removeFirst()
            cancelExpirationLocked(for: connection)
            excess.append(connection)
        }
        lock.unlock()
        for connection in excess {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
    }

    func acquire(
        destination: String,
        mode: NowhereTCPRelayMode,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        var selected: NowhereTCPConnection?
        var stale: [NowhereTCPConnection] = []
        var unavailable = false
        let replenishments: [NowhereTCPConnection] = lock.withLock {
            guard !closed else {
                unavailable = true
                return []
            }
            while let candidate = idle.popLast() {
                if candidate.isPrepared {
                    cancelExpirationLocked(for: candidate)
                    selected = candidate
                    break
                }
                cancelExpirationLocked(for: candidate)
                stale.append(candidate)
            }
            let warmCount = idle.count + preparing.count
            let requestedCount = selected == nil ? (warmCount == 0 ? 1 : 0) : 2
            let count = min(requestedCount, max(0, targetSize - warmCount))
            var connections: [NowhereTCPConnection] = []
            connections.reserveCapacity(count)
            for _ in 0..<count {
                let connection = NowhereTCPConnection(
                    configuration: configuration,
                    connectHost: connectHost,
                    tunnel: nil
                )
                preparing[ObjectIdentifier(connection)] = connection
                armExpirationLocked(for: connection)
                connections.append(connection)
            }
            return connections
        }

        if unavailable {
            completion(.failure(ProxyError.connectionFailed("Nowhere TCP pool closed")))
            return
        }
        for connection in stale {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
        startReplenishments(replenishments)

        if let selected {
            selected.setPreparedCloseHandler(nil)
            selected.activate(destination: destination, mode: mode) { [weak self] error in
                if error != nil {
                    selected.cancel()
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Nowhere TCP pool closed during acquire")))
                        return
                    }
                    self.openFresh(destination: destination, mode: mode, completion: completion)
                } else {
                    completion(.success(Self.proxyConnection(selected, mode: mode)))
                }
            }
        } else {
            openFresh(destination: destination, mode: mode, completion: completion)
        }
    }

    func closeAll() {
        let connections: [NowhereTCPConnection] = lock.withLock {
            guard !closed else { return [] }
            closed = true
            targetSize = 0
            let snapshot = idle + Array(preparing.values)
            idle.removeAll(keepingCapacity: false)
            preparing.removeAll(keepingCapacity: false)
            for expiration in expirations.values { expiration.cancel() }
            expirations.removeAll(keepingCapacity: false)
            return Array(snapshot)
        }
        for connection in connections {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
    }

    private func openFresh(
        destination: String,
        mode: NowhereTCPRelayMode,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let connection = NowhereTCPConnection(
            configuration: configuration,
            connectHost: connectHost,
            tunnel: nil
        )
        connection.openFresh(destination: destination, mode: mode) { error in
            if let error {
                connection.cancel()
                completion(.failure(error))
            } else {
                completion(.success(Self.proxyConnection(connection, mode: mode)))
            }
        }
    }

    private static func proxyConnection(
        _ connection: NowhereTCPConnection,
        mode: NowhereTCPRelayMode
    ) -> ProxyConnection {
        switch mode {
        case .tcp:
            return connection
        case .udp:
            return NowhereTCPUDPConnection(inner: connection)
        }
    }

    private func startReplenishments(_ connections: [NowhereTCPConnection]) {
        for connection in connections {
            connection.prepare { [weak self] error in
                guard let self else {
                    connection.cancel()
                    return
                }
                self.finishPreparation(connection: connection, error: error)
            }
        }
    }

    private func finishPreparation(connection: NowhereTCPConnection, error: Error?) {
        if error == nil {
            connection.setPreparedCloseHandler { [weak self, weak connection] in
                guard let self, let connection else { return }
                self.evict(connection)
            }
        }

        let keep: Bool = lock.withLock {
            let wasPreparing = preparing.removeValue(forKey: ObjectIdentifier(connection)) != nil
            guard wasPreparing, error == nil, !closed,
                  idle.count < targetSize, connection.isPrepared else {
                cancelExpirationLocked(for: connection)
                return false
            }
            idle.append(connection)
            return true
        }

        if keep {
            if !connection.isPrepared { evict(connection) }
        } else {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
    }

    private func evict(_ connection: NowhereTCPConnection) {
        lock.withLock {
            idle.removeAll { $0 === connection }
            cancelExpirationLocked(for: connection)
        }
    }

    private func armExpirationLocked(for connection: NowhereTCPConnection) {
        let identifier = ObjectIdentifier(connection)
        let expiration = DispatchWorkItem { [weak self, weak connection] in
            guard let self, let connection else { return }
            self.expire(connection)
        }
        expirations[identifier] = expiration
        Self.expiryQueue.asyncAfter(
            deadline: .now() + Self.warmConnectionTTL,
            execute: expiration
        )
    }

    private func cancelExpirationLocked(for connection: NowhereTCPConnection) {
        expirations.removeValue(forKey: ObjectIdentifier(connection))?.cancel()
    }

    private func expire(_ connection: NowhereTCPConnection) {
        let shouldCancel: Bool = lock.withLock {
            let identifier = ObjectIdentifier(connection)
            guard expirations.removeValue(forKey: identifier) != nil else { return false }
            let wasPreparing = preparing.removeValue(forKey: identifier) != nil
            let idleCount = idle.count
            idle.removeAll { $0 === connection }
            return wasPreparing || idle.count != idleCount
        }
        guard shouldCancel else { return }
        connection.setPreparedCloseHandler(nil)
        connection.cancel()
    }
}
