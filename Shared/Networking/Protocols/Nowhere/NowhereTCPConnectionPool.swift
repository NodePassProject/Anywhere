//
//  NowhereTCPConnectionPool.swift
//  Anywhere
//
//  Created by NodePassProject on 6/22/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereTCPConnectionPoolRegistry: Sendable {

    static let shared = NowhereTCPConnectionPoolRegistry()

    private struct Key: Hashable {
        let configurationID: UUID
        let connectHost: String
        let proxyHost: String
        let proxyPort: UInt16
        let key: String
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

    private let entries = Mutex<[UUID: Entry]>([:])

    private init() {}

    func acquire(
        configurationID: UUID,
        configuration: NowhereConfiguration,
        connectHost: String,
        destination: NowhereProtocol.Target,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        let key = Key(
            configurationID: configurationID,
            connectHost: connectHost,
            proxyHost: configuration.proxyHost,
            proxyPort: configuration.proxyPort,
            key: configuration.key,
            tlsServerName: configuration.tls.serverName,
            tlsALPN: configuration.tls.alpn,
            tlsMinVersion: configuration.tls.minVersion?.rawValue,
            tlsMaxVersion: configuration.tls.maxVersion?.rawValue,
            tlsECHEnabled: configuration.tls.echEnabled,
            tlsECHConfig: configuration.tls.echConfig,
            tlsFingerprint: configuration.tls.fingerprint.rawValue
        )

        var replaced: NowhereTCPConnectionPool?
        let pool: NowhereTCPConnectionPool = entries.withLock { entries in
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
        return try await pool.acquire(
            destination: destination,
            mode: mode,
            flowHeader: flowHeader,
            initialData: initialData,
            attempt: attempt
        )
    }

    func closeAll() {
        let pools: [NowhereTCPConnectionPool] = entries.withLock { entries in
            let snapshot = entries.values.map(\.pool)
            entries.removeAll(keepingCapacity: false)
            return snapshot
        }
        for pool in pools { pool.closeAll() }
    }

    func disable(configurationID: UUID) {
        let pool = entries.withLock { $0.removeValue(forKey: configurationID)?.pool }
        pool?.closeAll()
    }
}

nonisolated private final class NowhereTCPConnectionPool: Sendable {

    private static let warmConnectionTTL: Duration = .seconds(30)

    private struct State {
        var idle: [NowhereTCPConnection] = []
        var preparing: [ObjectIdentifier: NowhereTCPConnection] = [:]
        var expirations: [ObjectIdentifier: Task<Void, Never>] = [:]
        var targetSize: Int
        var closed = false
    }

    private let configuration: NowhereConfiguration
    private let connectHost: String
    private let state: Mutex<State>

    init(configuration: NowhereConfiguration, connectHost: String, targetSize: Int) {
        self.configuration = configuration
        self.connectHost = connectHost
        self.state = Mutex(State(targetSize: targetSize))
    }

    func resize(to newSize: Int) {
        var excess: [NowhereTCPConnection] = []
        state.withLock { state in
            state.targetSize = newSize
            while state.idle.count + state.preparing.count > newSize, let entry = state.preparing.first {
                state.preparing.removeValue(forKey: entry.key)
                cancelExpirationLocked(for: entry.value, in: &state)
                excess.append(entry.value)
            }
            while state.idle.count > newSize {
                let connection = state.idle.removeFirst()
                cancelExpirationLocked(for: connection, in: &state)
                excess.append(connection)
            }
        }
        for connection in excess {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
    }

    func acquire(
        destination: NowhereProtocol.Target,
        mode: NowhereTCPRelayMode,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        var selected: NowhereTCPConnection?
        var stale: [NowhereTCPConnection] = []
        var unavailable = false
        let replenishments: [NowhereTCPConnection] = state.withLock { state in
            guard !state.closed else {
                unavailable = true
                return []
            }
            while let candidate = state.idle.popLast() {
                if candidate.isPrepared {
                    cancelExpirationLocked(for: candidate, in: &state)
                    selected = candidate
                    break
                }
                cancelExpirationLocked(for: candidate, in: &state)
                stale.append(candidate)
            }
            let warmCount = state.idle.count + state.preparing.count
            let requestedCount = selected == nil ? (warmCount == 0 ? 1 : 0) : 2
            let count = min(requestedCount, max(0, state.targetSize - warmCount))
            var connections: [NowhereTCPConnection] = []
            connections.reserveCapacity(count)
            for _ in 0..<count {
                let connection = NowhereTCPConnection(
                    configuration: configuration,
                    connectHost: connectHost,
                    tunnel: nil
                )
                state.preparing[ObjectIdentifier(connection)] = connection
                armExpirationLocked(for: connection, in: &state)
                connections.append(connection)
            }
            return connections
        }

        if unavailable {
            throw AnywhereError.transport(.terminated)
        }
        for connection in stale {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
        startReplenishments(replenishments)

        if let selected {
            selected.setPreparedCloseHandler(nil)
            guard attempt.bind(selected) else {
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
            do {
                try await selected.activate(
                    destination: destination,
                    mode: mode,
                    flowHeader: flowHeader,
                    initialData: initialData,
                    attempt: initialData?.isEmpty == false ? attempt : nil
                )
                return Self.proxyConnection(selected, mode: mode)
            } catch {
                selected.cancel()
                throw error
            }
        } else {
            return try await openFresh(
                destination: destination,
                mode: mode,
                flowHeader: flowHeader,
                initialData: initialData,
                attempt: attempt
            )
        }
    }

    func closeAll() {
        let connections: [NowhereTCPConnection] = state.withLock { state in
            guard !state.closed else { return [] }
            state.closed = true
            state.targetSize = 0
            let snapshot = state.idle + Array(state.preparing.values)
            state.idle.removeAll(keepingCapacity: false)
            state.preparing.removeAll(keepingCapacity: false)
            for expiration in state.expirations.values { expiration.cancel() }
            state.expirations.removeAll(keepingCapacity: false)
            return Array(snapshot)
        }
        for connection in connections {
            connection.setPreparedCloseHandler(nil)
            connection.cancel()
        }
    }

    private func openFresh(
        destination: NowhereProtocol.Target,
        mode: NowhereTCPRelayMode,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        let connection = NowhereTCPConnection(
            configuration: configuration,
            connectHost: connectHost,
            tunnel: nil
        )
        guard attempt.bind(connection) else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await connection.openFresh(
                destination: destination,
                mode: mode,
                flowHeader: flowHeader,
                initialData: initialData,
                attempt: attempt
            )
            return Self.proxyConnection(connection, mode: mode)
        } catch {
            connection.cancel()
            throw error
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
            return NowhereTCPUDPConnection(
                inner: connection
            )
        }
    }

    private func startReplenishments(_ connections: [NowhereTCPConnection]) {
        for connection in connections {
            Task { [weak self] in
                let prepareError: Error?
                do {
                    try await connection.prepare()
                    prepareError = nil
                } catch {
                    prepareError = error
                }
                guard let self else {
                    connection.cancel()
                    return
                }
                self.finishPreparation(connection: connection, error: prepareError)
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

        let keep: Bool = state.withLock { state in
            let wasPreparing = state.preparing.removeValue(forKey: ObjectIdentifier(connection)) != nil
            guard wasPreparing, error == nil, !state.closed,
                  state.idle.count < state.targetSize, connection.isPrepared else {
                cancelExpirationLocked(for: connection, in: &state)
                return false
            }
            state.idle.append(connection)
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
        state.withLock { state in
            state.idle.removeAll { $0 === connection }
            cancelExpirationLocked(for: connection, in: &state)
        }
    }

    private func armExpirationLocked(for connection: NowhereTCPConnection, in state: inout State) {
        let identifier = ObjectIdentifier(connection)
        // `State` (and thus `expirations`) is Mutex-guarded, so `expire` is safe to fire
        // straight from the Task without a queue hop.
        let expiration = Task { [weak self, weak connection] in
            try? await Task.sleep(for: Self.warmConnectionTTL)
            guard !Task.isCancelled, let self, let connection else { return }
            self.expire(connection)
        }
        state.expirations[identifier] = expiration
    }

    private func cancelExpirationLocked(for connection: NowhereTCPConnection, in state: inout State) {
        state.expirations.removeValue(forKey: ObjectIdentifier(connection))?.cancel()
    }

    private func expire(_ connection: NowhereTCPConnection) {
        let shouldCancel: Bool = state.withLock { state in
            let identifier = ObjectIdentifier(connection)
            guard state.expirations.removeValue(forKey: identifier) != nil else { return false }
            let wasPreparing = state.preparing.removeValue(forKey: identifier) != nil
            let idleCount = state.idle.count
            state.idle.removeAll { $0 === connection }
            return wasPreparing || state.idle.count != idleCount
        }
        guard shouldCancel else { return }
        connection.setPreparedCloseHandler(nil)
        connection.cancel()
    }
}
