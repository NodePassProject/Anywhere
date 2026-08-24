//
//  NowhereClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereFlowOpenAttempt: Sendable {
    private struct State {
        var cancelled = false
        var connections: [ObjectIdentifier: ProxyConnection] = [:]
        var earlyDataWriteStarted = false
    }
    private let state = Mutex(State())

    func bind(_ connection: ProxyConnection) -> Bool {
        let accepted = state.withLock { state in
            guard !state.cancelled else { return false }
            state.connections[ObjectIdentifier(connection)] = connection
            return true
        }
        if !accepted { connection.cancel() }
        return accepted
    }

    func markEarlyDataWriteStarted() {
        state.withLock { $0.earlyDataWriteStarted = true }
    }

    var hasStartedEarlyDataWrite: Bool { state.withLock { $0.earlyDataWriteStarted } }

    func cancel() {
        let connections = state.withLock { state -> [ProxyConnection] in
            guard !state.cancelled else { return [] }
            state.cancelled = true
            let connections = Array(state.connections.values)
            state.connections.removeAll(keepingCapacity: false)
            return connections
        }
        for connection in connections { connection.cancel() }
    }
}

nonisolated final class NowhereClient: Sendable {
    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let key: String
        let uplink: NowhereNetwork
        let downlink: NowhereNetwork
        let sni: String
        let alpn: String
        let chain: [ProxyConfiguration]
        let sessionID: Data
    }

    private struct RegistryState {
        var entries: [Key: NowhereClient] = [:]
        var pending: [Key: Task<NowhereClient, Error>] = [:]
        var generations: [Key: UInt64] = [:]
        var epoch: UInt64 = 0
        var sealed = false
    }
    private static let registry = Mutex(RegistryState())

    static func seal() {
        registry.withLock { $0.sealed = true }
    }

    static func unseal() {
        registry.withLock { $0.sealed = false }
    }

    static func shared(for configuration: NowhereConfiguration) throws -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            uplink: configuration.uplink,
            downlink: configuration.downlink,
            sni: configuration.tls.serverName,
            alpn: configuration.alpn,
            chain: [],
            sessionID: configuration.sessionID
        )
        return try registry.withLock { state in
            if let existing = state.entries[key] { return existing }
            guard !state.sealed else { throw AnywhereError.transport(.terminated) }
            let client = NowhereClient(
                configuration: configuration,
                transport: nil,
                chainHolders: [],
                poolKey: key
            )
            state.entries[key] = client
            return client
        }
    }

    static func chained(
        configuration: NowhereConfiguration,
        transport: QUICDatagramTransport
    ) -> NowhereClient {
        NowhereClient(
            configuration: configuration,
            transport: transport,
            chainHolders: [],
            poolKey: nil
        )
    }

    static func acquireChained(
        configuration: NowhereConfiguration,
        chain: [ProxyConfiguration],
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            uplink: configuration.uplink,
            downlink: configuration.downlink,
            sni: configuration.tls.serverName,
            alpn: configuration.alpn,
            chain: chain,
            sessionID: configuration.sessionID
        )

        enum Decision { case existing(NowhereClient); case join(Task<NowhereClient, Error>) }
        let decision: Decision = try registry.withLock { state in
            if let client = state.entries[key] { return .existing(client) }
            if let inFlight = state.pending[key] { return .join(inFlight) }
            guard !state.sealed else { throw AnywhereError.transport(.terminated) }
            let buildEpoch = state.epoch
            let buildGeneration = state.generations[key, default: 0]
            let task = Task<NowhereClient, Error> {
                try await Self.buildChained(key: key, configuration: configuration,
                                            buildEpoch: buildEpoch,
                                            buildGeneration: buildGeneration,
                                            builder: builder)
            }
            state.pending[key] = task
            return .join(task)
        }
        switch decision {
        case .existing(let client):
            return client
        case .join(let task):
            return try await task.value
        }
    }

    private static func buildChained(
        key: Key,
        configuration: NowhereConfiguration,
        buildEpoch: UInt64,
        buildGeneration: UInt64,
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> NowhereClient {
        let builderResult: Result<(QUICDatagramTransport, [ProxyClient]), Error>
        do { builderResult = .success(try await builder()) }
        catch { builderResult = .failure(error) }

        typealias Discard = (Result<NowhereClient, Error>, QUICDatagramTransport?, [ProxyClient])
        let (outcome, staleTransport, staleHolders): Discard = registry.withLock { state in
            guard state.epoch == buildEpoch,
                  state.generations[key, default: 0] == buildGeneration else {
                let built = try? builderResult.get()
                return (
                    .failure(AnywhereError.proxy(.nowhere, .streamClosed)),
                    built?.0,
                    built?.1 ?? []
                )
            }
            state.pending.removeValue(forKey: key)
            switch builderResult {
            case .success(let (transport, holders)):
                let client = NowhereClient(
                    configuration: configuration,
                    transport: transport,
                    chainHolders: holders,
                    poolKey: key
                )
                state.entries[key] = client
                return (.success(client), nil, [])
            case .failure(let error):
                return (.failure(error), nil, [])
            }
        }
        staleTransport?.cancel()
        for client in staleHolders { await client.cancel() }
        return try outcome.get()
    }

    private let configuration: NowhereConfiguration
    private let transport: QUICDatagramTransport?
    private let poolKey: Key?

    private struct SessionState {
        var session: NowhereSession? = nil
        var transportConsumed = false
        var chainHolders: [ProxyClient]
        var retired = false
    }
    private let state: Mutex<SessionState>

    private init(
        configuration: NowhereConfiguration,
        transport: QUICDatagramTransport?,
        chainHolders: [ProxyClient],
        poolKey: Key?
    ) {
        self.configuration = configuration
        self.transport = transport
        self.state = Mutex(SessionState(chainHolders: chainHolders))
        self.poolKey = poolKey
    }

    private func acquireSession() async throws -> NowhereSession {
        enum Acquired {
            case reuse(NowhereSession)
            case transportSpent
            case fresh(NowhereSession)
        }
        let acquired: Acquired = state.withLock { state in
            guard !state.retired else { return .transportSpent }
            if let existing = state.session, !existing.isClosed {
                return .reuse(existing)
            }

            if transport != nil && state.transportConsumed {
                if let key = poolKey {
                    Self.registry.withLock { registryState in
                        if registryState.entries[key] === self {
                            registryState.entries.removeValue(forKey: key)
                        }
                    }
                }
                return .transportSpent
            }

            let newSession = NowhereSession(configuration: configuration, transport: transport)
            state.session = newSession
            if transport != nil { state.transportConsumed = true }
            return .fresh(newSession)
        }

        switch acquired {
        case .reuse(let existing):
            try await existing.ensureReady()
            return existing
        case .transportSpent:
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        case .fresh(let newSession):
            newSession.setOnClose { [weak self, weak newSession] in
                guard let self, let newSession else { return }
                self.handleSessionClose(newSession)
            }

            try await newSession.ensureReady()
            return newSession
        }
    }

    private func handleSessionClose(_ closedSession: NowhereSession) {
        let holders: [ProxyClient]? = state.withLock { state in
            guard state.session === closedSession else { return nil }
            state.session = nil
            let holders = state.chainHolders
            state.chainHolders = []
            if transport != nil, let key = poolKey {
                Self.registry.withLock { registryState in
                    if registryState.entries[key] === self {
                        registryState.entries.removeValue(forKey: key)
                    }
                }
            }
            return holders
        }
        guard let holders else { return }

        for client in holders {
            client.cancel()
        }
    }

    func openTCPHalf(
        destination: NowhereProtocol.Target,
        header: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws -> ProxyConnection {
        let session: NowhereSession
        do {
            session = try await acquireSession()
        } catch {
            if Self.isStaleSessionError(error) { invalidateSession() }
            throw error
        }
        let connection = NowhereConnection(
            session: session,
            destination: destination,
            flowHeader: header,
            initialData: initialData,
            attempt: attempt
        )
        guard attempt?.bind(connection) != false else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await connection.open()
            return connection
        } catch {
            connection.cancel()
            if Self.isStaleSessionError(error) {
                invalidateSession(ifCurrent: session)
            }
            throw error
        }
    }

    func openUDP(
        destination: NowhereProtocol.Target,
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws -> ProxyConnection {
        let session: NowhereSession
        do {
            session = try await acquireSession()
        } catch {
            if Self.isStaleSessionError(error) { invalidateSession() }
            throw error
        }
        let connection = NowhereUDPConnection(
            session: session,
            destination: destination,
            flowHeader: header
        )
        guard attempt?.bind(connection) != false else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await connection.open()
            return connection
        } catch {
            connection.cancel()
            if Self.isStaleSessionError(error) {
                invalidateSession(ifCurrent: session)
            }
            throw error
        }
    }

    private static func isStaleSessionError(_ error: Error) -> Bool {
        guard case AnywhereError.proxy(.nowhere, let failure) = error else { return false }
        switch failure {
        case .notReady, .streamClosed: return true
        case .flowRejected(let code) where code == NowhereProtocol.FlowRejectCode.sessionReplaced.rawValue:
            return true
        default: return false
        }
    }

    private func invalidateSession(ifCurrent expected: NowhereSession? = nil) {
        let invalidated: (NowhereSession, [ProxyClient])? = state.withLock { state in
            guard let current = state.session,
                  expected == nil || current === expected else { return nil }
            state.session = nil
            let holders = state.chainHolders
            state.chainHolders = []
            if transport != nil, let key = poolKey {
                Self.registry.withLock { registryState in
                    if registryState.entries[key] === self {
                        registryState.entries.removeValue(forKey: key)
                    }
                }
            }
            return (current, holders)
        }

        guard let (current, holders) = invalidated else { return }
        current.close()

        for client in holders {
            client.cancel()
        }
    }

    private func retire() {
        let resources: (NowhereSession?, [ProxyClient])? = state.withLock { state in
            guard !state.retired else { return nil }
            state.retired = true
            let current = state.session
            state.session = nil
            let holders = state.chainHolders
            state.chainHolders = []
            return (current, holders)
        }
        guard let resources else { return }
        resources.0?.close()
        transport?.cancel()
        for client in resources.1 { client.cancel() }
    }

    static func invalidateSharedSession(for configuration: NowhereConfiguration) {
        let resources: ([NowhereClient], [Task<NowhereClient, Error>]) = registry.withLock { state in
            let entryKeys = state.entries.keys.filter {
                Self.matches($0, configuration: configuration)
            }
            let pendingKeys = state.pending.keys.filter {
                Self.matches($0, configuration: configuration)
            }
            for key in Set(entryKeys + pendingKeys) {
                state.generations[key, default: 0] &+= 1
            }
            return (
                entryKeys.compactMap { state.entries.removeValue(forKey: $0) },
                pendingKeys.compactMap { state.pending.removeValue(forKey: $0) }
            )
        }
        for task in resources.1 { task.cancel() }
        for client in resources.0 { client.retire() }
    }

    private static func matches(
        _ key: Key,
        configuration: NowhereConfiguration
    ) -> Bool {
        key.host == configuration.proxyHost
            && key.port == configuration.proxyPort
            && key.key == configuration.key
            && key.uplink == configuration.uplink
            && key.downlink == configuration.downlink
            && key.sni == configuration.tls.serverName
            && key.alpn == configuration.alpn
            && key.sessionID == configuration.sessionID
    }

    static func closeAll() {
        let (clients, pending): ([NowhereClient], [Task<NowhereClient, Error>]) = registry.withLock { state in
            let clients = Array(state.entries.values)
            state.entries.removeAll(keepingCapacity: false)
            let pending = Array(state.pending.values)
            state.pending.removeAll(keepingCapacity: false)
            // Bumping the epoch makes any in-flight build discard its result and fail its joiners.
            state.epoch &+= 1
            return (clients, pending)
        }
        for task in pending { task.cancel() }
        for client in clients {
            client.retire()
        }
    }
}

nonisolated extension NowhereClient {
    static let pool: TransportPool = Pool()
    private final class Pool: TransportPool {
        func reclaim() {
            NowhereClient.closeAll()
            NowhereMuxShardRegistry.shared.closeAll()
            NowhereTransportIdentityRegistry.shared.reset()
        }
    }
}
