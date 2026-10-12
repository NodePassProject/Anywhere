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
        var connection: ProxyConnection?
    }
    private let state = Mutex(State())

    func bind(_ connection: ProxyConnection) -> Bool {
        let accepted = state.withLock { state in
            guard !state.cancelled else { return false }
            state.connection = connection
            return true
        }
        if !accepted { connection.cancel() }
        return accepted
    }

    func cancel() {
        let connection = state.withLock { state -> ProxyConnection? in
            guard !state.cancelled else { return nil }
            state.cancelled = true
            let connection = state.connection
            state.connection = nil
            return connection
        }
        connection?.cancel()
    }
}

nonisolated final class NowhereClient: Sendable {
    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let key: String
        let morph: Bool
        let chain: [ProxyConfiguration]
    }

    private struct RegistryState {
        var entries: [Key: NowhereClient] = [:]
        var pending: [Key: Task<NowhereClient, Error>] = [:]
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

    static func shared(for configuration: NowhereRuntimeConfiguration) throws -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            morph: configuration.morph,
            chain: []
        )
        return try registry.withLock { state in
            guard !state.sealed else { throw AnywhereError.transport(.terminated) }
            if let existing = state.entries[key] { return existing }
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
        configuration: NowhereRuntimeConfiguration,
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
        configuration: NowhereRuntimeConfiguration,
        chain: [ProxyConfiguration],
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            morph: configuration.morph,
            chain: chain
        )

        enum Decision { case existing(NowhereClient); case join(Task<NowhereClient, Error>) }
        let decision: Decision = try registry.withLock { state in
            guard !state.sealed else { throw AnywhereError.transport(.terminated) }
            if let client = state.entries[key] { return .existing(client) }
            if let inFlight = state.pending[key] { return .join(inFlight) }
            let buildEpoch = state.epoch
            let task = Task<NowhereClient, Error> {
                try await Self.buildChained(key: key, configuration: configuration,
                                            buildEpoch: buildEpoch,
                                            builder: builder)
            }
            state.pending[key] = task
            return .join(task)
        }
        switch decision {
        case .existing(let client):
            return client
        case .join(let task):
            return try await nowhereCancellableValue(of: task)
        }
    }

    private static func buildChained(
        key: Key,
        configuration: NowhereRuntimeConfiguration,
        buildEpoch: UInt64,
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> NowhereClient {
        let builderResult: Result<(QUICDatagramTransport, [ProxyClient]), Error>
        do { builderResult = .success(try await builder()) }
        catch { builderResult = .failure(error) }

        typealias Discard = (Result<NowhereClient, Error>, QUICDatagramTransport?, [ProxyClient])
        let (outcome, staleTransport, staleHolders): Discard = registry.withLock { state in
            guard state.epoch == buildEpoch, !state.sealed else {
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

    private let configuration: NowhereRuntimeConfiguration
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
        configuration: NowhereRuntimeConfiguration,
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
        let acquired: Acquired = try state.withLock { state in
            guard !state.retired else { return .transportSpent }
            if let existing = state.session, !existing.isClosed, !existing.isDraining {
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

            let newSession = try NowhereSession(configuration: configuration, transport: transport)
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
            newSession.setOnClose { [self, weak newSession] in
                guard let newSession else { return }
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

    func openTCP(
        destination: NowhereProtocol.Target,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws -> ProxyConnection {
        let session = try await acquireSession()
        let connection = NowhereConnection(
            session: session,
            destination: destination,
            initialData: initialData
        )
        guard attempt?.bind(connection) != false else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await connection.open()
            return connection
        } catch {
            connection.cancel()
            throw error
        }
    }

    func openUDP(
        destination: NowhereProtocol.Target,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws -> ProxyConnection {
        let session = try await acquireSession()
        let connection = NowhereUDPConnection(
            session: session,
            destination: destination
        )
        guard attempt?.bind(connection) != false else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await connection.open()
            return connection
        } catch {
            connection.cancel()
            throw error
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

    static func closeAll() {
        let (clients, pending): ([NowhereClient], [Task<NowhereClient, Error>]) = registry.withLock { state in
            let clients = Array(state.entries.values)
            state.entries.removeAll(keepingCapacity: false)
            let pending = Array(state.pending.values)
            state.pending.removeAll(keepingCapacity: false)
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
        }
    }
}

nonisolated func nowhereCancellableValue<Value: Sendable>(of task: Task<Value, Error>) async throws -> Value {
    try Task.checkCancellation()
    let inbox = AsyncInbox<Value>()
    let waiter = Task<Void, Never> {
        do {
            inbox.yield(try await task.value)
            inbox.finish()
        } catch {
            inbox.finish(throwing: error)
        }
    }
    defer { waiter.cancel() }
    guard let value = try await inbox.next() else { throw CancellationError() }
    try Task.checkCancellation()
    return value
}
