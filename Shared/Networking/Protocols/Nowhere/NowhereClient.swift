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
        var connections: [ObjectIdentifier: ProxyConnection] = [:]
        var cancelled = false
        var resolved = false
        var deadline: Task<Void, Never>?
        var earlyDataWriteStarted = false
    }
    private let state = Mutex(State())

    /// Binds the concrete half as soon as it exists. A cancellation that won
    /// the race closes it before any late success can escape.
    func bind(_ connection: ProxyConnection) -> Bool {
        let accepted = state.withLock { state in
            guard !state.cancelled else { return false }
            state.connections[ObjectIdentifier(connection)] = connection
            return true
        }
        if !accepted { connection.cancel() }
        return accepted
    }

    var isCancelled: Bool { state.withLock { $0.cancelled } }

    func markEarlyDataWriteStarted() {
        state.withLock { $0.earlyDataWriteStarted = true }
    }

    var hasStartedEarlyDataWrite: Bool { state.withLock { $0.earlyDataWriteStarted } }

    func armDeadline(at deadline: DispatchTime, handler: @escaping @Sendable () -> Void) {
        // A Task starts on creation, so only spin one up if we might still arm.
        let shouldArm = state.withLock { state -> Bool in !state.resolved }
        guard shouldArm else { return }

        let task = Task { [weak self] in
            let nowNanos = DispatchTime.now().uptimeNanoseconds
            let deadlineNanos = deadline.uptimeNanoseconds
            let delayNanos = deadlineNanos > nowNanos ? deadlineNanos - nowNanos : 0
            try? await Task.sleep(nanoseconds: delayNanos)
            guard !Task.isCancelled, let self, self.claimResult() else { return }
            self.cancel()
            handler()
        }

        let armed = state.withLock { state -> Bool in
            guard !state.resolved else { return false }
            state.deadline?.cancel()
            state.deadline = task
            return true
        }
        if !armed { task.cancel() }
    }

    func claimResult() -> Bool {
        let (accepted, deadline): (Bool, Task<Void, Never>?) = state.withLock { state in
            guard !state.resolved else { return (false, nil) }
            state.resolved = true
            let deadline = state.deadline
            state.deadline = nil
            return (true, deadline)
        }
        deadline?.cancel()
        return accepted
    }

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
        let chainSignature: String
        let sessionID: Data
    }

    private struct RegistryState {
        var entries: [Key: NowhereClient] = [:]
        /// Coalesces concurrent first-time builds for the same key: the leader stores its in-flight
        /// build task here and every joiner awaits it, so there is no waiter array of continuations.
        var pending: [Key: Task<NowhereClient, Error>] = [:]
        var epoch: UInt64 = 0
    }
    private static let registry = Mutex(RegistryState())

    static func shared(for configuration: NowhereConfiguration) -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            uplink: configuration.uplink,
            downlink: configuration.downlink,
            sni: configuration.tls.serverName,
            alpn: configuration.alpn,
            chainSignature: "",
            sessionID: configuration.sessionID
        )
        return registry.withLock { state in
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
        chainSignature: String,
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
            chainSignature: chainSignature,
            sessionID: configuration.sessionID
        )

        enum Decision { case existing(NowhereClient); case join(Task<NowhereClient, Error>) }
        let decision: Decision = registry.withLock { state in
            if let client = state.entries[key] { return .existing(client) }
            if let inFlight = state.pending[key] { return .join(inFlight) }
            let buildEpoch = state.epoch
            let task = Task<NowhereClient, Error> {
                try await Self.buildChained(key: key, configuration: configuration,
                                            buildEpoch: buildEpoch, builder: builder)
            }
            state.pending[key] = task           // our task leads; joiners await it
            return .join(task)
        }
        switch decision {
        case .existing(let client):
            return client
        case .join(let task):
            return try await task.value
        }
    }

    /// Runs the coalesced build once for the leader; joiners share its result via `task.value`.
    /// Clears the pending slot and honors the epoch guard (a `closeAll` mid-build discards the result).
    private static func buildChained(
        key: Key,
        configuration: NowhereConfiguration,
        buildEpoch: UInt64,
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> NowhereClient {
        let builderResult: Result<(QUICDatagramTransport, [ProxyClient]), Error>
        do { builderResult = .success(try await builder()) }
        catch { builderResult = .failure(error) }

        let (outcome, discarded): (Result<NowhereClient, Error>, [ProxyClient]) = registry.withLock { state in
            state.pending.removeValue(forKey: key)
            guard state.epoch == buildEpoch else {
                let discarded = (try? builderResult.get())?.1 ?? []
                return (.failure(AnywhereError.proxy(.nowhere, .streamClosed)), discarded)
            }
            switch builderResult {
            case .success(let (transport, holders)):
                let client = NowhereClient(
                    configuration: configuration,
                    transport: transport,
                    chainHolders: holders,
                    poolKey: key
                )
                state.entries[key] = client
                return (.success(client), [])
            case .failure(let error):
                return (.failure(error), [])
            }
        }
        for client in discarded { await client.cancel() }
        return try outcome.get()
    }

    private let configuration: NowhereConfiguration
    private let transport: QUICDatagramTransport?
    private let poolKey: Key?

    private struct SessionState {
        var session: NowhereSession? = nil
        var transportConsumed = false
        var chainHolders: [ProxyClient]
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

    private func acquireSession(isDefaultProxy: Bool) async throws -> NowhereSession {
        enum Acquired {
            case reuse(NowhereSession)
            case transportSpent
            case fresh(NowhereSession)
        }
        let acquired: Acquired = state.withLock { state in
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

            var handshakeTimer = MetricTimer(.handshakeNoDial)
            handshakeTimer.enabled = isDefaultProxy
            handshakeTimer.start()

            try await newSession.ensureReady()
            handshakeTimer.stop()
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
        attempt: NowhereFlowOpenAttempt? = nil,
        isDefaultProxy: Bool
    ) async throws -> ProxyConnection {
        let session: NowhereSession
        do {
            session = try await acquireSession(isDefaultProxy: isDefaultProxy)
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
        attempt: NowhereFlowOpenAttempt? = nil,
        isDefaultProxy: Bool
    ) async throws -> ProxyConnection {
        let session: NowhereSession
        do {
            session = try await acquireSession(isDefaultProxy: isDefaultProxy)
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

    /// Invalidates only the direct shared client identified by this transport
    /// configuration. Used when the TCP half of an asymmetric flow reports
    /// SessionReplaced before the QUIC sibling observes its session close.
    static func invalidateSharedSession(for configuration: NowhereConfiguration) {
        shared(for: configuration).invalidateSession()
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
            client.invalidateSession()
        }
    }
}

nonisolated extension NowhereClient {
    static let pool: TransportPool = Pool()
    private final class Pool: TransportPool {
        func reclaim() {
            NowhereClient.closeAll()
            NowhereTCPConnectionPoolRegistry.shared.closeAll()
            NowhereTransportIdentityRegistry.shared.reset()
        }
    }
}
