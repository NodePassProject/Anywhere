//
//  NowhereClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereFlowOpenAttempt {
    private struct State {
        var connections: [ObjectIdentifier: ProxyConnection] = [:]
        var cancelled = false
        var resolved = false
        var deadline: DispatchWorkItem?
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

    func armDeadline(at deadline: DispatchTime, handler: @escaping () -> Void) {
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.claimResult() else { return }
            self.cancel()
            handler()
        }
        let shouldArm = state.withLock { state in
            guard !state.resolved else { return false }
            state.deadline?.cancel()
            state.deadline = work
            return true
        }
        if shouldArm {
            NowhereFlowOpenAttempt.deadlineQueue.asyncAfter(
                deadline: deadline,
                execute: work
            )
        }
    }

    func claimResult() -> Bool {
        let (accepted, deadline): (Bool, DispatchWorkItem?) = state.withLock { state in
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

    private static let deadlineQueue = DispatchQueue(
        label: "com.argsment.Anywhere.NowhereLogicalFlowDeadline",
        qos: .utility
    )
}

nonisolated final class NowhereClient {

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let key: String
        let spec: String?
        let uplink: NowhereNetwork
        let downlink: NowhereNetwork
        let sni: String
        let alpn: String
        let chainSignature: String
        let sessionID: Data
    }

    private struct RegistryState {
        var entries: [Key: NowhereClient] = [:]
        /// Coalesces concurrent first-time builds for the same key.
        var pending: [Key: [(Result<NowhereClient, Error>) -> Void]] = [:]
        var epoch: UInt64 = 0
    }
    private static let registry = Mutex(RegistryState())

    static func shared(for configuration: NowhereConfiguration) -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            spec: configuration.spec,
            uplink: configuration.uplink,
            downlink: configuration.downlink,
            sni: configuration.tls.serverName,
            alpn: configuration.protocolSpec.effectiveALPN,
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
        builder: @escaping (@escaping (Result<(QUICDatagramTransport, [ProxyClient]), Error>) -> Void) -> Void,
        completion: @escaping (Result<NowhereClient, Error>) -> Void
    ) {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            spec: configuration.spec,
            uplink: configuration.uplink,
            downlink: configuration.downlink,
            sni: configuration.tls.serverName,
            alpn: configuration.protocolSpec.effectiveALPN,
            chainSignature: chainSignature,
            sessionID: configuration.sessionID
        )

        // Fast paths resolve under the lock; the completion itself fires outside.
        var existing: NowhereClient?
        var shouldBuild = false
        var buildEpoch: UInt64 = 0
        registry.withLock { state in
            if let client = state.entries[key] {
                existing = client
                return
            }
            if state.pending[key] != nil {
                state.pending[key]?.append(completion)
                return
            }
            state.pending[key] = [completion]
            buildEpoch = state.epoch
            shouldBuild = true
        }
        if let existing {
            completion(.success(existing))
            return
        }
        guard shouldBuild else { return }

        builder { builderResult in
            // Registry insert and waiter drain happen atomically; the coalesced
            // completions fire after the lock is released.
            let (queued, outcome, discarded): (
                [(Result<NowhereClient, Error>) -> Void],
                Result<NowhereClient, Error>,
                [ProxyClient]
            ) = Self.registry.withLock { state in
                let queued = state.pending.removeValue(forKey: key) ?? []
                guard state.epoch == buildEpoch else {
                    let discarded: [ProxyClient]
                    if case .success((_, let holders)) = builderResult {
                        discarded = holders
                    } else {
                        discarded = []
                    }
                    return (queued, .failure(NowhereError.streamClosed), discarded)
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
                    return (queued, .success(client), [])
                case .failure(let error):
                    return (queued, .failure(error), [])
                }
            }
            for client in discarded { client.cancel() }
            for callback in queued { callback(outcome) }
        }
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

    private func acquireSession(isDefaultProxy: Bool, completion: @escaping (Result<NowhereSession, Error>) -> Void) {
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

        let newSession: NowhereSession
        switch acquired {
        case .reuse(let existing):
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        case .transportSpent:
            completion(.failure(NowhereError.streamClosed))
            return
        case .fresh(let fresh):
            newSession = fresh
        }

        newSession.onClose = { [weak self, weak newSession] in
            guard let self, let newSession else { return }
            self.handleSessionClose(newSession)
        }
        
        var handshakeTimer = MetricTimer(.handshakeNoDial)
        handshakeTimer.enabled = isDefaultProxy
        handshakeTimer.start()

        newSession.ensureReady { [weak newSession, handshakeTimer] error in
            guard let newSession else {
                completion(.failure(NowhereError.connectionFailed("Session deallocated")))
                return
            }
            if let error { completion(.failure(error)) }
            else {
                handshakeTimer.stop()
                completion(.success(newSession))
            }
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
        destination: String,
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt? = nil,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if Self.isStaleSessionError(error) { self?.invalidateSession() }
                completion(.failure(error))
            case .success(let session):
                let connection = NowhereConnection(
                    session: session,
                    destination: destination,
                    flowHeader: header
                )
                guard attempt?.bind(connection) != false else {
                    completion(.failure(NowhereError.streamClosed))
                    return
                }
                connection.open { error in
                    if let error {
                        connection.cancel()
                        if Self.isStaleSessionError(error) {
                            self?.invalidateSession(ifCurrent: session)
                        }
                        completion(.failure(error))
                    } else {
                        completion(.success(connection))
                    }
                }
            }
        }
    }

    func openUDP(
        destination: String,
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt? = nil,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if Self.isStaleSessionError(error) { self?.invalidateSession() }
                completion(.failure(error))
            case .success(let session):
                let connection = NowhereUDPConnection(
                    session: session,
                    destination: destination,
                    flowHeader: header
                )
                guard attempt?.bind(connection) != false else {
                    completion(.failure(NowhereError.streamClosed))
                    return
                }
                connection.open { error in
                    if let error {
                        connection.cancel()
                        if Self.isStaleSessionError(error) {
                            self?.invalidateSession(ifCurrent: session)
                        }
                        completion(.failure(error))
                    } else {
                        completion(.success(connection))
                    }
                }
            }
        }
    }

    private static func isStaleSessionError(_ error: Error) -> Bool {
        guard let nowhereError = error as? NowhereError else { return false }
        switch nowhereError {
        case .notReady, .streamClosed: return true
        case .flowRejected(.sessionReplaced): return true
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
        let (clients, pending): ([NowhereClient], [(Result<NowhereClient, Error>) -> Void]) = registry.withLock { state in
            let clients = Array(state.entries.values)
            state.entries.removeAll(keepingCapacity: false)
            let pending = state.pending.values.flatMap { $0 }
            state.pending.removeAll(keepingCapacity: false)
            state.epoch &+= 1
            return (clients, pending)
        }
        for callback in pending { callback(.failure(NowhereError.streamClosed)) }
        for client in clients {
            client.invalidateSession()
        }
    }
}

extension NowhereClient {
    static let pool: TransportPool = Pool()
    private final class Pool: TransportPool {
        func reclaim() {
            NowhereClient.closeAll()
            NowhereTCPConnectionPoolRegistry.shared.closeAll()
            NowhereTransportIdentityRegistry.shared.reset()
        }
    }
}
