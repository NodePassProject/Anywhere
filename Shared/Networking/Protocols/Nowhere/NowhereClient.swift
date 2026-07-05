//
//  NowhereClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

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
            let (queued, outcome): ([(Result<NowhereClient, Error>) -> Void], Result<NowhereClient, Error>) = Self.registry.withLock { state in
                let queued = state.pending.removeValue(forKey: key) ?? []
                switch builderResult {
                case .success(let (transport, holders)):
                    let client = NowhereClient(
                        configuration: configuration,
                        transport: transport,
                        chainHolders: holders,
                        poolKey: key
                    )
                    state.entries[key] = client
                    return (queued, .success(client))
                case .failure(let error):
                    return (queued, .failure(error))
                }
            }
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

    func openTCP(destination: String, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        openTCP(destination: destination, retriesLeft: 1, isDefaultProxy: isDefaultProxy, completion: completion)
    }

    func openTCPHalf(
        destination: String,
        header: NowhereProtocol.FlowHeader,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        openTCPHalf(
            destination: destination,
            header: header,
            retriesLeft: 1,
            isDefaultProxy: isDefaultProxy,
            completion: completion
        )
    }

    private func openTCPHalf(
        destination: String,
        header: NowhereProtocol.FlowHeader,
        retriesLeft: Int,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openTCPHalf(
                        destination: destination,
                        header: header,
                        retriesLeft: retriesLeft - 1,
                        isDefaultProxy: isDefaultProxy,
                        completion: completion
                    )
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let connection = NowhereConnection(
                    session: session,
                    destination: destination,
                    flowHeader: header
                )
                connection.open { error in
                    if let error {
                        connection.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openTCPHalf(
                                destination: destination,
                                header: header,
                                retriesLeft: retriesLeft - 1,
                                isDefaultProxy: isDefaultProxy,
                                completion: completion
                            )
                        } else {
                            completion(.failure(error))
                        }
                    } else {
                        completion(.success(connection))
                    }
                }
            }
        }
    }

    private func openTCP(destination: String, retriesLeft: Int, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let connection = NowhereConnection(session: session, destination: destination)
                connection.open { error in
                    if let error {
                        connection.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                        } else {
                            completion(.failure(error))
                        }
                    } else {
                        completion(.success(connection))
                    }
                }
            }
        }
    }

    func openUDP(destination: String, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        openUDP(destination: destination, retriesLeft: 1, isDefaultProxy: isDefaultProxy, completion: completion)
    }

    func openUDP(
        destination: String,
        flowID: UInt64,
        downlink: NowhereNetwork,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        openUDP(
            destination: destination,
            flowID: flowID,
            downlink: downlink,
            retriesLeft: 1,
            isDefaultProxy: isDefaultProxy,
            completion: completion
        )
    }

    private func openUDP(
        destination: String,
        flowID: UInt64,
        downlink: NowhereNetwork,
        retriesLeft: Int,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openUDP(
                        destination: destination,
                        flowID: flowID,
                        downlink: downlink,
                        retriesLeft: retriesLeft - 1,
                        isDefaultProxy: isDefaultProxy,
                        completion: completion
                    )
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let connection = NowhereUDPConnection(
                    session: session,
                    destination: destination,
                    requestedFlowID: flowID,
                    downlink: downlink,
                    reopensExpiredFlow: false
                )
                connection.open { error in
                    if let error {
                        connection.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openUDP(
                                destination: destination,
                                flowID: flowID,
                                downlink: downlink,
                                retriesLeft: retriesLeft - 1,
                                isDefaultProxy: isDefaultProxy,
                                completion: completion
                            )
                        } else {
                            completion(.failure(error))
                        }
                    } else {
                        completion(.success(connection))
                    }
                }
            }
        }
    }

    private func openUDP(destination: String, retriesLeft: Int, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openUDP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let connection = NowhereUDPConnection(session: session, destination: destination)
                connection.open { error in
                    if let error {
                        connection.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openUDP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                        } else {
                            completion(.failure(error))
                        }
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
        default: return false
        }
    }

    private func invalidateSession() {
        let (current, holders): (NowhereSession?, [ProxyClient]) = state.withLock { state in
            let current = state.session
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

        current?.close()

        for client in holders {
            client.cancel()
        }
    }

    static func closeAll() {
        let clients: [NowhereClient] = registry.withLock { state in
            let clients = Array(state.entries.values)
            state.entries.removeAll(keepingCapacity: false)
            return clients
        }
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
