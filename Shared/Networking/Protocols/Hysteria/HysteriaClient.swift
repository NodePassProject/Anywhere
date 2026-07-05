//
//  HysteriaClient.swift
//  Anywhere
//
//  Created by NodePassProject on 4/18/26.
//

import Foundation
import Synchronization

/// Reconnectable wrapper around `HysteriaSession`; dead sessions clear via
/// `onClose` and callers reconnect on the next acquire. Chained entries are
/// removed on close because their transport is one-shot.
nonisolated final class HysteriaClient {

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let sni: String
        let password: String
        /// Empty for direct entries; colon-joined chain hop IDs otherwise.
        let chainSignature: String
    }

    private struct RegistryState {
        var entries: [Key: HysteriaClient] = [:]
        /// Coalesces concurrent first-time builds for the same key.
        var pending: [Key: [(Result<HysteriaClient, Error>) -> Void]] = [:]
    }
    private static let registry = Mutex(RegistryState())

    static func shared(for configuration: HysteriaConfiguration) -> HysteriaClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.sni,
            password: configuration.password,
            chainSignature: ""
        )
        return registry.withLock { state in
            if let existing = state.entries[key] { return existing }
            let client = HysteriaClient(
                configuration: configuration,
                transport: nil,
                chainHolders: [],
                poolKey: key
            )
            state.entries[key] = client
            return client
        }
    }

    /// Non-pooled client bound to a per-flow UDP-relay transport (used when
    /// Hysteria is itself a chain link).
    static func chained(
        configuration: HysteriaConfiguration,
        transport: QUICDatagramTransport
    ) -> HysteriaClient {
        HysteriaClient(
            configuration: configuration,
            transport: transport,
            chainHolders: [],
            poolKey: nil
        )
    }

    /// Pooled chained dial. Shares one client per `(server, chainSignature)`.
    /// Concurrent cache misses coalesce to a single build.
    static func acquireChained(
        configuration: HysteriaConfiguration,
        chainSignature: String,
        builder: @escaping (@escaping (Result<(QUICDatagramTransport, [ProxyClient]), Error>) -> Void) -> Void,
        completion: @escaping (Result<HysteriaClient, Error>) -> Void
    ) {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.sni,
            password: configuration.password,
            chainSignature: chainSignature
        )

        // Fast paths resolve under the lock; the completion itself fires outside.
        var existing: HysteriaClient?
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
            let (queued, outcome): ([(Result<HysteriaClient, Error>) -> Void], Result<HysteriaClient, Error>) = Self.registry.withLock { state in
                let queued = state.pending.removeValue(forKey: key) ?? []
                switch builderResult {
                case .success(let (transport, holders)):
                    let client = HysteriaClient(
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

    private let configuration: HysteriaConfiguration
    /// Set for chained clients; `nil` for direct dials that use the direct UDP carrier.
    private let transport: QUICDatagramTransport?
    /// Pool-registry key. `nil` for per-call chained clients.
    private let poolKey: Key?

    private struct SessionState {
        var session: HysteriaSession? = nil
        /// `true` once a session has consumed the one-shot chained transport.
        var transportConsumed = false
        /// Chain hop ProxyClients retained by a pooled chained entry.
        var chainHolders: [ProxyClient]
    }
    private let state: Mutex<SessionState>

    private init(
        configuration: HysteriaConfiguration,
        transport: QUICDatagramTransport?,
        chainHolders: [ProxyClient],
        poolKey: Key?
    ) {
        self.configuration = configuration
        self.transport = transport
        self.state = Mutex(SessionState(chainHolders: chainHolders))
        self.poolKey = poolKey
    }

    private func acquireSession(isDefaultProxy: Bool, completion: @escaping (Result<HysteriaSession, Error>) -> Void) {
        enum Acquired {
            case reuse(HysteriaSession)
            case transportSpent
            case fresh(HysteriaSession)
        }
        let acquired: Acquired = state.withLock { state in
            if let existing = state.session, !existing.isClosed {
                return .reuse(existing)
            }

            // Chained transport is one-shot; drop the pool entry inline so acquires
            // racing `handleSessionClose` don't get this dead client.
            // Lock order: instance → registry.
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

            let newSession = HysteriaSession(configuration: configuration, transport: transport)
            state.session = newSession
            if transport != nil { state.transportConsumed = true }
            return .fresh(newSession)
        }

        let newSession: HysteriaSession
        switch acquired {
        case .reuse(let existing):
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        case .transportSpent:
            completion(.failure(HysteriaError.streamClosed))
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
                completion(.failure(HysteriaError.connectionFailed("Session deallocated")))
                return
            }
            if let error { completion(.failure(error)) }
            else {
                handshakeTimer.stop()
                completion(.success(newSession))
            }
        }
    }

    /// Clears the closed session and, for chained entries, cancels chain
    /// holders and unregisters from the pool. Lock order: instance → registry.
    private func handleSessionClose(_ closedSession: HysteriaSession) {
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

    private func openTCP(destination: String, retriesLeft: Int, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        // The idle-close timer can fire between `isClosed` check and
        // stream open; one retry with a fresh session covers that window.
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let connection = HysteriaConnection(session: session, destination: destination)
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
                let connection = HysteriaUDPConnection(session: session, destination: destination)
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

    /// True for failures meaning the cached session went away mid-acquire;
    /// `udpNotSupported` is excluded as a permanent server-side property.
    private static func isStaleSessionError(_ error: Error) -> Bool {
        guard let hysteriaError = error as? HysteriaError else { return false }
        switch hysteriaError {
        case .notReady, .streamClosed: return true
        default: return false
        }
    }

    /// Synchronously drops the cached session. For chained entries also
    /// cancels chain holders and unregisters from the pool.
    private func invalidateSession() {
        let (current, holders): (HysteriaSession?, [ProxyClient]) = state.withLock { state in
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

    /// Invalidates every pooled session — the kernel tears down UDP sockets
    /// during sleep, and a reused dead session stalls until ngtcp2's idle timeout.
    static func closeAll() {
        let clients = registry.withLock { state in Array(state.entries.values) }
        for client in clients {
            client.invalidateSession()
        }
    }
}

extension HysteriaClient {
    static let pool: TransportPool = Pool()
    private final class Pool: TransportPool {
        func reclaim() { HysteriaClient.closeAll() }
    }
}
