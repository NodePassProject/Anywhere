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
nonisolated final class HysteriaClient: Sendable {

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
        /// Coalesces concurrent first-time builds for the same key: the leader stores its in-flight
        /// build task here and every joiner awaits it, so there is no waiter array of continuations.
        var pending: [Key: Task<HysteriaClient, Error>] = [:]
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
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> HysteriaClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.sni,
            password: configuration.password,
            chainSignature: chainSignature
        )

        enum Decision { case existing(HysteriaClient); case join(Task<HysteriaClient, Error>) }
        let decision: Decision = registry.withLock { state in
            if let client = state.entries[key] { return .existing(client) }
            if let inFlight = state.pending[key] { return .join(inFlight) }
            let task = Task<HysteriaClient, Error> {
                try await Self.buildChained(key: key, configuration: configuration, builder: builder)
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
    private static func buildChained(
        key: Key,
        configuration: HysteriaConfiguration,
        builder: @escaping @Sendable () async throws -> (QUICDatagramTransport, [ProxyClient])
    ) async throws -> HysteriaClient {
        let builderResult: Result<(QUICDatagramTransport, [ProxyClient]), Error>
        do { builderResult = .success(try await builder()) }
        catch { builderResult = .failure(error) }

        let outcome: Result<HysteriaClient, Error> = registry.withLock { state in
            state.pending.removeValue(forKey: key)
            switch builderResult {
            case .success(let (transport, holders)):
                let client = HysteriaClient(
                    configuration: configuration,
                    transport: transport,
                    chainHolders: holders,
                    poolKey: key
                )
                state.entries[key] = client
                return .success(client)
            case .failure(let error):
                return .failure(error)
            }
        }
        return try outcome.get()
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

    private func acquireSession(isDefaultProxy: Bool) async throws -> HysteriaSession {
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

        switch acquired {
        case .reuse(let existing):
            try await existing.ensureReady()
            return existing
        case .transportSpent:
            throw AnywhereError.proxy(.hysteria, .streamClosed)
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

    // The idle-close timer can fire between the `isClosed` check and stream open; one retry
    // with a fresh session covers that window. Session acquire and stream open share the budget.
    func openTCP(destination: String, isDefaultProxy: Bool) async throws -> ProxyConnection {
        var retriesLeft = 1
        while true {
            let session: HysteriaSession
            do {
                session = try await acquireSession(isDefaultProxy: isDefaultProxy)
            } catch {
                if retriesLeft > 0, Self.isStaleSessionError(error) { retriesLeft -= 1; continue }
                throw error
            }
            let connection = HysteriaConnection(session: session, destination: destination)
            do {
                try await connection.open()
                return connection
            } catch {
                connection.cancel()
                if retriesLeft > 0, Self.isStaleSessionError(error) { retriesLeft -= 1; continue }
                throw error
            }
        }
    }

    func openUDP(destination: String, isDefaultProxy: Bool) async throws -> ProxyConnection {
        var retriesLeft = 1
        while true {
            let session: HysteriaSession
            do {
                session = try await acquireSession(isDefaultProxy: isDefaultProxy)
            } catch {
                if retriesLeft > 0, Self.isStaleSessionError(error) { retriesLeft -= 1; continue }
                throw error
            }
            let connection = HysteriaUDPConnection(session: session, destination: destination)
            do {
                try await connection.open()
                return connection
            } catch {
                connection.cancel()
                if retriesLeft > 0, Self.isStaleSessionError(error) { retriesLeft -= 1; continue }
                throw error
            }
        }
    }

    /// True for failures meaning the cached session went away mid-acquire;
    /// `udpNotSupported` is excluded as a permanent server-side property.
    private static func isStaleSessionError(_ error: Error) -> Bool {
        guard case AnywhereError.proxy(.hysteria, let failure) = error else { return false }
        switch failure {
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

nonisolated extension HysteriaClient {
    static let pool: TransportPool = Pool()
    private final class Pool: TransportPool {
        func reclaim() { HysteriaClient.closeAll() }
    }
}
