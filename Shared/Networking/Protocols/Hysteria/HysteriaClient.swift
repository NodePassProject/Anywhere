//
//  HysteriaClient.swift
//  Anywhere
//
//  Created by NodePassProject on 4/18/26.
//

import Foundation

/// Reconnectable wrapper around `HysteriaSession`. One active session per
/// pool entry; dead sessions clear themselves via `onClose` and direct
/// callers reconnect on the next acquire. Chained entries are removed on
/// close since their transport is one-shot.
///
/// Use ``shared(for:)`` for direct dials, ``acquireChained(...)`` for
/// pooled chained dials, ``chained(configuration:transport:)`` for a
/// chain-link Hysteria handed a per-flow inbound tunnel.
nonisolated final class HysteriaClient {

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let sni: String
        let password: String
        /// Empty for direct entries; colon-joined chain hop IDs otherwise.
        let chainSignature: String
    }

    private static let registryLock = UnfairLock()
    private static var registry: [Key: HysteriaClient] = [:]
    /// Coalesces concurrent first-time builds for the same key.
    private static var pending: [Key: [(Result<HysteriaClient, Error>) -> Void]] = [:]

    static func shared(for configuration: HysteriaConfiguration) -> HysteriaClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.sni,
            password: configuration.password,
            chainSignature: ""
        )
        registryLock.lock()
        defer { registryLock.unlock() }
        if let existing = registry[key] { return existing }
        let client = HysteriaClient(
            configuration: configuration,
            transport: nil,
            chainHolders: [],
            poolKey: key
        )
        registry[key] = client
        return client
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
    /// On cache miss `builder` produces the chain's transport and the chain
    /// hop ProxyClients that the new entry takes ownership of. Concurrent
    /// misses coalesce to a single build.
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

        registryLock.lock()
        if let existing = registry[key] {
            registryLock.unlock()
            completion(.success(existing))
            return
        }
        if pending[key] != nil {
            // Build already in flight — queue this completion for the same result.
            pending[key]?.append(completion)
            registryLock.unlock()
            return
        }
        pending[key] = [completion]
        registryLock.unlock()

        builder { builderResult in
            Self.registryLock.lock()
            let queued = Self.pending.removeValue(forKey: key) ?? []
            let outcome: Result<HysteriaClient, Error>
            switch builderResult {
            case .success(let (transport, holders)):
                let client = HysteriaClient(
                    configuration: configuration,
                    transport: transport,
                    chainHolders: holders,
                    poolKey: key
                )
                Self.registry[key] = client
                outcome = .success(client)
            case .failure(let error):
                outcome = .failure(error)
            }
            Self.registryLock.unlock()
            for cb in queued { cb(outcome) }
        }
    }

    private let configuration: HysteriaConfiguration
    /// Set for chained clients; `nil` for direct dials that use a kernel socket.
    private let transport: QUICDatagramTransport?
    /// Chain hop ProxyClients retained by a pooled chained entry.
    private var chainHolders: [ProxyClient]
    /// Pool-registry key. `nil` for per-call chained clients.
    private let poolKey: Key?
    private let lock = UnfairLock()
    private var session: HysteriaSession?
    /// `true` once a session has consumed the one-shot chained transport.
    private var transportConsumed: Bool = false

    private init(
        configuration: HysteriaConfiguration,
        transport: QUICDatagramTransport?,
        chainHolders: [ProxyClient],
        poolKey: Key?
    ) {
        self.configuration = configuration
        self.transport = transport
        self.chainHolders = chainHolders
        self.poolKey = poolKey
    }

    private func acquireSession(isDefaultProxy: Bool, completion: @escaping (Result<HysteriaSession, Error>) -> Void) {
        lock.lock()
        if let existing = session, !existing.poolIsClosed {
            lock.unlock()
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        }

        // Chained transport is one-shot; once consumed, drop the pool
        // entry inline so subsequent `acquireChained` calls cache-miss
        // and build a fresh chain. Without this, the entry lingers until
        // `handleSessionClose` fires async, and acquires landing in that
        // window all hand out this dead client. Lock order is instance →
        // registry, matching `handleSessionClose`.
        if transport != nil && transportConsumed {
            if let key = poolKey {
                Self.registryLock.lock()
                if Self.registry[key] === self {
                    Self.registry.removeValue(forKey: key)
                }
                Self.registryLock.unlock()
            }
            lock.unlock()
            completion(.failure(HysteriaError.streamClosed))
            return
        }

        let newSession = HysteriaSession(configuration: configuration, transport: transport)
        session = newSession
        if transport != nil { transportConsumed = true }
        lock.unlock()

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

    /// Handles a session closing. Chained entries also drop chain holders
    /// and unregister from the pool. The registry removal happens under the
    /// per-instance lock so concurrent `acquireChained` never sees an entry
    /// whose per-instance state has already been cleared. Lock order is
    /// instance → registry; no other path takes them in the reverse order.
    private func handleSessionClose(_ closedSession: HysteriaSession) {
        lock.lock()
        guard session === closedSession else {
            lock.unlock()
            return
        }
        session = nil
        let holders = chainHolders
        chainHolders = []
        if transport != nil, let key = poolKey {
            Self.registryLock.lock()
            if Self.registry[key] === self {
                Self.registry.removeValue(forKey: key)
            }
            Self.registryLock.unlock()
        }
        lock.unlock()

        for client in holders {
            client.cancel()
        }
    }

    func openTCP(destination: String, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        openTCP(destination: destination, retriesLeft: 1, isDefaultProxy: isDefaultProxy, completion: completion)
    }

    private func openTCP(destination: String, retriesLeft: Int, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        // The idle-close timer can fire between `acquireSession` checking
        // `poolIsClosed` and the stream actually opening, so a single retry
        // with a fresh session covers the race window. Errors from both
        // `ensureReady` (caught here) and `conn.open` (caught below) can
        // surface the race.
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let conn = HysteriaConnection(session: session, destination: destination)
                conn.open { error in
                    if let error {
                        conn.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                        } else {
                            completion(.failure(error))
                        }
                    } else {
                        completion(.success(conn))
                    }
                }
            }
        }
    }

    func openUDP(destination: String, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        openUDP(destination: destination, retriesLeft: 1, isDefaultProxy: isDefaultProxy, completion: completion)
    }

    private func openUDP(destination: String, retriesLeft: Int, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        // See `openTCP(retriesLeft:)` for the race rationale.
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openUDP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let conn = HysteriaUDPConnection(session: session, destination: destination)
                conn.open { error in
                    if let error {
                        conn.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openUDP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                        } else {
                            completion(.failure(error))
                        }
                    } else {
                        completion(.success(conn))
                    }
                }
            }
        }
    }

    /// True for failures that indicate the cached session went away between
    /// the `poolIsClosed` check and the stream-open. `udpNotSupported` is
    /// excluded because it's a permanent server-side property.
    private static func isStaleSessionError(_ error: Error) -> Bool {
        guard let hErr = error as? HysteriaError else { return false }
        switch hErr {
        case .notReady, .streamClosed: return true
        default: return false
        }
    }

    /// Synchronously drops the cached session (used by `closeAll` on device
    /// wake). Chained entries also drop chain holders and unregister. See
    /// `handleSessionClose` for the lock-order rationale.
    private func invalidateSession() {
        lock.lock()
        let current = session
        session = nil
        let holders = chainHolders
        chainHolders = []
        if transport != nil, let key = poolKey {
            Self.registryLock.lock()
            if Self.registry[key] === self {
                Self.registry.removeValue(forKey: key)
            }
            Self.registryLock.unlock()
        }
        lock.unlock()

        current?.close()

        for client in holders {
            client.cancel()
        }
    }

    /// Invalidates every pooled session. Used on device wake to drop
    /// QUIC connections whose underlying UDP socket the kernel tore down
    /// during sleep — otherwise the first post-wake request reuses the
    /// dead session and stalls until ngtcp2's idle timeout fires.
    static func closeAll() {
        registryLock.lock()
        let clients = Array(registry.values)
        registryLock.unlock()
        for client in clients {
            client.invalidateSession()
        }
    }
}
