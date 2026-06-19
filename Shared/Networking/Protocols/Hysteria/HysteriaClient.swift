//
//  HysteriaClient.swift
//  Anywhere
//
//  Created by NodePassProject on 4/18/26.
//

import Foundation

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

        registryLock.lock()
        if let existing = registry[key] {
            registryLock.unlock()
            completion(.success(existing))
            return
        }
        if pending[key] != nil {
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
        if let existing = session, !existing.isClosed {
            lock.unlock()
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        }

        // Chained transport is one-shot; drop the pool entry inline so acquires
        // racing `handleSessionClose` don't get this dead client.
        // Lock order: instance → registry.
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

    /// Clears the closed session and, for chained entries, cancels chain
    /// holders and unregisters from the pool. Lock order: instance → registry.
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

    /// Invalidates every pooled session — the kernel tears down UDP sockets
    /// during sleep, and a reused dead session stalls until ngtcp2's idle timeout.
    static func closeAll() {
        registryLock.lock()
        let clients = Array(registry.values)
        registryLock.unlock()
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
