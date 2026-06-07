//
//  NowhereClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

nonisolated final class NowhereClient {

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let key: String
        let chainSignature: String
    }

    private static let registryLock = UnfairLock()
    private static var registry: [Key: NowhereClient] = [:]
    private static var pending: [Key: [(Result<NowhereClient, Error>) -> Void]] = [:]

    static func shared(for configuration: NowhereConfiguration) -> NowhereClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            key: configuration.key,
            chainSignature: ""
        )
        registryLock.lock()
        defer { registryLock.unlock() }
        if let existing = registry[key] { return existing }
        let client = NowhereClient(
            configuration: configuration,
            transport: nil,
            chainHolders: [],
            poolKey: key
        )
        registry[key] = client
        return client
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
            let outcome: Result<NowhereClient, Error>
            switch builderResult {
            case .success(let (transport, holders)):
                let client = NowhereClient(
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

    private let configuration: NowhereConfiguration
    private let transport: QUICDatagramTransport?
    private var chainHolders: [ProxyClient]
    private let poolKey: Key?
    private let lock = UnfairLock()
    private var session: NowhereSession?
    private var transportConsumed = false

    private init(
        configuration: NowhereConfiguration,
        transport: QUICDatagramTransport?,
        chainHolders: [ProxyClient],
        poolKey: Key?
    ) {
        self.configuration = configuration
        self.transport = transport
        self.chainHolders = chainHolders
        self.poolKey = poolKey
    }

    private func acquireSession(isDefaultProxy: Bool, completion: @escaping (Result<NowhereSession, Error>) -> Void) {
        lock.lock()
        if let existing = session, !existing.poolIsClosed {
            lock.unlock()
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        }

        if transport != nil && transportConsumed {
            if let key = poolKey {
                Self.registryLock.lock()
                if Self.registry[key] === self {
                    Self.registry.removeValue(forKey: key)
                }
                Self.registryLock.unlock()
            }
            lock.unlock()
            completion(.failure(NowhereError.streamClosed))
            return
        }

        let newSession = NowhereSession(configuration: configuration, transport: transport)
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
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let conn = NowhereConnection(session: session, destination: destination)
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
                let conn = NowhereUDPConnection(session: session, destination: destination)
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

    private static func isStaleSessionError(_ error: Error) -> Bool {
        guard let nErr = error as? NowhereError else { return false }
        switch nErr {
        case .notReady, .streamClosed: return true
        default: return false
        }
    }

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

    static func closeAll() {
        registryLock.lock()
        let clients = Array(registry.values)
        registryLock.unlock()
        for client in clients {
            client.invalidateSession()
        }
    }
}
