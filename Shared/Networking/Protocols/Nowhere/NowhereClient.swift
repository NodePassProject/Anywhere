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
        let spec: String?
        let sni: String
        let alpn: String
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
            spec: configuration.spec,
            sni: configuration.tls.serverName,
            alpn: configuration.protocolSpec.effectiveALPN,
            chainSignature: ""
        )
        registryLock.lock()
        defer { registryLock.unlock() }
        if let existing = registry[key] {
            existing.updateRoute(configuration.route)
            return existing
        }
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
            spec: configuration.spec,
            sni: configuration.tls.serverName,
            alpn: configuration.protocolSpec.effectiveALPN,
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
    private var routePolicy: NowhereRoutePolicy
    private var session: NowhereSession?
    private var tcpMux: NowhereTCPMuxClient?
    private var retiredTCPMuxes: [NowhereTCPMuxClient] = []
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
        self.routePolicy = configuration.route
    }

    private func currentRoute() -> NowhereRoutePolicy {
        lock.lock()
        defer { lock.unlock() }
        return routePolicy
    }

    private func updateRoute(_ route: NowhereRoutePolicy) {
        lock.lock()
        let previous = routePolicy
        routePolicy = route
        let muxToRetire: NowhereTCPMuxClient?
        if previous.muxEnabled && !route.muxEnabled {
            // Keep old muxed flows alive; new flows get dedicated TCP carriers.
            muxToRetire = tcpMux
            if let muxToRetire {
                retiredTCPMuxes.append(muxToRetire)
            }
            tcpMux = nil
        } else {
            muxToRetire = nil
        }
        lock.unlock()
        muxToRetire?.retireWhenIdle()
    }

    private func acquireSession(isDefaultProxy: Bool, completion: @escaping (Result<NowhereSession, Error>) -> Void) {
        lock.lock()
        if let existing = session, !existing.isClosed {
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
        let muxToClose = tcpMux
        tcpMux = nil
        let retiredMuxes = retiredTCPMuxes
        retiredTCPMuxes.removeAll()
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

        muxToClose?.close()
        for mux in retiredMuxes { mux.close() }
        for client in holders {
            client.cancel()
        }
    }

    func openTCP(destination: String, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        let route = currentRoute()
        guard route.usesTCPLane else {
            openQUICTCP(destination: destination, retriesLeft: 1, isDefaultProxy: isDefaultProxy, completion: completion)
            return
        }
        guard transport == nil else {
            completion(.failure(NowhereError.connectionFailed("TCP lane is unavailable for chained Nowhere")))
            return
        }
        openRoutedTCP(destination: destination, route: route, retriesLeft: 1, isDefaultProxy: isDefaultProxy, completion: completion)
    }

    private func openRoutedTCP(
        destination: String,
        route: NowhereRoutePolicy,
        retriesLeft: Int,
        isDefaultProxy: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] sessionResult in
            guard let self else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            switch sessionResult {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error) {
                    self.openRoutedTCP(destination: destination, route: route, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                self.acquireTCPMux(attachedTo: session, shared: route.muxEnabled) { muxResult in
                    switch muxResult {
                    case .failure(let error):
                        completion(.failure(error))
                    case .success(let mux):
                        if route.tcpUpload == .tcp {
                            mux.openTCP(
                                destination: destination,
                                uploadLane: route.tcpUpload,
                                downloadLane: route.tcpDownload,
                                retainClient: !route.muxEnabled,
                                completion: completion
                            )
                        } else {
                            let conn = NowhereConnection(
                                session: session,
                                destination: destination,
                                uploadLane: route.tcpUpload,
                                downloadLane: route.tcpDownload,
                                tcpDownlinkMux: mux,
                                retainedTCPDownlinkMux: route.muxEnabled ? nil : mux
                            )
                            conn.open { error in
                                if let error {
                                    conn.cancel()
                                    completion(.failure(error))
                                } else {
                                    completion(.success(conn))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func acquireTCPMux(
        attachedTo session: NowhereSession,
        shared: Bool,
        completion: @escaping (Result<NowhereTCPMuxClient, Error>) -> Void
    ) {
        guard shared else {
            let mux = NowhereTCPMuxClient(configuration: configuration, session: session, closeWhenIdle: true)
            mux.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(mux)) }
            }
            return
        }
        lock.lock()
        let existing = tcpMux
        lock.unlock()
        if let existing, !existing.isClosed, existing.isAttached(to: session) {
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        }
        lock.lock()
        if tcpMux !== existing {
            lock.unlock()
            acquireTCPMux(attachedTo: session, shared: shared, completion: completion)
            return
        }
        let oldMux = tcpMux
        if let oldMux {
            retiredTCPMuxes.append(oldMux)
            oldMux.retireWhenIdle()
        }
        let mux = NowhereTCPMuxClient(configuration: configuration, session: session)
        tcpMux = mux
        lock.unlock()
        mux.onClose = { [weak self, weak mux] in
            guard let self, let mux else { return }
            self.handleTCPMuxClose(mux)
        }
        mux.ensureReady { [weak self, weak mux] error in
            guard let mux else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            if let error {
                self?.lock.lock()
                if self?.tcpMux === mux { self?.tcpMux = nil }
                self?.lock.unlock()
                completion(.failure(error))
            } else {
                completion(.success(mux))
            }
        }
    }

    private func handleTCPMuxClose(_ closedMux: NowhereTCPMuxClient) {
        lock.lock()
        if tcpMux === closedMux {
            tcpMux = nil
        }
        retiredTCPMuxes.removeAll { $0 === closedMux }
        lock.unlock()
    }

    private func openQUICTCP(destination: String, retriesLeft: Int, isDefaultProxy: Bool, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        acquireSession(isDefaultProxy: isDefaultProxy) { [weak self] result in
            switch result {
            case .failure(let error):
                if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                    self.openQUICTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
                } else {
                    completion(.failure(error))
                }
            case .success(let session):
                let conn = NowhereConnection(session: session, destination: destination)
                conn.open { error in
                    if let error {
                        conn.cancel()
                        if retriesLeft > 0, Self.isStaleSessionError(error), let self {
                            self.openQUICTCP(destination: destination, retriesLeft: retriesLeft - 1, isDefaultProxy: isDefaultProxy, completion: completion)
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
        let mux = tcpMux
        tcpMux = nil
        let retiredMuxes = retiredTCPMuxes
        retiredTCPMuxes.removeAll()
        if transport != nil, let key = poolKey {
            Self.registryLock.lock()
            if Self.registry[key] === self {
                Self.registry.removeValue(forKey: key)
            }
            Self.registryLock.unlock()
        }
        lock.unlock()

        current?.close()
        mux?.close()
        for mux in retiredMuxes { mux.close() }

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

extension NowhereClient {
    static let pool: TransportPool = Pool()
    private final class Pool: TransportPool {
        func reclaim() { NowhereClient.closeAll() }
    }
}
