//
//  SudokuConnectionFactory.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import Synchronization

nonisolated final class SudokuConnectionFactory: Sendable {
    private struct PreparedKey: Hashable {
        let host: String
        let port: UInt16
        let useTLS: Bool
        let serverName: String
    }

    private final class PreparedConnection: Sendable {
        let connection: ProxyConnection

        init(connection: ProxyConnection) {
            self.connection = connection
        }
    }

    private static let preparedConnectionTTL: TimeInterval = 4
    private static let preparedConnectionWaitTimeout: TimeInterval = 0.25
    private let configuration: ProxyConfiguration
    private let directDialHost: String
    private let dialChain: [ProxyConfiguration]
    
    private struct State: PhaseHolding {
        var initialTunnel: ProxyConnection?
        var retainedClients: [ProxyClient] = []
        var retainedTLSClients: [TLSClient] = []
        var retainedTransports: [TCPTransport] = []
        var connections: [ProxyConnection] = []
        var phase: SudokuLifecycle = .open
    }

    private let stateLock: Mutex<State>
    
    private struct PreparedState {
        var preparedConnections: [PreparedKey: [PreparedConnection]] = [:]
        var pendingPreparations: [PreparedKey: Int] = [:]
        var preparedClosed = false
        var scheduledTasks: [Int: Task<Void, Never>] = [:]
        var scheduledDeadlines: [Int: DeadlineToken] = [:]
        var nextScheduledTaskID = 0
        var generation: UInt64 = 0
        var nextWaiterID: UInt64 = 0
        var waiters: [(id: UInt64, cont: AsyncStream<Never>.Continuation)] = []
    }
    private let preparedState = Mutex(PreparedState())
    
    private func drainPreparedWaitersLocked(_ s: inout PreparedState) -> [AsyncStream<Never>.Continuation] {
        s.generation &+= 1
        let conts = s.waiters.map { $0.cont }
        s.waiters.removeAll(keepingCapacity: true)
        return conts
    }
    
    private func waitPreparedSignal(observed: UInt64) async {
        let id = preparedState.withLock { s -> UInt64 in
            let id = s.nextWaiterID
            s.nextWaiterID &+= 1
            return id
        }
        let stream: AsyncStream<Never>? = preparedState.withLock { s -> AsyncStream<Never>? in
            if s.generation != observed { return nil }
            let (stream, cont) = AsyncStream.makeStream(of: Never.self)
            s.waiters.append((id: id, cont: cont))
            return stream
        }
        guard let stream else { return }
        for await _ in stream {}
        preparedState.withLock { s in s.waiters.removeAll { $0.id == id } }
    }
    
    private func waitPreparedSignal(observed: UInt64, until deadline: TimeInterval) async {
        let interval = deadline - MonotonicClock.now
        guard interval > 0 else { return }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.waitPreparedSignal(observed: observed) }
            group.addTask { try? await Task.sleep(seconds: interval, precision: .prompt) }
            _ = await group.next()
            group.cancelAll()
        }
    }

    init(
        configuration: ProxyConfiguration,
        initialTunnel: ProxyConnection?,
        directDialHost: String,
        parentChain: [ProxyConfiguration] = []
    ) {
        self.configuration = configuration
        self.stateLock = Mutex(State(initialTunnel: initialTunnel))
        self.directDialHost = directDialHost
        if let chain = configuration.chain, !chain.isEmpty {
            self.dialChain = chain
        } else {
            self.dialChain = parentChain
        }
    }

    func open(host: String, port: UInt16, useTLS: Bool, serverName: String?) async throws -> BlockingProxyStream {
        if stateLock.withLock({ $0.phase == .closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        if let prepared = await takePreparedConnection(for: key) {
            return BlockingProxyStream(connection: prepared.connection, owner: self)
        }
        let connection = try await openProxyConnection(host: host, port: port, useTLS: useTLS, serverName: serverName)
        guard retainConnection(connection) else {
            connection.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        return BlockingProxyStream(connection: connection, owner: self)
    }

    func prepare(host: String, port: UInt16, useTLS: Bool, serverName: String?, count: Int) {
        guard count > 0, preparedConnectionsEnabled else {
            return
        }

        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        ensurePreparedConnections(for: key, targetCount: count)
    }

    private func ensurePreparedConnections(for key: PreparedKey, targetCount: Int) {
        guard targetCount > 0 else { return }
        let needed = preparedState.withLock { state -> Int in
            if state.preparedClosed { return 0 }
            let readyCount = state.preparedConnections[key]?.count ?? 0
            let pendingCount = state.pendingPreparations[key] ?? 0
            let needed = max(0, targetCount - readyCount - pendingCount)
            if needed > 0 {
                state.pendingPreparations[key] = pendingCount + needed
            }
            return needed
        }
        guard needed > 0 else { return }

        for _ in 0..<needed {
            let spawned = preparedState.withLock { state -> Bool in
                guard !state.preparedClosed else { return false }
                let id = state.nextScheduledTaskID
                state.nextScheduledTaskID += 1
                state.scheduledTasks[id] = Task { [weak self] in
                    guard let self else { return }
                    let result: Result<ProxyConnection, Error>
                    do {
                        result = .success(try await self.openProxyConnection(
                            host: key.host,
                            port: key.port,
                            useTLS: key.useTLS,
                            serverName: key.serverName
                        ))
                    } catch {
                        result = .failure(error)
                    }
                    self.preparedState.withLock { _ = $0.scheduledTasks.removeValue(forKey: id) }
                    self.finishPreparation(result, for: key)
                }
                return true
            }
            if !spawned {
                finishPendingPreparation(for: key)
            }
        }
    }

    func openWebSocket(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?,
        hostHeader: String,
        path: String,
        headers: [String: String]
    ) async throws -> BlockingProxyStream {
        if stateLock.withLock({ $0.phase == .closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        let base = try await openProxyConnection(host: host, port: port, useTLS: useTLS, serverName: serverName)
        guard retainConnection(base) else {
            base.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        let ws = WebSocketConnection(
            tunnel: base,
            configuration: WebSocketConfiguration(
                host: hostHeader,
                path: path,
                headers: headers,
                heartbeatPeriod: 30
            )
        )
        do {
            try await ws.performUpgrade()
        } catch {
            releaseConnection(base)
            ws.cancel()
            base.cancel()
            throw error
        }
        let connection = WebSocketProxyConnection(wsConnection: ws)
        guard replaceConnection(base, with: connection) else {
            connection.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        return BlockingProxyStream(connection: connection, owner: self)
    }

    func closeAll() {
        var waitersToWake: [AsyncStream<Never>.Continuation] = []
        let scheduled: (tasks: [Task<Void, Never>], deadlines: [DeadlineToken]) = preparedState.withLock { state in
            state.preparedClosed = true
            state.preparedConnections.removeAll()
            state.pendingPreparations.removeAll()
            let tasks = Array(state.scheduledTasks.values)
            let deadlines = Array(state.scheduledDeadlines.values)
            state.scheduledTasks.removeAll()
            state.scheduledDeadlines.removeAll()
            waitersToWake = drainPreparedWaitersLocked(&state)
            return (tasks, deadlines)
        }
        for cont in waitersToWake { cont.finish() }
        for task in scheduled.tasks { task.cancel() }
        for deadline in scheduled.deadlines { deadline.cancel() }

        typealias Drained = (toClose: [ProxyConnection], clients: [ProxyClient],
                             tlsClients: [TLSClient], transports: [TCPTransport])
        let drained: Drained? = stateLock.withLock { (state: inout State) -> Drained? in
            guard state.transition(to: .closed) else { return nil }
            let toClose = state.connections + (state.initialTunnel.map { [$0] } ?? [])
            let clients = state.retainedClients
            let tlsClients = state.retainedTLSClients
            let transports = state.retainedTransports
            state.connections.removeAll()
            state.retainedClients.removeAll()
            state.retainedTLSClients.removeAll()
            state.retainedTransports.removeAll()
            state.initialTunnel = nil
            return (toClose, clients, tlsClients, transports)
        }
        guard let drained else { return }
        for connection in drained.toClose { connection.cancel() }
        for client in drained.clients { client.cancel() }
        for client in drained.tlsClients { client.cancel() }
        for transport in drained.transports { transport.cancel() }
    }

    private func preparedKey(host: String, port: UInt16, useTLS: Bool, serverName: String?) -> PreparedKey {
        PreparedKey(
            host: host.lowercased(),
            port: port,
            useTLS: useTLS,
            serverName: (serverName ?? host).lowercased()
        )
    }

    private var supportsPreparedConnections: Bool {
        guard dialChain.isEmpty else { return false }
        return stateLock.withLock { $0.phase == .open && $0.initialTunnel == nil }
    }

    fileprivate var preparedConnectionsEnabled: Bool {
        ProcessInfo.processInfo.environment["ANYWHERE_SUDOKU_DISABLE_PRECONNECT"] != "1"
            && supportsPreparedConnections
    }

    private func takePreparedConnection(for key: PreparedKey) async -> PreparedConnection? {
        let deadline = MonotonicClock.now + Self.preparedConnectionWaitTimeout
        while true {
            let taken: PreparedConnection?
            let shouldWait: Bool
            let generation: UInt64
            (taken, shouldWait, generation) = preparedState.withLock { state -> (PreparedConnection?, Bool, UInt64) in
                if var ready = state.preparedConnections[key], !ready.isEmpty {
                    let connection = ready.removeFirst()
                    if ready.isEmpty {
                        state.preparedConnections.removeValue(forKey: key)
                    } else {
                        state.preparedConnections[key] = ready
                    }
                    return (connection, false, state.generation)
                }
                let shouldWait = !state.preparedClosed && (state.pendingPreparations[key] ?? 0) > 0
                return (nil, shouldWait, state.generation)
            }
            if let taken {
                return taken
            }
            guard shouldWait, MonotonicClock.now < deadline else { return nil }
            await waitPreparedSignal(observed: generation, until: deadline)
            if Task.isCancelled { return nil }
        }
    }

    private func finishPreparation(_ result: Result<ProxyConnection, Error>, for key: PreparedKey) {
        guard case .success(let connection) = result else {
            finishPendingPreparation(for: key)
            return
        }

        let retained = retainConnection(connection)
        let prepared = retained ? PreparedConnection(connection: connection) : nil

        var waitersToWake: [AsyncStream<Never>.Continuation] = []
        let acceptedPrepared: PreparedConnection? = preparedState.withLock { state in
            decrementPendingPreparationLocked(&state, for: key)
            if let prepared, !state.preparedClosed {
                state.preparedConnections[key, default: []].append(prepared)
            }
            waitersToWake = drainPreparedWaitersLocked(&state)
            return state.preparedClosed ? nil : prepared
        }
        for cont in waitersToWake { cont.finish() }

        guard let acceptedPrepared else {
            if retained {
                releaseConnection(connection)
            }
            connection.cancel()
            return
        }
        expirePreparedConnection(acceptedPrepared, for: key)
    }

    private func finishPendingPreparation(for key: PreparedKey) {
        let conts = preparedState.withLock { state -> [AsyncStream<Never>.Continuation] in
            decrementPendingPreparationLocked(&state, for: key)
            return drainPreparedWaitersLocked(&state)
        }
        for cont in conts { cont.finish() }
    }

    private func decrementPendingPreparationLocked(_ state: inout PreparedState, for key: PreparedKey) {
        let remaining = max(0, (state.pendingPreparations[key] ?? 1) - 1)
        if remaining == 0 {
            state.pendingPreparations.removeValue(forKey: key)
        } else {
            state.pendingPreparations[key] = remaining
        }
    }

    private func expirePreparedConnection(_ prepared: PreparedConnection, for key: PreparedKey) {
        scheduleAfter(Self.preparedConnectionTTL) { [weak self] in
            guard let self else { return }
            let expired: Bool = self.preparedState.withLock { state in
                guard var ready = state.preparedConnections[key],
                      let index = ready.firstIndex(where: { $0 === prepared }) else { return false }
                ready.remove(at: index)
                if ready.isEmpty {
                    state.preparedConnections.removeValue(forKey: key)
                } else {
                    state.preparedConnections[key] = ready
                }
                return true
            }
            if expired {
                self.releaseConnection(prepared.connection)
                prepared.connection.cancel()
            }
        }
    }

    private func scheduleAfter(_ delay: TimeInterval, _ operation: @escaping @Sendable () -> Void) {
        let id: Int? = preparedState.withLock { state in
            guard !state.preparedClosed else { return nil }
            let id = state.nextScheduledTaskID
            state.nextScheduledTaskID += 1
            return id
        }
        guard let id else { return }
        let deadline = TickScheduler.shared.schedule(in: .seconds(delay), precision: .relaxed) { [weak self] in
            guard let self else { return }
            let stillTracked = self.preparedState.withLock { $0.scheduledDeadlines.removeValue(forKey: id) != nil }
            guard stillTracked else { return }
            operation()
        }
        let closedNow = preparedState.withLock { state -> Bool in
            guard !state.preparedClosed else { return true }
            state.scheduledDeadlines[id] = deadline
            return false
        }
        if closedNow { deadline.cancel() }
    }

    private func openProxyConnection(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?
    ) async throws -> ProxyConnection {
        let tunnel: ProxyConnection?
        if let initialTunnel = stateLock.withLock({ (state: inout State) -> ProxyConnection? in
            let current = state.initialTunnel
            state.initialTunnel = nil
            return current
        }) {
            tunnel = initialTunnel
        } else if !dialChain.isEmpty {
            tunnel = try await buildChainTunnel(chain: dialChain, targetHost: host, targetPort: port)
        } else {
            tunnel = nil
        }

        if useTLS {
            return try await openTLSConnection(serverName: serverName ?? host, port: port, overTunnel: tunnel)
        }

        if let tunnel {
            return tunnel
        }

        let transport = TCPTransport(host: directDialHost, port: port, resolution: .proxies)
        guard retainTransport(transport) else {
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        do {
            try await transport.connect()
        } catch {
            releaseTransport(transport)
            throw error
        }
        releaseTransport(transport)
        return DirectProxyConnection(transport: transport)
    }

    private func openTLSConnection(
        serverName: String,
        port: UInt16,
        overTunnel tunnel: ProxyConnection?
    ) async throws -> ProxyConnection {
        let tls = TLSClient(configuration: TLSConfiguration(serverName: serverName, alpn: ["http/1.1"]))
        guard retainTLSClient(tls) else {
            tunnel?.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        do {
            let connection: TLSRecordConnection
            if let tunnel {
                connection = try await tls.connect(overTunnel: tunnel)
            } else {
                connection = try await tls.connect(host: directDialHost, port: port)
            }
            releaseTLSClient(tls)
            return TLSProxyConnection(tlsConnection: connection)
        } catch {
            releaseTLSClient(tls)
            tunnel?.cancel()
            throw error
        }
    }

    private func buildChainTunnel(
        chain: [ProxyConfiguration],
        targetHost: String,
        targetPort: UInt16
    ) async throws -> ProxyConnection {
        let hopNetworks = try ProxyClient.computeChainHopNetworks(chain: chain, lastDeliver: .tcp).get()
        let dialing = Mutex<[ProxyClient]>([])
        defer {
            for client in dialing.withLock({ $0 }) { releaseClient(client) }
        }
        do {
            return try await ProxyClient.buildDetachedChainTunnel(
                chain: chain,
                hopNetworks: hopNetworks,
                finalDestination: (targetHost, targetPort),
                useResolvedAddressForDirectDial: false,
                track: { [self] client in
                    dialing.withLock { $0.append(client) }
                    if !retainClient(client) { client.cancel() }
                }
            )
        } catch {
            for client in dialing.withLock({ $0 }) { await client.cancel() }
            throw error
        }
    }

    private func retainClient(_ client: ProxyClient) -> Bool {
        stateLock.withLock { state in
            guard state.phase == .open else { return false }
            state.retainedClients.append(client)
            return true
        }
    }

    private func releaseClient(_ client: ProxyClient) {
        stateLock.withLock { state in
            state.retainedClients.removeAll { $0 === client }
        }
    }

    private func retainTLSClient(_ client: TLSClient) -> Bool {
        stateLock.withLock { state in
            guard state.phase == .open else { return false }
            state.retainedTLSClients.append(client)
            return true
        }
    }

    private func releaseTLSClient(_ client: TLSClient) {
        stateLock.withLock { state in
            state.retainedTLSClients.removeAll { $0 === client }
        }
    }

    private func retainTransport(_ transport: TCPTransport) -> Bool {
        stateLock.withLock { state in
            guard state.phase == .open else { return false }
            state.retainedTransports.append(transport)
            return true
        }
    }

    private func releaseTransport(_ transport: TCPTransport) {
        stateLock.withLock { state in
            state.retainedTransports.removeAll { $0 === transport }
        }
    }

    private func retainConnection(_ connection: ProxyConnection) -> Bool {
        stateLock.withLock { state in
            guard state.phase == .open else { return false }
            state.connections.append(connection)
            return true
        }
    }

    private func replaceConnection(_ old: ProxyConnection, with new: ProxyConnection) -> Bool {
        stateLock.withLock { state in
            state.connections.removeAll { $0 === old }
            guard state.phase == .open else { return false }
            state.connections.append(new)
            return true
        }
    }

    func releaseConnection(_ connection: ProxyConnection) {
        stateLock.withLock { state in
            state.connections.removeAll { $0 === connection }
        }
    }
}
