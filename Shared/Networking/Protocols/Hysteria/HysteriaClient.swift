//
//  HysteriaClient.swift
//  Anywhere
//
//  Created by NodePassProject on 4/18/26.
//

import Foundation
import Synchronization

nonisolated final class HysteriaClient: Sendable {

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let sni: String
        let password: String
        let chainSignature: String
    }

    private struct RegistryState {
        var entries: [Key: HysteriaClient] = [:]
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
            state.pending[key] = task
            return .join(task)
        }
        switch decision {
        case .existing(let client):
            return client
        case .join(let task):
            return try await task.value
        }
    }

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
    private let transport: QUICDatagramTransport?
    private let poolKey: Key?

    private enum Phase: PhaseTransitionable {
        case idle
        case live(HysteriaSession)
        case spent

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .live),
                 (.live, .live),
                 (.live, .idle),
                 (.live, .spent):
                return true
            default:
                return false
            }
        }
    }

    private struct SessionState: PhaseHolding {
        var phase: Phase = .idle
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

    private func removeFromRegistry() {
        guard transport != nil, let key = poolKey else { return }
        Self.registry.withLock { registryState in
            if registryState.entries[key] === self {
                registryState.entries.removeValue(forKey: key)
            }
        }
    }

    private func acquireSession() async throws -> HysteriaSession {
        enum Acquired {
            case reuse(HysteriaSession)
            case transportSpent(abandoned: [ProxyClient])
            case fresh(HysteriaSession)
        }
        let acquired: Acquired = state.withLock { state in
            if case .live(let existing) = state.phase, !existing.isClosed {
                return .reuse(existing)
            }
            switch state.phase {
            case .spent:
                let abandoned = state.chainHolders
                state.chainHolders = []
                removeFromRegistry()
                return .transportSpent(abandoned: abandoned)
            case .live where transport != nil:
                let abandoned = state.chainHolders
                state.chainHolders = []
                state.transition(to: .spent)
                removeFromRegistry()
                return .transportSpent(abandoned: abandoned)
            case .idle, .live:
                let newSession = HysteriaSession(configuration: configuration, transport: transport)
                state.transition(to: .live(newSession))
                return .fresh(newSession)
            }
        }

        switch acquired {
        case .reuse(let existing):
            try await existing.ensureReady()
            return existing
        case .transportSpent(let abandoned):
            for client in abandoned {
                await client.cancel()
            }
            throw AnywhereError.proxy(.hysteria, .streamClosed)
        case .fresh(let newSession):
            newSession.setOnClose { [weak self, weak newSession] in
                guard let self, let newSession else { return }
                self.handleSessionClose(newSession)
            }

            try await newSession.ensureReady()
            return newSession
        }
    }

    private func handleSessionClose(_ closedSession: HysteriaSession) {
        let holders: [ProxyClient]? = state.withLock { state in
            guard case .live(let current) = state.phase, current === closedSession else { return nil }
            state.transition(to: transport != nil ? .spent : .idle)
            let holders = state.chainHolders
            state.chainHolders = []
            removeFromRegistry()
            return holders
        }
        guard let holders else { return }

        for client in holders {
            client.cancel()
        }
    }

    func openTCP(destination: String) async throws -> ProxyConnection {
        var retriesLeft = 1
        while true {
            let session: HysteriaSession
            do {
                session = try await acquireSession()
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

    func openUDP(destination: String) async throws -> ProxyConnection {
        var retriesLeft = 1
        while true {
            let session: HysteriaSession
            do {
                session = try await acquireSession()
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

    private static func isStaleSessionError(_ error: Error) -> Bool {
        if case AnywhereError.quic(let quicError) = error {
            switch quicError {
            case .closed, .timedOut, .streamReset, .streamClosedWithError, .streamFailed:
                return true
            case .connectionFailed, .handshakeFailed, .datagramTooLarge, .datagramQueueFull:
                return false
            }
        }
        if case AnywhereError.proxy(.hysteria, let failure) = error {
            switch failure {
            case .notReady, .streamClosed, .connectionClosed:
                return true
            default:
                return false
            }
        }
        return false
    }

    private func invalidateSession() {
        let (current, holders): (HysteriaSession?, [ProxyClient]) = state.withLock { state in
            var current: HysteriaSession?
            if case .live(let session) = state.phase {
                current = session
                state.transition(to: transport != nil ? .spent : .idle)
            }
            let holders = state.chainHolders
            state.chainHolders = []
            removeFromRegistry()
            return (current, holders)
        }

        current?.close()

        for client in holders {
            client.cancel()
        }
    }

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
