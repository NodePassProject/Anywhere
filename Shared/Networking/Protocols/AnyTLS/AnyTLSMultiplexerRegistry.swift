//
//  AnyTLSMultiplexerRegistry.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexerRegistry")

nonisolated final class AnyTLSMultiplexerRegistry: Sendable {
    nonisolated static let shared = AnyTLSMultiplexerRegistry()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let password: String
    }

    private struct State {
        var pools: [Key: AnyTLSMultiplexerPool] = [:]
        var sealed = false
    }
    private let state = Mutex(State())

    private init() {}

    func seal() { state.withLock { $0.sealed = true } }

    func unseal() { state.withLock { $0.sealed = false } }

    func pool(
        for configuration: ProxyConfiguration,
        dialOut: @escaping AnyTLSMultiplexerPool.DialOut
    ) -> AnyTLSMultiplexerPool? {
        guard
            case .anytls(let password, let idleSessionCheckInterval, let idleSessionTimeout, let minIdleSession, _) = configuration.outbound
        else {
            logger.debug("[AnyTLSMultiplexerRegistry] outbound is not .anytls — refusing to create pool")
            return nil
        }
        let key = Key(host: configuration.serverAddress, port: configuration.serverPort, password: password)
        var reused = true
        let pool = state.withLock { state -> AnyTLSMultiplexerPool? in
            if let existing = state.pools[key] {
                return existing
            }
            guard !state.sealed else { return nil }
            reused = false
            let created = AnyTLSMultiplexerPool(
                password: password,
                idleSessionCheckInterval: TimeInterval(idleSessionCheckInterval),
                idleSessionTimeout:       TimeInterval(idleSessionTimeout),
                minIdleSession:           minIdleSession,
                dialOut: dialOut
            )
            state.pools[key] = created
            return created
        }
        guard let pool else {
            logger.debug("[AnyTLSMultiplexerRegistry] sealed — refusing to create pool \(configuration.serverAddress):\(configuration.serverPort)")
            return nil
        }
        if reused {
            logger.debug("[AnyTLSMultiplexerRegistry] reuse pool \(configuration.serverAddress):\(configuration.serverPort)")
        } else {
            logger.debug("[AnyTLSMultiplexerRegistry] created pool \(configuration.serverAddress):\(configuration.serverPort) ici=\(idleSessionCheckInterval)s it=\(idleSessionTimeout)s mis=\(minIdleSession)")
        }
        return pool
    }

    func closeAll() {
        let snapshot = state.withLock { state -> [AnyTLSMultiplexerPool] in
            let values = Array(state.pools.values)
            state.pools.removeAll(keepingCapacity: false)
            return values
        }
        if !snapshot.isEmpty {
            logger.debug("[AnyTLSMultiplexerRegistry] closeAll(\(snapshot.count) pools)")
        }
        for pool in snapshot {
            pool.closeAll()
        }
    }
}

nonisolated extension AnyTLSMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}
