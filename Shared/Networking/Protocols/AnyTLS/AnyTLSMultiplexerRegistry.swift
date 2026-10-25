//
//  AnyTLSMultiplexerRegistry.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated final class AnyTLSMultiplexerRegistry: Sendable {
    nonisolated static let shared = AnyTLSMultiplexerRegistry()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let password: String
        let chain: [ProxyConfiguration]
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
        guard let anytls = configuration.anytls else { return nil }
        let key = Key(
            host: configuration.serverAddress,
            port: configuration.serverPort,
            password: anytls.password,
            chain: configuration.chain ?? []
        )
        let pool = state.withLock { state -> AnyTLSMultiplexerPool? in
            if let existing = state.pools[key] {
                return existing
            }
            guard !state.sealed else { return nil }
            let created = AnyTLSMultiplexerPool(
                password: anytls.password,
                idleSessionCheckInterval: TimeInterval(anytls.idleCheckInterval),
                idleSessionTimeout:       TimeInterval(anytls.idleTimeout),
                minIdleSession:           anytls.minIdleSession,
                dialOut: dialOut
            )
            state.pools[key] = created
            return created
        }
        guard let pool else { return nil }
        return pool
    }

    func closeAll() {
        let snapshot = state.withLock { state -> [AnyTLSMultiplexerPool] in
            let values = Array(state.pools.values)
            state.pools.removeAll(keepingCapacity: false)
            return values
        }
        for pool in snapshot {
            pool.closeAll()
        }
    }
}

nonisolated extension AnyTLSMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}
