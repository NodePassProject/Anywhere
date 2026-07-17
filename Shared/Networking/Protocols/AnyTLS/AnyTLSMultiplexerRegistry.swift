//
//  AnyTLSMultiplexerRegistry.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexerRegistry")

/// Keyed by `(host, port, password)`; configs sharing the triple reuse one warm pool.
nonisolated final class AnyTLSMultiplexerRegistry: Sendable {

    nonisolated static let shared = AnyTLSMultiplexerRegistry()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let password: String
    }

    private let pools = Mutex<[Key: AnyTLSMultiplexerPool]>([:])

    private init() {}

    /// Creates the pool on first use; on reuse the passed `dialOut` is dropped.
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
        let pool = pools.withLock { pools -> AnyTLSMultiplexerPool in
            if let existing = pools[key] {
                return existing
            }
            reused = false
            let created = AnyTLSMultiplexerPool(
                password: password,
                idleSessionCheckInterval: TimeInterval(idleSessionCheckInterval),
                idleSessionTimeout:       TimeInterval(idleSessionTimeout),
                minIdleSession:           minIdleSession,
                dialOut: dialOut
            )
            pools[key] = created
            return created
        }
        if reused {
            logger.debug("[AnyTLSMultiplexerRegistry] reuse pool \(configuration.serverAddress):\(configuration.serverPort)")
        } else {
            logger.debug("[AnyTLSMultiplexerRegistry] created pool \(configuration.serverAddress):\(configuration.serverPort) ici=\(idleSessionCheckInterval)s it=\(idleSessionTimeout)s mis=\(minIdleSession)")
        }
        return pool
    }

    /// Called on wake/path change/stop because the kernel may have torn down the sockets.
    func closeAll() {
        let snapshot = pools.withLock { pools -> [AnyTLSMultiplexerPool] in
            let values = Array(pools.values)
            pools.removeAll(keepingCapacity: false)
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
