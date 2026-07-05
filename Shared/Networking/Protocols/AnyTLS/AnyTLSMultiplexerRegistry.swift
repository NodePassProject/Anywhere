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
nonisolated final class AnyTLSMultiplexerRegistry {

    static let shared = AnyTLSMultiplexerRegistry()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let password: String
    }

    private let clients = Mutex<[Key: AnyTLSMultiplexerPool]>([:])

    private init() {}

    /// Creates the pool on first use; on reuse the passed `dialOut` is dropped.
    func client(
        for configuration: ProxyConfiguration,
        dialOut: @escaping AnyTLSMultiplexerPool.DialOut
    ) -> AnyTLSMultiplexerPool? {
        guard
            case .anytls(let password, let idleSessionCheckInterval, let idleSessionTimeout, let minIdleSession, _) = configuration.outbound
        else {
            logger.debug("[AnyTLSMultiplexerRegistry] outbound is not .anytls — refusing to create client")
            return nil
        }
        let key = Key(host: configuration.serverAddress, port: configuration.serverPort, password: password)
        var reused = true
        let client = clients.withLock { clients -> AnyTLSMultiplexerPool in
            if let existing = clients[key] {
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
            clients[key] = created
            return created
        }
        if reused {
            logger.debug("[AnyTLSMultiplexerRegistry] reuse client \(configuration.serverAddress):\(configuration.serverPort)")
        } else {
            logger.debug("[AnyTLSMultiplexerRegistry] created client \(configuration.serverAddress):\(configuration.serverPort) ici=\(idleSessionCheckInterval)s it=\(idleSessionTimeout)s mis=\(minIdleSession)")
        }
        return client
    }

    /// Called on wake/path change/stop because the kernel may have torn down the sockets.
    func closeAll() {
        let snapshot = clients.withLock { clients -> [AnyTLSMultiplexerPool] in
            let values = Array(clients.values)
            clients.removeAll(keepingCapacity: false)
            return values
        }
        if !snapshot.isEmpty {
            logger.debug("[AnyTLSMultiplexerRegistry] closeAll(\(snapshot.count) clients)")
        }
        for client in snapshot {
            client.closeAll()
        }
    }
}

extension AnyTLSMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}
