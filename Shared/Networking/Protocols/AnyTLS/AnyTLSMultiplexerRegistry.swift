//
//  AnyTLSMultiplexerRegistry.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexerRegistry")

/// Process-wide registry of `AnyTLSMultiplexerPool`s keyed by `(host, port, password)`;
/// configs sharing the same triple reuse the same warm TLS-multiplexer pool.
nonisolated final class AnyTLSMultiplexerRegistry {

    static let shared = AnyTLSMultiplexerRegistry()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let password: String
    }

    private let lock = UnfairLock()
    private var clients: [Key: AnyTLSMultiplexerPool] = [:]

    private init() {}

    /// Returns the per-server pool, creating it on first use; on reuse the passed `dialOut` is dropped.
    func client(
        for configuration: ProxyConfiguration,
        dialOut: @escaping AnyTLSMultiplexerPool.DialOut
    ) -> AnyTLSMultiplexerPool? {
        guard
            case .anytls(let password, let ici, let it, let mis, _) = configuration.outbound
        else {
            logger.debug("[AnyTLSMultiplexerRegistry] outbound is not .anytls — refusing to create client")
            return nil
        }
        let key = Key(host: configuration.serverAddress, port: configuration.serverPort, password: password)
        lock.lock()
        if let existing = clients[key] {
            lock.unlock()
            logger.debug("[AnyTLSMultiplexerRegistry] reuse client \(configuration.serverAddress):\(configuration.serverPort)")
            return existing
        }
        let client = AnyTLSMultiplexerPool(
            password: password,
            idleSessionCheckInterval: TimeInterval(ici),
            idleSessionTimeout:       TimeInterval(it),
            minIdleSession:           mis,
            dialOut: dialOut
        )
        clients[key] = client
        lock.unlock()
        logger.debug("[AnyTLSMultiplexerRegistry] created client \(configuration.serverAddress):\(configuration.serverPort) ici=\(ici)s it=\(it)s mis=\(mis)")
        return client
    }

    /// Closes every pooled multiplexer; called on wake/path change/stop because the
    /// kernel may have torn down the underlying sockets.
    func closeAll() {
        lock.lock()
        let snapshot = Array(clients.values)
        clients.removeAll(keepingCapacity: false)
        lock.unlock()
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
