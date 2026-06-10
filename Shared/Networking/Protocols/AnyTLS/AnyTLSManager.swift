//
//  AnyTLSManager.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLSManager")

/// Process-wide registry of `AnyTLSClient`s keyed by `(host, port, password)`;
/// configs sharing the same triple reuse the same warm TLS-session pool.
nonisolated final class AnyTLSManager {

    static let shared = AnyTLSManager()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let password: String
    }

    private let lock = UnfairLock()
    private var clients: [Key: AnyTLSClient] = [:]

    private init() {}

    /// Returns the per-server pool, creating it on first use; on reuse the passed `dialOut` is dropped.
    func client(
        for configuration: ProxyConfiguration,
        dialOut: @escaping AnyTLSClient.DialOut
    ) -> AnyTLSClient? {
        guard
            case .anytls(let password, let ici, let it, let mis, _) = configuration.outbound
        else {
            logger.debug("[AnyTLSManager] outbound is not .anytls — refusing to create client")
            return nil
        }
        let key = Key(host: configuration.serverAddress, port: configuration.serverPort, password: password)
        lock.lock()
        if let existing = clients[key] {
            lock.unlock()
            logger.debug("[AnyTLSManager] reuse client \(configuration.serverAddress):\(configuration.serverPort)")
            return existing
        }
        let client = AnyTLSClient(
            password: password,
            idleSessionCheckInterval: TimeInterval(ici),
            idleSessionTimeout:       TimeInterval(it),
            minIdleSession:           mis,
            dialOut: dialOut
        )
        clients[key] = client
        lock.unlock()
        logger.debug("[AnyTLSManager] created client \(configuration.serverAddress):\(configuration.serverPort) ici=\(ici)s it=\(it)s mis=\(mis)")
        return client
    }

    /// Closes every pooled session; called on wake/path change/stop because the
    /// kernel may have torn down the underlying sockets.
    func closeAll() {
        lock.lock()
        let snapshot = Array(clients.values)
        clients.removeAll(keepingCapacity: false)
        lock.unlock()
        if !snapshot.isEmpty {
            logger.debug("[AnyTLSManager] closeAll(\(snapshot.count) clients)")
        }
        for client in snapshot {
            client.closeAll()
        }
    }
}

extension AnyTLSManager: TransportPool {
    func reclaim() { closeAll() }
}
