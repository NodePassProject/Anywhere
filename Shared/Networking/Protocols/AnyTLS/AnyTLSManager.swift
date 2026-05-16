//
//  AnyTLSManager.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLSManager")

/// Process-wide registry of `AnyTLSClient`s keyed by `(host, port, password)`.
///
/// Each `AnyTLSClient` owns one TLS-session pool, so different proxy
/// configurations that share the same `(host, port, password)` triple end up
/// reusing the same warm pool — matching how `HysteriaClient.shared(for:)`
/// dedupes its QUIC sessions.
///
/// The `dialOut` closure is captured per-key on first creation; subsequent
/// `client(for:dialOut:)` calls with the same key reuse the existing client
/// and ignore the new closure. This is fine because the inputs that
/// influence the dial path (TLS knobs, chain) are part of the
/// `ProxyConfiguration` already keyed in.
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

    /// Returns the per-server pool for `configuration`, creating it on first
    /// use. The `dialOut` closure is captured into the new `AnyTLSClient`;
    /// subsequent calls for the same key reuse the existing client and the
    /// passed closure is dropped.
    func client(
        for configuration: ProxyConfiguration,
        dialOut: @escaping AnyTLSClient.DialOut
    ) -> AnyTLSClient? {
        guard
            case .anytls(let password, let ici, let it, let mis, _) = configuration.outbound
        else {
            logger.warning("[AnyTLSManager] outbound is not .anytls — refusing to create client")
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
        logger.info("[AnyTLSManager] created client \(configuration.serverAddress):\(configuration.serverPort) ici=\(ici)s it=\(it)s mis=\(mis)")
        return client
    }

    /// Closes every pooled session — invoked from `LWIPStack` lifecycle hooks
    /// (device wake, network path change, tunnel stop) so we don't try to
    /// reuse a TLS connection whose underlying socket the kernel tore down.
    func closeAll() {
        lock.lock()
        let snapshot = Array(clients.values)
        clients.removeAll(keepingCapacity: false)
        lock.unlock()
        if !snapshot.isEmpty {
            logger.info("[AnyTLSManager] closeAll(\(snapshot.count) clients)")
        }
        for client in snapshot {
            client.closeAll()
        }
    }
}
