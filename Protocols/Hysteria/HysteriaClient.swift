//
//  HysteriaClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/18/26.
//

import Foundation

/// Reconnectable wrapper around `HysteriaSession`, mirroring the reference
/// Hysteria client's `reconnectableClientImpl` (`core/client/reconnect.go`).
///
/// Semantics:
/// - At most one active `HysteriaSession` per unique server configuration.
/// - Lazy reconnect: a dead session clears itself via the `onClose` hook;
///   the next `openTCP`/`openUDP` call establishes a fresh one.
/// - No in-wrapper retries: an operation that hits a dying session returns
///   the error to the caller, matching the reference behavior.
///
/// Instances are shared via ``shared(for:)`` keyed by
/// `(host, port, SNI, password)`. Callers should not construct directly.
final class HysteriaClient {

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let sni: String
        let password: String
    }

    private static let registryLock = UnfairLock()
    private static var registry: [Key: HysteriaClient] = [:]

    static func shared(for configuration: HysteriaConfiguration) -> HysteriaClient {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI,
            password: configuration.password
        )
        registryLock.lock()
        defer { registryLock.unlock() }
        if let existing = registry[key] { return existing }
        let client = HysteriaClient(configuration: configuration)
        registry[key] = client
        return client
    }

    private let configuration: HysteriaConfiguration
    private let lock = UnfairLock()
    private var session: HysteriaSession?

    private init(configuration: HysteriaConfiguration) {
        self.configuration = configuration
    }

    private func acquireSession(completion: @escaping (Result<HysteriaSession, Error>) -> Void) {
        lock.lock()
        if let existing = session, !existing.poolIsClosed {
            lock.unlock()
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        }

        let newSession = HysteriaSession(configuration: configuration)
        session = newSession
        lock.unlock()

        newSession.onClose = { [weak self, weak newSession] in
            guard let self, let newSession else { return }
            self.lock.lock()
            if self.session === newSession {
                self.session = nil
            }
            self.lock.unlock()
        }

        newSession.ensureReady { [weak newSession] error in
            guard let newSession else {
                completion(.failure(HysteriaError.connectionFailed("Session deallocated")))
                return
            }
            if let error { completion(.failure(error)) }
            else { completion(.success(newSession)) }
        }
    }

    func openTCP(destination: String, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        acquireSession { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let session):
                let conn = HysteriaConnection(session: session, destination: destination)
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

    func openUDP(destination: String, completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        acquireSession { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let session):
                let conn = HysteriaUDPConnection(session: session, destination: destination)
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
