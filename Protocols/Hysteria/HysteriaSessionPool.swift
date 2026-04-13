//
//  HysteriaSessionPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HysteriaPool")

final class HysteriaSessionPool {

    static let shared = HysteriaSessionPool()

    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let sni: String
        let password: String
    }

    private let lock = UnfairLock()
    private var sessions: [Key: HysteriaSession] = [:]

    private init() {}

    /// Ensures a ready session exists for the given configuration, then
    /// invokes completion on the session queue.
    func acquireSession(
        configuration: HysteriaConfiguration,
        completion: @escaping (Result<HysteriaSession, Error>) -> Void
    ) {
        let key = Key(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI,
            password: configuration.password
        )

        lock.lock()
        if let existing = sessions[key], !existing.poolIsClosed {
            lock.unlock()
            existing.ensureReady { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(existing)) }
            }
            return
        }

        let session = HysteriaSession(configuration: configuration)
        sessions[key] = session
        lock.unlock()

        session.onClose = { [weak self, weak session] in
            guard let self, let session else { return }
            self.lock.lock()
            if self.sessions[key] === session {
                self.sessions.removeValue(forKey: key)
            }
            self.lock.unlock()
        }

        session.ensureReady { [weak session] error in
            guard let session else {
                completion(.failure(HysteriaError.connectionFailed("Session deallocated")))
                return
            }
            if let error { completion(.failure(error)) }
            else { completion(.success(session)) }
        }
    }
}
