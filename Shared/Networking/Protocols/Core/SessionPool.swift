//
//  SessionPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation

// MARK: - PoolableSession

/// Minimum surface a ``SessionPool`` needs to manage a session.
protocol PoolableSession: AnyObject {
    /// Whether the session is closed; closed sessions are evicted by the pool.
    var poolIsClosed: Bool { get }

    func close()
}

// MARK: - SessionPool

/// Generic base for pooled-session managers keyed by `host:port:sni`.
nonisolated class SessionPool<S: PoolableSession> {

    /// Guards `sessions` and any subclass-owned auxiliary storage.
    let lock = UnfairLock()

    var sessions: [String: [S]] = [:]

    init() {}

    static func makeKey(host: String, port: UInt16, sni: String) -> String {
        "\(host):\(port):\(sni)"
    }

    func removeSession(_ session: S, key: String) {
        lock.lock()
        sessions[key]?.removeAll { $0 === session }
        if sessions[key]?.isEmpty == true {
            sessions.removeValue(forKey: key)
        }
        lock.unlock()
    }

    /// Closes every pooled session; subclasses override to also cover auxiliary storage they own.
    func closeAll() {
        lock.lock()
        let all = sessions.values.flatMap { $0 }
        sessions.removeAll()
        lock.unlock()

        for session in all {
            session.close()
        }
    }
}

extension SessionPool: TransportPool {
    func reclaim() { closeAll() }
}
