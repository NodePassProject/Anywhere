//
//  SessionPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/14/26.
//

import Foundation

// MARK: - PoolableSession

/// The minimum surface a ``SessionPool`` needs from its sessions: a way to
/// check whether the session has closed out of band, and a way to tear it
/// down on pool-wide close.
protocol PoolableSession: AnyObject {
    /// Whether the session is closed. Sessions with this set are evicted by
    /// the pool.
    var poolIsClosed: Bool { get }

    /// Tears down the session. Called by `closeAll()` on pool shutdown; may
    /// also be invoked by pool eviction paths.
    func close()
}

// MARK: - SessionPool

/// Generic base for pooled-session managers (HTTP/2, HTTP/3). Handles the
/// scaffolding that's identical across pool implementations:
///
/// - a lock,
/// - a `host:port:sni`-keyed bucket dictionary,
/// - removal of a specific session from its bucket,
/// - a default `closeAll()` that drains every pooled session.
///
/// Subclasses add protocol-specific state (GOAWAY draining, idle timeouts,
/// soft/hard caps) and override `closeAll()` to include their auxiliary
/// storage.
nonisolated class SessionPool<S: PoolableSession> {

    /// Guards ``sessions`` and any subclass-owned auxiliary storage. Subclasses
    /// must acquire this lock before touching ``sessions``.
    let lock = UnfairLock()

    /// Sessions keyed by ``makeKey(host:port:sni:)``.
    var sessions: [String: [S]] = [:]

    init() {}

    /// Builds the bucket key shared by every subclass.
    static func makeKey(host: String, port: UInt16, sni: String) -> String {
        "\(host):\(port):\(sni)"
    }

    /// Removes `session` from its bucket at `key`. Drops the bucket entirely
    /// if it becomes empty. Thread-safe.
    func removeSession(_ session: S, key: String) {
        lock.lock()
        sessions[key]?.removeAll { $0 === session }
        if sessions[key]?.isEmpty == true {
            sessions.removeValue(forKey: key)
        }
        lock.unlock()
    }

    /// Closes every pooled session and empties the bucket dictionary.
    /// Subclasses should override to additionally close any protocol-specific
    /// auxiliary collections (e.g. dedicated sessions for chained tunnels).
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
