//
//  HTTP3SessionPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP3Pool")

/// Pools ``HTTP3Session`` instances (each a QUIC connection) for reuse
/// across CONNECT streams. Adds idle eviction plus soft/hard caps on top
/// of ``SessionPool``'s scaffolding to keep QUIC connection growth bounded.
final class HTTP3SessionPool: SessionPool<HTTP3Session> {

    static let shared = HTTP3SessionPool()

    /// Last activity time per session (for idle eviction).
    private var lastActivity: [ObjectIdentifier: Date] = [:]

    /// Soft cap on sessions per pool key. When reached, acquire tries to
    /// evict an idle session before creating a new one.
    private static let maxSessionsPerKey = 16

    /// Hard cap on sessions per pool key. If every session is busy, the pool
    /// may grow past the soft cap up to this ceiling to avoid breaking live
    /// streams. Beyond this, acquire reuses the least-busy session instead
    /// of opening another — preventing runaway growth under sustained load.
    private static let hardMaxSessionsPerKey = 32

    /// Sessions idle longer than this are evicted.
    private static let idleTimeout: TimeInterval = 60

    /// Periodic cleanup timer.
    private var cleanupTimer: DispatchSourceTimer?
    private let cleanupQueue = DispatchQueue(label: "com.argsment.Anywhere.http3pool.cleanup")

    private override init() {
        super.init()
        startCleanupTimer()
    }

    // MARK: - Acquire

    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        configuration: NaiveConfiguration,
        destination: String,
        completion: @escaping (HTTP3Stream) -> Void
    ) {
        let key = Self.makeKey(host: host, port: port, sni: sni)
        let session: HTTP3Session

        lock.lock()

        // Evict closed, stream-blocked, and idle sessions.
        evictStale(key: key)

        if let existing = sessions[key]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(existing)] = Date()
            session = existing
        } else if let overflow = overflowSession(key: key) {
            // Hard cap hit and every session is saturated — pile onto the
            // least-loaded one rather than grow the pool unbounded.
            lastActivity[ObjectIdentifier(overflow)] = Date()
            session = overflow
        } else {
            // Soft cap: never close a session that still has live streams —
            // doing so would abort in-flight tunnels on unrelated
            // destinations. Prefer evicting an idle session; if all are
            // busy, allow the pool to grow past the soft cap (up to
            // `hardMaxSessionsPerKey`) rather than break working streams.
            let currentCount = sessions[key]?.count ?? 0
            if currentCount >= Self.maxSessionsPerKey {
                if let victim = sessions[key]?.first(where: { !$0.hasActiveStreams }) {
                    lock.unlock()
                    victim.close()
                    lock.lock()
                    sessions[key]?.removeAll { $0 === victim }
                    lastActivity.removeValue(forKey: ObjectIdentifier(victim))
                }
            }

            let new = HTTP3Session(
                host: host, port: port, serverName: sni, configuration: configuration
            )
            let capturedKey = key
            new.onClose = { [weak self, weak new] in
                guard let self, let new else { return }
                self.removeSession(new, key: capturedKey)
            }
            sessions[key, default: []].append(new)
            lastActivity[ObjectIdentifier(new)] = Date()
            session = new
        }
        lock.unlock()

        session.queue.async {
            let stream = session.createStream(destination: destination)
            completion(stream)
        }
    }

    /// Returns the least-loaded existing session when the pool is at its
    /// hard cap, bypassing per-session `maxConcurrentStreams`. Returns nil
    /// when we still have room to grow the pool. Must be called with `lock`
    /// held.
    private func overflowSession(key: String) -> HTTP3Session? {
        guard let pool = sessions[key], pool.count >= Self.hardMaxSessionsPerKey else {
            return nil
        }
        let candidate = pool
            .filter { !$0.poolIsClosed && !$0.poolIsStreamBlocked }
            .min(by: { $0.currentStreamLoad < $1.currentStreamLoad })
        guard let candidate, candidate.forceReserveStream() else { return nil }
        logger.warning("[HTTP3Pool] Pool hit hard cap (\(Self.hardMaxSessionsPerKey)) for \(key); overflowing onto existing session")
        return candidate
    }

    // MARK: - Eviction

    /// Removes closed, stream-blocked, and idle sessions from `key`'s bucket.
    /// Must be called with ``lock`` held.
    private func evictStale(key: String) {
        let now = Date()
        sessions[key]?.removeAll { session in
            if session.poolIsClosed || session.poolIsStreamBlocked {
                lastActivity.removeValue(forKey: ObjectIdentifier(session))
                return true
            }
            // Only evict idle sessions that have NO active streams.
            if !session.hasActiveStreams,
               let activity = lastActivity[ObjectIdentifier(session)],
               now.timeIntervalSince(activity) > Self.idleTimeout {
                lastActivity.removeValue(forKey: ObjectIdentifier(session))
                DispatchQueue.global().async { session.close() }
                return true
            }
            return false
        }
        if sessions[key]?.isEmpty == true {
            sessions.removeValue(forKey: key)
        }
    }

    /// Drops the bucket entry plus the activity record. The base implementation
    /// is otherwise sufficient.
    override func removeSession(_ session: HTTP3Session, key: String) {
        super.removeSession(session, key: key)
        lock.lock()
        lastActivity.removeValue(forKey: ObjectIdentifier(session))
        lock.unlock()
    }

    // MARK: - Periodic Cleanup

    private func startCleanupTimer() {
        let timer = DispatchSource.makeTimerSource(queue: cleanupQueue)
        timer.schedule(deadline: .now() + Self.idleTimeout,
                      repeating: Self.idleTimeout, leeway: .seconds(5))
        timer.setEventHandler { [weak self] in
            self?.cleanupIdleSessions()
        }
        timer.resume()
        cleanupTimer = timer
    }

    private func cleanupIdleSessions() {
        lock.lock()
        let now = Date()
        var sessionsToClose: [HTTP3Session] = []

        for key in sessions.keys {
            sessions[key]?.removeAll { session in
                if session.poolIsClosed {
                    lastActivity.removeValue(forKey: ObjectIdentifier(session))
                    return true
                }
                // Never evict sessions that still have active streams.
                if !session.hasActiveStreams,
                   let activity = lastActivity[ObjectIdentifier(session)],
                   now.timeIntervalSince(activity) > Self.idleTimeout {
                    lastActivity.removeValue(forKey: ObjectIdentifier(session))
                    sessionsToClose.append(session)
                    return true
                }
                return false
            }
            if sessions[key]?.isEmpty == true {
                sessions.removeValue(forKey: key)
            }
        }
        lock.unlock()

        for session in sessionsToClose {
            session.close()
        }
    }

    /// Closes every pooled session and clears the activity table.
    override func closeAll() {
        lock.lock()
        lastActivity.removeAll()
        lock.unlock()

        super.closeAll()
    }
}
