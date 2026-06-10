//
//  HTTP3SessionPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP3Pool")

/// Pools HTTP3Session QUIC connections for reuse across CONNECT streams,
/// with idle eviction and soft/hard caps.
nonisolated final class HTTP3SessionPool: SessionPool<HTTP3Session> {

    static let shared = HTTP3SessionPool()

    private var lastActivity: [ObjectIdentifier: CFAbsoluteTime] = [:]

    /// Soft cap: try to evict an idle session before creating a new one.
    private static let maxSessionsPerKey = 8

    /// Hard cap: beyond this, pile onto the least-loaded session instead of opening another.
    private static let hardMaxSessionsPerKey = 16

    private static let idleTimeout: TimeInterval = 60

    private var cleanupTimer: DispatchSourceTimer?
    private let cleanupQueue = DispatchQueue(label: AWCore.Identifier.http3PoolCleanupQueue)

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

        evictStale(key: key)

        if let existing = sessions[key]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(existing)] = CFAbsoluteTimeGetCurrent()
            session = existing
        } else if let overflow = overflowSession(key: key) {
            lastActivity[ObjectIdentifier(overflow)] = CFAbsoluteTimeGetCurrent()
            session = overflow
        } else {
            // Never close a session with live streams; evict an idle one if
            // possible, otherwise grow past the soft cap up to the hard cap.
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
                host: host, port: port, serverName: sni
            )
            let capturedKey = key
            new.onClose = { [weak self, weak new] in
                guard let self, let new else { return }
                self.removeSession(new, key: capturedKey)
            }
            sessions[key, default: []].append(new)
            lastActivity[ObjectIdentifier(new)] = CFAbsoluteTimeGetCurrent()
            session = new
        }
        lock.unlock()

        session.queue.async {
            session.noteStreamStarted()
            let stream = HTTP3Stream(session: session, configuration: configuration, destination: destination)
            completion(stream)
        }
    }

    /// Returns the least-loaded session when the pool is at its hard cap.
    /// Must be called with `lock` held.
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

    /// Removes closed, stream-blocked, and idle sessions. Must be called with ``lock`` held.
    private func evictStale(key: String) {
        let now = CFAbsoluteTimeGetCurrent()
        sessions[key]?.removeAll { session in
            if session.poolIsClosed || session.poolIsStreamBlocked {
                lastActivity.removeValue(forKey: ObjectIdentifier(session))
                return true
            }
            if !session.hasActiveStreams,
               let activity = lastActivity[ObjectIdentifier(session)],
               now - activity > Self.idleTimeout {
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

    /// Also clears the activity record for the removed session.
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
        let now = CFAbsoluteTimeGetCurrent()
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
                   now - activity > Self.idleTimeout {
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

    override func closeAll() {
        lock.lock()
        lastActivity.removeAll()
        lock.unlock()

        super.closeAll()
    }
}
