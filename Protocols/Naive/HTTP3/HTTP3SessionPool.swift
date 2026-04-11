//
//  HTTP3SessionPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP3Pool")

class HTTP3SessionPool {

    static let shared = HTTP3SessionPool()

    private let lock = UnfairLock()

    /// Sessions keyed by "host:port:sni".
    private var sessions: [String: [HTTP3Session]] = [:]

    /// Last activity time per session (for idle eviction).
    private var lastActivity: [ObjectIdentifier: Date] = [:]

    /// Maximum sessions per pool key.
    private static let maxSessionsPerKey = 8

    /// Sessions idle longer than this are evicted.
    private static let idleTimeout: TimeInterval = 60

    /// Periodic cleanup timer.
    private var cleanupTimer: DispatchSourceTimer?
    private let cleanupQueue = DispatchQueue(label: "com.argsment.Anywhere.http3pool.cleanup")

    private init() {
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
        let key = "\(host):\(port):\(sni)"
        let session: HTTP3Session

        lock.lock()

        // Evict closed, stream-blocked, and idle sessions
        evictStale(key: key)

        if let existing = sessions[key]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(existing)] = Date()
            session = existing
        } else {
            // Enforce max sessions per key
            let currentCount = sessions[key]?.count ?? 0
            if currentCount >= Self.maxSessionsPerKey {
                // Evict the oldest session to make room
                if let oldest = sessions[key]?.first {
                    lock.unlock()
                    oldest.close()
                    lock.lock()
                    sessions[key]?.removeAll { $0 === oldest }
                    lastActivity.removeValue(forKey: ObjectIdentifier(oldest))
                }
            }

            let new = HTTP3Session(
                host: host, port: port, sni: sni, configuration: configuration
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

    // MARK: - Eviction

    private func evictStale(key: String) {
        let now = Date()
        sessions[key]?.removeAll { session in
            if session.poolIsClosed || session.poolIsStreamBlocked {
                lastActivity.removeValue(forKey: ObjectIdentifier(session))
                return true
            }
            // Only evict idle sessions that have NO active streams
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

    private func removeSession(_ session: HTTP3Session, key: String) {
        lock.lock()
        sessions[key]?.removeAll { $0 === session }
        lastActivity.removeValue(forKey: ObjectIdentifier(session))
        if sessions[key]?.isEmpty == true {
            sessions.removeValue(forKey: key)
        }
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
                // Never evict sessions that still have active streams
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

    /// Closes all pooled sessions.
    func closeAll() {
        lock.lock()
        let all = sessions.values.flatMap { $0 }
        sessions.removeAll()
        lastActivity.removeAll()
        lock.unlock()

        for session in all {
            session.close()
        }
    }
}
