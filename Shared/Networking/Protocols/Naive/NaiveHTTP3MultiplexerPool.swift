//
//  NaiveHTTP3MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "NaiveHTTP3MultiplexerPool")

/// Pools HTTP3Multiplexer QUIC connections for reuse across CONNECT streams,
/// with idle eviction and soft/hard caps.
nonisolated final class NaiveHTTP3MultiplexerPool: MultiplexerPool<HTTP3Multiplexer> {

    static let shared = NaiveHTTP3MultiplexerPool()

    private var lastActivity: [ObjectIdentifier: CFAbsoluteTime] = [:]

    /// Soft cap: try to evict an idle multiplexer before creating a new one.
    private static let maxSessionsPerKey = 8

    /// Hard cap: beyond this, pile onto the least-loaded multiplexer instead of opening another.
    private static let hardMaxMultiplexersPerKey = 16

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
        completion: @escaping (NaiveHTTP3Stream) -> Void
    ) {
        let key = Self.makeKey(host: host, port: port, sni: sni)
        let multiplexer: HTTP3Multiplexer

        lock.lock()

        evictStale(key: key)

        if let existing = multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(existing)] = CFAbsoluteTimeGetCurrent()
            multiplexer = existing
        } else if let overflow = overflowSession(key: key) {
            lastActivity[ObjectIdentifier(overflow)] = CFAbsoluteTimeGetCurrent()
            multiplexer = overflow
        } else {
            // Never close a multiplexer with live streams; evict an idle one if
            // possible, otherwise grow past the soft cap up to the hard cap.
            let currentCount = multiplexers[key]?.count ?? 0
            if currentCount >= Self.maxSessionsPerKey {
                if let victim = multiplexers[key]?.first(where: { !$0.hasActiveStreams }) {
                    lock.unlock()
                    victim.close()
                    lock.lock()
                    multiplexers[key]?.removeAll { $0 === victim }
                    lastActivity.removeValue(forKey: ObjectIdentifier(victim))
                }
            }

            let new = HTTP3Multiplexer(
                host: host, port: port, serverName: sni
            )
            let capturedKey = key
            new.onClose = { [weak self, weak new] in
                guard let self, let new else { return }
                self.removeMultiplexer(new, key: capturedKey)
            }
            multiplexers[key, default: []].append(new)
            lastActivity[ObjectIdentifier(new)] = CFAbsoluteTimeGetCurrent()
            multiplexer = new
        }
        lock.unlock()

        multiplexer.queue.async {
            multiplexer.noteStreamStarted()
            let stream = NaiveHTTP3Stream(multiplexer: multiplexer, configuration: configuration, destination: destination)
            completion(stream)
        }
    }

    /// Returns the least-loaded multiplexer when the pool is at its hard cap.
    /// Must be called with `lock` held.
    private func overflowSession(key: String) -> HTTP3Multiplexer? {
        guard let pool = multiplexers[key], pool.count >= Self.hardMaxMultiplexersPerKey else {
            return nil
        }
        let candidate = pool
            .filter { !$0.isClosed && !$0.poolIsStreamBlocked }
            .min(by: { $0.activeStreamCount < $1.activeStreamCount })
        guard let candidate, candidate.forceReserveStream() else { return nil }
        logger.warning("[HTTP3Pool] Pool hit hard cap (\(Self.hardMaxMultiplexersPerKey)) for \(key); overflowing onto existing multiplexer")
        return candidate
    }

    // MARK: - Eviction

    /// Removes closed, stream-blocked, and idle multiplexers. Must be called with ``lock`` held.
    private func evictStale(key: String) {
        let now = CFAbsoluteTimeGetCurrent()
        multiplexers[key]?.removeAll { multiplexer in
            if multiplexer.isClosed || multiplexer.poolIsStreamBlocked {
                lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                return true
            }
            if !multiplexer.hasActiveStreams,
               let activity = lastActivity[ObjectIdentifier(multiplexer)],
               now - activity > Self.idleTimeout {
                lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                DispatchQueue.global().async { multiplexer.close() }
                return true
            }
            return false
        }
        if multiplexers[key]?.isEmpty == true {
            multiplexers.removeValue(forKey: key)
        }
    }

    /// Also clears the activity record for the removed multiplexer.
    override func removeMultiplexer(_ multiplexer: HTTP3Multiplexer, key: String) {
        super.removeMultiplexer(multiplexer, key: key)
        lock.lock()
        lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
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
        var multiplexersToClose: [HTTP3Multiplexer] = []

        for key in multiplexers.keys {
            multiplexers[key]?.removeAll { multiplexer in
                if multiplexer.isClosed {
                    lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                    return true
                }
                // Never evict multiplexers that still have active streams.
                if !multiplexer.hasActiveStreams,
                   let activity = lastActivity[ObjectIdentifier(multiplexer)],
                   now - activity > Self.idleTimeout {
                    lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                    multiplexersToClose.append(multiplexer)
                    return true
                }
                return false
            }
            if multiplexers[key]?.isEmpty == true {
                multiplexers.removeValue(forKey: key)
            }
        }
        lock.unlock()

        for multiplexer in multiplexersToClose {
            multiplexer.close()
        }
    }

    override func closeAll() {
        lock.lock()
        lastActivity.removeAll()
        lock.unlock()

        super.closeAll()
    }
}
