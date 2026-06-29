//
//  NaiveHTTP3MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP3MultiplexerPool")

nonisolated final class NaiveHTTP3MultiplexerPool: MultiplexerPool<HTTP3Multiplexer> {

    static let shared = NaiveHTTP3MultiplexerPool()

    private static let poolPolicy = MultiplexerPolicy(
        idleTimeout: 60,
        idleCheckInterval: 60,
        softCapPerKey: 8,
        hardCapPerKey: 16
    )

    private override init() {
        super.init()
        startIdleEviction(Self.poolPolicy)
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

        // Prune dead/stream-blocked muxes here; age-based idle eviction is the base's sweep.
        pruneDead(key: key)

        if let existing = multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
            multiplexer = existing
        } else if let overflow = overflowSession(key: key) {
            lastActivity[ObjectIdentifier(overflow)] = MonotonicClock.now
            multiplexer = overflow
        } else {
            // Never close a multiplexer with live streams; evict an idle one if possible, else grow up to the hard cap.
            let currentCount = multiplexers[key]?.count ?? 0
            let softCap = policy?.softCapPerKey ?? 0
            if softCap > 0, currentCount >= softCap {
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
            lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
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
        let hardCap = policy?.hardCapPerKey ?? 0
        guard hardCap > 0, let pool = multiplexers[key], pool.count >= hardCap else {
            return nil
        }
        let candidate = pool
            .filter { !$0.isClosed && !$0.poolIsStreamBlocked }
            .min(by: { $0.activeStreamCount < $1.activeStreamCount })
        guard let candidate, candidate.forceReserveStream() else { return nil }
        logger.warning("[HTTP3Pool] Pool hit hard cap (\(policy?.hardCapPerKey ?? 0)) for \(key); overflowing onto existing multiplexer")
        return candidate
    }

    // MARK: - Eviction

    /// Removes closed/stream-blocked muxes (age-based eviction is the base's). Must hold ``lock``.
    private func pruneDead(key: String) {
        multiplexers[key]?.removeAll { multiplexer in
            if multiplexer.isClosed || multiplexer.poolIsStreamBlocked {
                lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                return true
            }
            return false
        }
        if multiplexers[key]?.isEmpty == true {
            multiplexers.removeValue(forKey: key)
        }
    }
}
