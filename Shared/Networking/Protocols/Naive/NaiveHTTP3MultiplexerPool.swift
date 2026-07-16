//
//  NaiveHTTP3MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

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
        destination: String
    ) async throws -> NaiveHTTP3Stream {
        let key = Self.makeKey(host: host, port: port, sni: sni)

        // A soft-cap eviction must close its victim off-lock (close() re-enters
        // removeMultiplexer via onClose), so that path splits into two lock holds;
        // every other path stays in a single hold, matching the original.
        enum Plan { case ready(HTTP3Multiplexer); case closeVictimThenCreate(HTTP3Multiplexer) }
        let plan: Plan = lock.withLock { _ in
            // Prune dead/stream-blocked muxes here; age-based idle eviction is the base's sweep.
            pruneDead(key: key)

            if let existing = multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
                lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
                return .ready(existing)
            }
            if let overflow = overflowSession(key: key) {
                lastActivity[ObjectIdentifier(overflow)] = MonotonicClock.now
                return .ready(overflow)
            }
            // Never close a multiplexer with live streams; evict an idle one if possible, else grow up to the hard cap.
            let currentCount = multiplexers[key]?.count ?? 0
            let softCap = policy?.softCapPerKey ?? 0
            if softCap > 0, currentCount >= softCap,
               let victim = multiplexers[key]?.first(where: { !$0.hasActiveStreams }) {
                return .closeVictimThenCreate(victim)
            }
            return .ready(makeAndRegisterMultiplexer(key: key, host: host, port: port, sni: sni))
        }

        let multiplexer: HTTP3Multiplexer
        switch plan {
        case .ready(let ready):
            multiplexer = ready
        case .closeVictimThenCreate(let victim):
            victim.close()
            multiplexer = lock.withLock { _ in
                multiplexers[key]?.removeAll { $0 === victim }
                lastActivity.removeValue(forKey: ObjectIdentifier(victim))
                return makeAndRegisterMultiplexer(key: key, host: host, port: port, sni: sni)
            }
        }

        // The async open runs after the pool gate is released (never hold `lock` across `await`).
        return await multiplexer.run {
            multiplexer.noteStreamStarted()
            return NaiveHTTP3Stream(multiplexer: multiplexer, configuration: configuration, destination: destination)
        }
    }

    /// Builds a fresh multiplexer, wires its self-eviction, and registers it. Must hold ``lock``.
    private func makeAndRegisterMultiplexer(key: String, host: String, port: UInt16, sni: String) -> HTTP3Multiplexer {
        let new = HTTP3Multiplexer(host: host, port: port, serverName: sni)
        new.onClose = { [weak self, weak new] in
            guard let self, let new else { return }
            self.removeMultiplexer(new, key: key)
        }
        multiplexers[key, default: []].append(new)
        lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
        return new
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
            if multiplexer.isClosed {
                lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                return true
            }
            if multiplexer.poolIsStreamBlocked && !multiplexer.hasActiveStreams {
                lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                multiplexer.close()
                return true
            }
            return false
        }
        if multiplexers[key]?.isEmpty == true {
            multiplexers.removeValue(forKey: key)
        }
    }
}
