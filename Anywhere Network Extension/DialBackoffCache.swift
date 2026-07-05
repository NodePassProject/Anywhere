//
//  DialBackoffCache.swift
//  Anywhere
//
//  Created by NodePassProject on 7/5/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "DialBackoffCache")

/// Negative cache for raw-IP direct dials that keep timing out (dead P2P/PCDN
/// peers): after repeated connect timeouts, SYNs get an immediate RST instead
/// of pinning a dial slot for the full deadline. Keyed by host alone — a dead
/// peer is dead on every port, so strikes accumulate and blocks apply per IP.
final class DialBackoffCache {
    static let shared = DialBackoffCache()

    private init() {}

    private struct Entry {
        var strikes: Int
        var lastStrike: TimeInterval
        var blockedUntil: TimeInterval
    }

    private var entries: [String: Entry] = [:]
    private var lastSweep: TimeInterval = 0

    func recordTimeout(host: String) {
        let now = MonotonicClock.now
        sweepIfDue(now: now)
        var entry = entries[host] ?? Entry(strikes: 0, lastStrike: now, blockedUntil: 0)
        if now - entry.lastStrike > TunnelConstants.dialBackoffStrikeWindow {
            entry.strikes = 0
        }
        entry.strikes += 1
        entry.lastStrike = now
        if entry.strikes >= TunnelConstants.dialBackoffStrikeThreshold {
            // Log only the transition into blocked, not each renewing strike.
            if now >= entry.blockedUntil {
                logger.debug("[TCP] dial backoff: blocking \(host) for \(Int(TunnelConstants.dialBackoffBlockInterval))s after \(entry.strikes) timeouts")
            }
            entry.blockedUntil = now + TunnelConstants.dialBackoffBlockInterval
        }
        entries[host] = entry
    }

    func shouldFastFail(host: String) -> Bool {
        MonotonicClock.now < (entries[host]?.blockedUntil ?? 0)
    }

    /// Clears strikes after a successful connect so a recovered host can't be
    /// re-blocked by a single later transient timeout.
    func recordSuccess(host: String) {
        entries.removeValue(forKey: host)
    }

    /// Destinations currently blocked; sampled by `DialDiagnostics`.
    var blockedCount: Int {
        let now = MonotonicClock.now
        return entries.values.reduce(0) { now < $1.blockedUntil ? $0 + 1 : $0 }
    }

    /// Reaps expired entries at most once per window; keeps the key set bounded.
    private func sweepIfDue(now: TimeInterval) {
        guard now - lastSweep > TunnelConstants.dialBackoffStrikeWindow
                || entries.count >= TunnelConstants.dialBackoffMaxEntries else { return }
        lastSweep = now
        entries = entries.filter { _, entry in
            now - entry.lastStrike <= TunnelConstants.dialBackoffStrikeWindow
                || now < entry.blockedUntil
        }
        if entries.count >= TunnelConstants.dialBackoffMaxEntries {
            // Still over cap after expiry — anomalous churn; start fresh rather
            // than track an unbounded key set.
            entries.removeAll(keepingCapacity: false)
        }
    }
}
