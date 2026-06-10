//
//  ConnectionMetrics.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// Newest connection-establishment timings for the live home stats, reflecting
/// the default outbound proxy only. The handshake subtraction is global, so it
/// is approximate under concurrent dials; clamped at zero. Thread-safe via
/// lock; `nonisolated` to stay off the main actor.
nonisolated final class ConnectionMetrics: @unchecked Sendable {
    static let shared = ConnectionMetrics()

    /// A connection-establishment latency tracked for the live stats.
    enum Metric {
        /// First-hop TCP connect — the "dial".
        case dial
        /// Full proxy setup to tunnel-ready; the recorded span includes the
        /// dial, which `record(_:_:)` subtracts off.
        case handshake
        /// Full setup span for a QUIC transport (no first-hop TCP dial).
        case handshakeNoDial
    }

    private let lock = NSLock()
    /// Newest first-hop dial, parked until a default-proxy handshake promotes
    /// it — the socket can't know its route at dial time.
    private var pendingDialMs: Int?
    private var dialMs: Int?
    private var handshakeMs: Int?
    /// >0 while a latency-test probe is running; recording is suppressed.
    private var suspendDepth = 0

    struct Snapshot {
        let dialMs: Int?
        let handshakeMs: Int?
    }

    /// Records a measured latency; no-op while recording is suspended.
    func record(_ metric: Metric, _ duration: Duration) {
        let ms = max(0, duration.milliseconds)
        lock.lock()
        if suspendDepth == 0 {
            switch metric {
            case .dial:
                // Parked; committed only by the next default-proxy handshake.
                pendingDialMs = ms
            case .handshake:
                // Default proxy only: commit the pending dial and the post-TCP
                // remainder together for the same connection.
                if let dial = pendingDialMs {
                    dialMs = dial
                    handshakeMs = max(0, ms - dial)
                } else {
                    handshakeMs = ms
                }
            case .handshakeNoDial:
                // QUIC: clear the dial gauge so a stale pending dial is never paired.
                dialMs = nil
                handshakeMs = ms
            }
        }
        lock.unlock()
    }

    /// Suppresses recording during a latency-test probe; re-entrant, pair with
    /// `resumeRecording()`.
    func suspendRecording() {
        lock.lock()
        suspendDepth += 1
        lock.unlock()
    }

    func resumeRecording() {
        lock.lock()
        if suspendDepth > 0 { suspendDepth -= 1 }
        lock.unlock()
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(dialMs: dialMs, handshakeMs: handshakeMs)
    }

    func reset() {
        lock.lock()
        pendingDialMs = nil
        dialMs = nil
        handshakeMs = nil
        lock.unlock()
    }
}

private extension Duration {
    nonisolated var milliseconds: Int {
        let c = components
        return Int(c.seconds * 1_000 + c.attoseconds / 1_000_000_000_000_000)
    }
}
