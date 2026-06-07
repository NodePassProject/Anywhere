//
//  ConnectionMetrics.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// Most-recent connection-establishment timings, surfaced live in the home
/// stats cards.
///
/// Unlike the byte/connection/memory counters — read on demand from the tunnel
/// stack on each poll — dial and handshake durations are *events*: the data
/// plane stamps them here (via ``MetricTimer``) as connections come up, and the
/// extension's ``StatsRecorder`` reads the latest pair when the app polls.
///
/// "Newest data point" semantics: only the most recent measurement of each is
/// kept, cleared on ``reset()`` so a new tunnel session starts blank.
///
/// All timings are recorded through ``MetricTimer`` — the standard stopwatch for
/// any ``Metric`` — so the socket/proxy primitives carry no metrics logic. Both
/// figures reflect **proxied connections only**:
/// - Direct (bypass) connections dial a ``RawTCPSocket`` straight to the
///   destination without a ``ProxyClient``; those timers are disabled
///   (`enabled = false`), so their dials aren't counted (and a bypass connection
///   has no proxy handshake to record in the first place).
/// - Latency-test probes *are* proxied, but may target a config other than the
///   active tunnel, so ``LatencyTester`` brackets them with ``suspendRecording()``
///   / ``resumeRecording()`` to keep the live gauge tied to the active tunnel.
///
/// Because the handshake's dial subtraction (see ``record(_:_:)``) is global
/// rather than threaded per connection, the handshake is exact for serial setups
/// (the common case) and a close approximation under concurrent dials; it is
/// clamped at zero so it can never read negative.
///
/// Thread-safe: written from socket/proxy completion handlers on arbitrary
/// queues, read from the IPC message handler. `nonisolated` (like the other
/// networking primitives) so it stays off the main actor under the project's
/// default-`MainActor` isolation; safety comes from the lock, not the actor.
nonisolated final class ConnectionMetrics: @unchecked Sendable {
    static let shared = ConnectionMetrics()

    /// A connection-establishment latency tracked for the live stats. To track a
    /// new timing, add a case here plus a branch in ``record(_:_:)`` and a field
    /// in ``Snapshot`` — ``MetricTimer`` then works for it unchanged.
    enum Metric {
        /// First-hop TCP connect — the "dial".
        case dial
        /// Full proxy setup, timed from the `connect` call to tunnel-ready (TLS +
        /// protocol handshake). The recorded span includes the dial; ``record(_:_:)``
        /// subtracts the latest dial so the figure is only the post-TCP work.
        case handshake
    }

    private let lock = NSLock()
    private var dialMs: Int?
    private var handshakeMs: Int?
    /// >0 while a latency-test probe is running; recording is suppressed so the
    /// probe's (possibly non-active-config) timings don't reach the live gauge.
    private var suspendDepth = 0

    struct Snapshot {
        let dialMs: Int?
        let handshakeMs: Int?
    }

    /// Records a measured latency for `metric` — called by ``MetricTimer``.
    /// No-op while recording is suspended (a latency-test probe).
    func record(_ metric: Metric, _ duration: Duration) {
        let ms = max(0, duration.milliseconds)
        lock.lock()
        if suspendDepth == 0 {
            switch metric {
            case .dial:
                dialMs = ms
            case .handshake:
                // The span includes the dial; subtract it to leave the post-TCP
                // handshake. Fall back to the full span when no dial is known
                // (e.g. a QUIC-only transport that never opens a RawTCPSocket).
                handshakeMs = dialMs.map { max(0, ms - $0) } ?? ms
            }
        }
        lock.unlock()
    }

    /// Brackets a latency-test probe so its timings are not recorded — the probe
    /// may target a config other than the active tunnel. Re-entrant via a depth
    /// counter, so concurrent probes are safe; pair with ``resumeRecording()``
    /// (ideally via `defer`).
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
