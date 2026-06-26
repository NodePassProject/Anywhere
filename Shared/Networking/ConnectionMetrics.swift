//
//  ConnectionMetrics.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// Default outbound proxy only. Handshake subtraction is global, so timings are
/// approximate under concurrent dials; clamped at zero.
nonisolated final class ConnectionMetrics: @unchecked Sendable {
    static let shared = ConnectionMetrics()

    enum Metric {
        /// First-hop TCP connect — the "dial".
        case dial
        /// Full proxy setup span, includes the dial which `record` subtracts off.
        case handshake
        /// QUIC setup span — no first-hop TCP dial.
        case handshakeNoDial
    }

    private let lock = UnfairLock()
    /// Parked until a default-proxy handshake promotes it — the socket can't
    /// know its route at dial time.
    private var pendingDialMs: Int?
    private var dialMs: Int?
    private var handshakeMs: Int?
    private var dialTotalMs = 0
    private var dialSampleCount = 0
    private var handshakeTotalMs = 0
    private var handshakeSampleCount = 0
    /// >0 while a latency-test probe is running; recording is suppressed.
    private var suspendDepth = 0

    struct Snapshot {
        let dialMs: Int?
        let handshakeMs: Int?
        let avgDialMs: Int?
        let avgHandshakeMs: Int?
    }

    /// No-op while recording is suspended.
    func record(_ metric: Metric, _ duration: Duration) {
        let ms = max(0, duration.milliseconds)
        lock.lock()
        if suspendDepth == 0 {
            switch metric {
            case .dial:
                pendingDialMs = ms
            case .handshake:
                // Commit pending dial and post-TCP remainder for the same
                // connection; consume the dial so it isn't double-counted.
                let remainder: Int
                if let dial = pendingDialMs {
                    pendingDialMs = nil
                    dialMs = dial
                    dialTotalMs += dial
                    dialSampleCount += 1
                    remainder = max(0, ms - dial)
                } else {
                    remainder = ms
                }
                handshakeMs = remainder
                handshakeTotalMs += remainder
                handshakeSampleCount += 1
            case .handshakeNoDial:
                // QUIC: clear the dial gauge so a stale pending dial is never paired.
                dialMs = nil
                handshakeMs = ms
                handshakeTotalMs += ms
                handshakeSampleCount += 1
            }
        }
        lock.unlock()
    }

    /// Re-entrant; pair with `resumeRecording()`.
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
        return Snapshot(
            dialMs: dialMs,
            handshakeMs: handshakeMs,
            avgDialMs: dialSampleCount > 0 ? dialTotalMs / dialSampleCount : nil,
            avgHandshakeMs: handshakeSampleCount > 0 ? handshakeTotalMs / handshakeSampleCount : nil
        )
    }

    func reset() {
        lock.lock()
        pendingDialMs = nil
        dialMs = nil
        handshakeMs = nil
        dialTotalMs = 0
        dialSampleCount = 0
        handshakeTotalMs = 0
        handshakeSampleCount = 0
        lock.unlock()
    }
}

private extension Duration {
    nonisolated var milliseconds: Int {
        let components = self.components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
