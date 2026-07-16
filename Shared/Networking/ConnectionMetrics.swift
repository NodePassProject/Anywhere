//
//  ConnectionMetrics.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation
import Synchronization

/// Default outbound proxy only. Handshake subtraction is global, so timings are
/// approximate under concurrent dials; clamped at zero.
nonisolated final class ConnectionMetrics: Sendable {
    static let shared = ConnectionMetrics()

    enum Metric {
        /// First-hop TCP connect — the "dial".
        case dial
        /// Full proxy setup span, includes the dial which `record` subtracts off.
        case handshake
        /// QUIC setup span — no first-hop TCP dial.
        case handshakeNoDial
    }

    private struct State {
        /// Parked until a default-proxy handshake promotes it — the socket can't
        /// know its route at dial time.
        var pendingDialMs: Int?
        var dialMs: Int?
        var handshakeMs: Int?
        var dialTotalMs = 0
        var dialSampleCount = 0
        var handshakeTotalMs = 0
        var handshakeSampleCount = 0
        /// >0 while a latency-test probe is running; recording is suppressed.
        var suspendDepth = 0
    }

    private let state = Mutex(State())

    struct Snapshot {
        let dialMs: Int?
        let handshakeMs: Int?
        let avgDialMs: Int?
        let avgHandshakeMs: Int?
    }

    /// No-op while recording is suspended.
    func record(_ metric: Metric, _ duration: Duration) {
        let ms = max(0, duration.milliseconds)
        state.withLock { state in
            guard state.suspendDepth == 0 else { return }
            switch metric {
            case .dial:
                state.pendingDialMs = ms
            case .handshake:
                // Commit pending dial and post-TCP remainder for the same
                // connection; consume the dial so it isn't double-counted.
                let remainder: Int
                if let dial = state.pendingDialMs {
                    state.pendingDialMs = nil
                    state.dialMs = dial
                    state.dialTotalMs += dial
                    state.dialSampleCount += 1
                    remainder = max(0, ms - dial)
                } else {
                    remainder = ms
                }
                state.handshakeMs = remainder
                state.handshakeTotalMs += remainder
                state.handshakeSampleCount += 1
            case .handshakeNoDial:
                // QUIC: clear the dial gauge so the snapshot doesn't pair a stale dial
                // with this handshake.
                state.dialMs = nil
                state.handshakeMs = ms
                state.handshakeTotalMs += ms
                state.handshakeSampleCount += 1
            }
        }
    }

    /// Re-entrant; pair with `resumeRecording()`.
    func suspendRecording() {
        state.withLock { $0.suspendDepth += 1 }
    }

    func resumeRecording() {
        state.withLock { state in
            if state.suspendDepth > 0 { state.suspendDepth -= 1 }
        }
    }

    func snapshot() -> Snapshot {
        state.withLock { state in
            Snapshot(
                dialMs: state.dialMs,
                handshakeMs: state.handshakeMs,
                avgDialMs: state.dialSampleCount > 0 ? state.dialTotalMs / state.dialSampleCount : nil,
                avgHandshakeMs: state.handshakeSampleCount > 0 ? state.handshakeTotalMs / state.handshakeSampleCount : nil
            )
        }
    }

    func reset() {
        // Leaves `suspendDepth` untouched — a reset must not cancel an active suspension.
        state.withLock { state in
            state.pendingDialMs = nil
            state.dialMs = nil
            state.handshakeMs = nil
            state.dialTotalMs = 0
            state.dialSampleCount = 0
            state.handshakeTotalMs = 0
            state.handshakeSampleCount = 0
        }
    }
}

private extension Duration {
    nonisolated var milliseconds: Int {
        let components = self.components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
