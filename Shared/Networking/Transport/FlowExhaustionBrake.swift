//
//  FlowExhaustionBrake.swift
//  Anywhere
//
//  Created by NodePassProject on 7/6/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "FlowExhaustionBrake")

nonisolated final class FlowExhaustionBrake: Sendable {
    static let shared = FlowExhaustionBrake()

    private static let baseInterval: TimeInterval = 5
    private static let maxInterval: TimeInterval = 60
    /// A re-trip within this window of the previous one doubles the interval;
    /// later re-trips start over at ``baseInterval``.
    private static let escalationWindow: TimeInterval = 120

    private struct State {
        var brakeUntil: TimeInterval = 0
        var interval: TimeInterval = 0
        var lastTrip: TimeInterval = 0
    }

    private let state = Mutex(State())

    private init() {}

    var isBraking: Bool {
        state.withLock { MonotonicClock.now < $0.brakeUntil }
    }

    /// Seconds until release, or 0 when open; sampled by `DialDiagnostics`.
    var remainingSeconds: TimeInterval {
        state.withLock { max(0, $0.brakeUntil - MonotonicClock.now) }
    }

    /// A dial failed on kernel resource exhaustion. Trips (or re-trips) the
    /// brake; failures of dials already in flight while braking add no new
    /// information and don't extend it.
    func recordExhaustion() {
        let engaged: TimeInterval? = state.withLock { state in
            let now = MonotonicClock.now
            guard now >= state.brakeUntil else { return nil }
            if state.lastTrip > 0, now - state.lastTrip < Self.escalationWindow {
                state.interval = min(max(state.interval, Self.baseInterval) * 2, Self.maxInterval)
            } else {
                state.interval = Self.baseInterval
            }
            state.lastTrip = now
            state.brakeUntil = now + state.interval
            return state.interval
        }
        if let engaged {
            logger.warning("[Flow] kernel flow exhaustion: shedding new connections for \(Int(engaged))s [flows=\(FlowGauge.live)/\(TunnelLimits.flowBudget) pending=\(FlowGauge.pendingTCP) udp=\(FlowGauge.liveUDP)]")
        }
    }

    /// A dial created a kernel socket — evidence of headroom. Resets the
    /// escalation ladder unless the brake is still engaged: a success
    /// mid-brake is an in-flight straggler that got a freed slot, not proof
    /// the exhaustion cleared.
    func recordRecovery() {
        state.withLock { state in
            guard MonotonicClock.now >= state.brakeUntil else { return }
            state.interval = 0
            state.lastTrip = 0
        }
    }
}
