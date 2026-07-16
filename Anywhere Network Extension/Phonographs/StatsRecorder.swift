//
//  StatsRecorder.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation
import Synchronization

final class StatsRecorder: @unchecked Sendable {
    struct RawValues {
        let byteCounts: TrafficByteCounts
        let tcpConnectionCount: Int
        let udpConnectionCount: Int
        let memoryBytes: UInt64
    }

    /// All timing state lives behind one mutex: `start` runs on the tunnel-start
    /// task, `noteSleep`/`noteWake` on the provider's sleep/wake overrides, and
    /// `snapshot` on the app-message handler — three distinct isolation contexts.
    private struct State {
        var source: (() -> RawValues)?
        var startedAt: TimeInterval?
        var sleepSecondsAccumulated: TimeInterval = 0
        /// Non-nil while the device is asleep (between `noteSleep` and `noteWake`).
        var sleepBeganAt: TimeInterval?
    }

    private let state = Mutex(State())

    /// Called once at tunnel start. The `source` closure is stored and later invoked
    /// under the mutex-guarded ``snapshot()``; `StatsRecorder`'s `@unchecked Sendable`
    /// covers holding this non-`Sendable` closure behind the lock.
    func start(source: @escaping () -> RawValues) {
        state.withLock { state in
            state.source = source
            state.startedAt = MonotonicClock.now
            state.sleepSecondsAccumulated = 0
            state.sleepBeganAt = nil
        }
    }

    /// Clears live connection timings so the next session starts blank.
    func stop() {
        state.withLock { state in
            state.source = nil
            state.startedAt = nil
            state.sleepSecondsAccumulated = 0
            state.sleepBeganAt = nil
        }
        ConnectionMetrics.shared.reset()
    }

    /// Marks the start of a device-sleep interval (`NEProvider.sleep`).
    func noteSleep() {
        state.withLock { state in
            guard state.sleepBeganAt == nil else { return }
            state.sleepBeganAt = MonotonicClock.now
        }
    }

    /// Closes the current device-sleep interval (`NEProvider.wake`).
    func noteWake() {
        state.withLock { state in
            guard let sleepBeganAt = state.sleepBeganAt else { return }
            state.sleepSecondsAccumulated += MonotonicClock.now - sleepBeganAt
            state.sleepBeganAt = nil
        }
    }

    func snapshot() -> StatsResponse {
        // Snapshot the timing state and the source closure under the lock, then
        // invoke `source` and build the response outside it (the closure reaches
        // into the tunnel stack and must not run under our mutex).
        let (source, startedAt, sleepSecondsAccumulated, sleepBeganAt) = state.withLock { state in
            (state.source, state.startedAt, state.sleepSecondsAccumulated, state.sleepBeganAt)
        }

        let live = source?()
        let counts = live?.byteCounts ?? TrafficByteCounts()
        let timings = ConnectionMetrics.shared.snapshot()
        let now = MonotonicClock.now
        let sleepSeconds = sleepSecondsAccumulated + (sleepBeganAt.map { now - $0 } ?? 0)
        let wakeSeconds = startedAt.map { max(now - $0 - sleepSeconds, 0) } ?? 0
        let routes: [RouteTrafficEntry] = counts.routes
            .map { target, value in
                RouteTrafficEntry(
                    target: target,
                    bytesIn: value.bytesIn,
                    bytesOut: value.bytesOut
                )
            }
            .sorted { $0.totalBytes > $1.totalBytes }
        return StatsResponse(
            bytesIn: counts.totalBytesIn,
            bytesOut: counts.totalBytesOut,
            routes: routes,
            tcpConnectionCount: live?.tcpConnectionCount ?? 0,
            udpConnectionCount: live?.udpConnectionCount ?? 0,
            memoryBytes: live?.memoryBytes ?? 0,
            wakeSeconds: wakeSeconds,
            sleepSeconds: sleepSeconds,
            dialMs: timings.dialMs,
            handshakeMs: timings.handshakeMs,
            avgDialMs: timings.avgDialMs,
            avgHandshakeMs: timings.avgHandshakeMs
        )
    }
}
