//
//  StatsRecorder.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation
import Synchronization

final class StatsRecorder: Sendable {
    struct RawValues {
        let byteCounts: TrafficByteCounts
        let tcpConnectionCount: Int
        let udpConnectionCount: Int
        let memoryBytes: UInt64
    }
    
    private struct State {
        var source: (() -> RawValues)?
        var startedAt: TimeInterval?
        var sleepSecondsAccumulated: TimeInterval = 0
        var sleepBeganAt: TimeInterval?
    }

    private let state = Mutex(State())
    
    func start(source: @escaping () -> RawValues) {
        state.withLock { state in
            state.source = source
            state.startedAt = MonotonicClock.now
            state.sleepSecondsAccumulated = 0
            state.sleepBeganAt = nil
        }
    }
    
    func stop() {
        state.withLock { state in
            state.source = nil
            state.startedAt = nil
            state.sleepSecondsAccumulated = 0
            state.sleepBeganAt = nil
        }
        ConnectionMetrics.shared.reset()
    }
    
    func noteSleep() {
        state.withLock { state in
            guard state.sleepBeganAt == nil else { return }
            state.sleepBeganAt = MonotonicClock.now
        }
    }
    
    func noteWake() {
        state.withLock { state in
            guard let sleepBeganAt = state.sleepBeganAt else { return }
            state.sleepSecondsAccumulated += MonotonicClock.now - sleepBeganAt
            state.sleepBeganAt = nil
        }
    }

    func snapshot() -> StatsResponse {
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
