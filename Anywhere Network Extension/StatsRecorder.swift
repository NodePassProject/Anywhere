//
//  StatsRecorder.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation

final class StatsRecorder {
    struct RawValues {
        let byteCounts: TrafficByteCounts
        let tcpConnectionCount: Int
        let udpConnectionCount: Int
        let memoryBytes: UInt64
    }

    private var source: (() -> RawValues)?
    private var startedAt: TimeInterval?
    private var sleepSecondsAccumulated: TimeInterval = 0
    /// Non-nil while the device is asleep (between `noteSleep` and `noteWake`).
    private var sleepBeganAt: TimeInterval?

    /// Begins serving snapshots from `source`. Called once at tunnel start.
    func start(source: @escaping () -> RawValues) {
        self.source = source
        startedAt = MonotonicClock.now
        sleepSecondsAccumulated = 0
        sleepBeganAt = nil
    }

    /// Stops serving snapshots and clears the live connection timings so the
    /// next session starts blank.
    func stop() {
        source = nil
        startedAt = nil
        sleepSecondsAccumulated = 0
        sleepBeganAt = nil
        ConnectionMetrics.shared.reset()
    }

    /// Marks the start of a device-sleep interval (`NEProvider.sleep`).
    func noteSleep() {
        guard sleepBeganAt == nil else { return }
        sleepBeganAt = MonotonicClock.now
    }

    /// Closes the current device-sleep interval (`NEProvider.wake`).
    func noteWake() {
        guard let sleepBeganAt else { return }
        sleepSecondsAccumulated += MonotonicClock.now - sleepBeganAt
        self.sleepBeganAt = nil
    }

    /// Builds a `StatsResponse` for the IPC reply from the current live values.
    func snapshot() -> StatsResponse {
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
