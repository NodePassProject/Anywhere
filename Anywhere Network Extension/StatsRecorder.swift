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

    /// Begins serving snapshots from `source`. Called once at tunnel start.
    func start(source: @escaping () -> RawValues) {
        self.source = source
    }

    /// Stops serving snapshots and clears the live connection timings so the
    /// next session starts blank.
    func stop() {
        source = nil
        ConnectionMetrics.shared.reset()
    }

    /// Builds a `StatsResponse` for the IPC reply from the current live values.
    func snapshot() -> StatsResponse {
        let live = source?()
        let counts = live?.byteCounts ?? TrafficByteCounts()
        let timings = ConnectionMetrics.shared.snapshot()
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
            dialMs: timings.dialMs,
            handshakeMs: timings.handshakeMs
        )
    }
}
