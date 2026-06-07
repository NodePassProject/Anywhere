//
//  StatsRecorder.swift
//  Anywhere Network Extension
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation

final class StatsRecorder {
    struct RawValues {
        let cumulativeBytesIn: Int64
        let cumulativeBytesOut: Int64
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
        let timings = ConnectionMetrics.shared.snapshot()
        return StatsResponse(
            bytesIn: live?.cumulativeBytesIn ?? 0,
            bytesOut: live?.cumulativeBytesOut ?? 0,
            tcpConnectionCount: live?.tcpConnectionCount ?? 0,
            udpConnectionCount: live?.udpConnectionCount ?? 0,
            memoryBytes: live?.memoryBytes ?? 0,
            dialMs: timings.dialMs,
            handshakeMs: timings.handshakeMs
        )
    }
}
