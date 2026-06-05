//
//  ConnectionStatsModel.swift
//  Anywhere
//
//  Created by NodePassProject on 3/29/26.
//

import Foundation
import NetworkExtension
import Observation

/// One second of traffic telemetry in ``ConnectionStatsModel/samples``.
struct TrafficSample: Identifiable, Sendable {
    /// Monotonic sequence number; also the natural chart x-position.
    let id: UInt64
    /// Bytes received during this second (throughput, not a running total).
    let bytesIn: Int64
    /// Bytes sent during this second.
    let bytesOut: Int64
    /// Active TCP connections at sample time.
    let tcpConnections: Int
    /// Active UDP flows at sample time.
    let udpConnections: Int
    /// Extension memory footprint at sample time, in bytes.
    let memoryBytes: UInt64
}

/// Isolated model for VPN traffic statistics.
///
/// Polls the extension once per second while connected. Publishes the running
/// `bytesIn`/`bytesOut` totals, the latest connection-count and memory gauges,
/// and a rolling 60-second window of ``samples`` for time-series display.
@MainActor
@Observable
class ConnectionStatsModel {
    static let shared = ConnectionStatsModel()

    /// Cumulative byte totals for the session (shown on the home / TV screens).
    private(set) var bytesIn: Int64 = 0
    private(set) var bytesOut: Int64 = 0

    /// Latest instantaneous gauges, refreshed on every poll.
    private(set) var tcpConnections: Int = 0
    private(set) var udpConnections: Int = 0
    private(set) var memoryBytes: UInt64 = 0

    /// Rolling window of the most recent ``maxSamples`` seconds, one entry per
    /// poll, oldest first.
    private(set) var samples: [TrafficSample] = []

    /// 60 samples at 1 Hz → the last ~60 seconds.
    static let maxSamples = 60

    @ObservationIgnored private var statsTask: Task<Void, Never>?
    @ObservationIgnored private weak var session: NETunnelProviderSession?

    // Baseline for turning cumulative byte totals into per-second throughput.
    @ObservationIgnored private var lastBytesIn: Int64 = 0
    @ObservationIgnored private var lastBytesOut: Int64 = 0
    @ObservationIgnored private var hasBaseline = false
    @ObservationIgnored private var sampleSeq: UInt64 = 0

    func startPolling(session: NETunnelProviderSession) {
        self.session = session
        guard statsTask == nil else { return }
        statsTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, !Task.isCancelled else { break }
                await self.pollStats()
            }
        }
    }

    func stopPolling() {
        statsTask?.cancel()
        statsTask = nil
        session = nil
    }

    func reset() {
        bytesIn = 0
        bytesOut = 0
        tcpConnections = 0
        udpConnections = 0
        memoryBytes = 0
        samples = []
        lastBytesIn = 0
        lastBytesOut = 0
        hasBaseline = false
        sampleSeq = 0
    }

    private func pollStats() async {
        guard let session else { return }
        guard let data = try? JSONEncoder().encode(TunnelMessage.fetchStats) else { return }

        let response: Data? = await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }

        guard let response,
              let stats = try? JSONDecoder().decode(StatsResponse.self, from: response) else { return }
        self.bytesIn = stats.bytesIn
        self.bytesOut = stats.bytesOut
        self.tcpConnections = stats.tcpConnections
        self.udpConnections = stats.udpConnections
        self.memoryBytes = stats.memoryBytes
        appendSample(stats)
    }

    /// Appends one entry to the rolling window, converting the cumulative byte
    /// totals into per-second throughput. The first poll only seeds the
    /// baseline (throughput 0), so a carried-over total can't spike the graph;
    /// counter resets are clamped to 0 for the same reason.
    private func appendSample(_ stats: StatsResponse) {
        let inDelta = hasBaseline ? max(0, stats.bytesIn - lastBytesIn) : 0
        let outDelta = hasBaseline ? max(0, stats.bytesOut - lastBytesOut) : 0
        lastBytesIn = stats.bytesIn
        lastBytesOut = stats.bytesOut
        hasBaseline = true

        sampleSeq += 1
        samples.append(TrafficSample(
            id: sampleSeq,
            bytesIn: inDelta,
            bytesOut: outDelta,
            tcpConnections: stats.tcpConnections,
            udpConnections: stats.udpConnections,
            memoryBytes: stats.memoryBytes
        ))
        if samples.count > Self.maxSamples {
            samples.removeFirst(samples.count - Self.maxSamples)
        }
    }
}

#if DEBUG
extension ConnectionStatsModel {
    /// A model pre-filled with a full 60-second synthetic window for SwiftUI
    /// previews and tests. The `private(set)` properties are file-scoped, so the
    /// seeder lives here alongside the model rather than in the view file.
    static func previewSeeded() -> ConnectionStatsModel {
        let model = ConnectionStatsModel()
        var samples: [TrafficSample] = []
        for i in 0..<maxSamples {
            let t = Double(i)
            samples.append(TrafficSample(
                id: UInt64(i + 1),
                bytesIn: Int64(400_000 + 350_000 * (sin(t / 6) + 1)),
                bytesOut: Int64(120_000 + 90_000 * (cos(t / 5) + 1)),
                tcpConnections: Int(max(0, 8 + 6 * sin(t / 8))),
                udpConnections: Int(max(0, 3 + 3 * cos(t / 7))),
                memoryBytes: UInt64(max(0, 28_000_000 + 4_000_000 * sin(t / 10)))
            ))
        }
        model.samples = samples
        model.bytesIn = 1_840_000_000
        model.bytesOut = 320_000_000
        model.tcpConnections = samples.last?.tcpConnections ?? 0
        model.udpConnections = samples.last?.udpConnections ?? 0
        model.memoryBytes = samples.last?.memoryBytes ?? 0
        return model
    }
}
#endif
