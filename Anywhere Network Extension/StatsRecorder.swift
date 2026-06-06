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

    private static let maxSamples = 130
    private static let trimBatch = 10

    private var samples: [StatsSample] = []
    private var lastBytesIn: Int64 = 0
    private var lastBytesOut: Int64 = 0
    private var hasBaseline = false
    private var sampleSeq: UInt64 = 0
    private var task: Task<Void, Never>?
    private var source: (() -> RawValues)?

    func start(source: @escaping () -> RawValues) {
        guard task == nil else { return }
        self.source = source
        task = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, !Task.isCancelled else { break }
                self.tick()
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        source = nil
        samples = []
        lastBytesIn = 0
        lastBytesOut = 0
        hasBaseline = false
        sampleSeq = 0
    }

    /// Builds a `StatsResponse` for the IPC reply.
    func snapshot() -> StatsResponse {
        let live = source?()
        return StatsResponse(
            bytesIn: live?.cumulativeBytesIn ?? lastBytesIn,
            bytesOut: live?.cumulativeBytesOut ?? lastBytesOut,
            samples: samples
        )
    }

    private func tick() {
        guard let raw = source?() else { return }
        let inDelta = hasBaseline ? max(0, raw.cumulativeBytesIn - lastBytesIn) : 0
        let outDelta = hasBaseline ? max(0, raw.cumulativeBytesOut - lastBytesOut) : 0
        lastBytesIn = raw.cumulativeBytesIn
        lastBytesOut = raw.cumulativeBytesOut
        hasBaseline = true
        sampleSeq += 1
        samples.append(StatsSample(
            id: sampleSeq,
            bytesIn: inDelta,
            bytesOut: outDelta,
            tcpConnectionCount: raw.tcpConnectionCount,
            udpConnectionCount: raw.udpConnectionCount,
            memoryBytes: raw.memoryBytes
        ))
        if samples.count > Self.maxSamples {
            samples.removeFirst(Self.trimBatch)
        }
    }
}
