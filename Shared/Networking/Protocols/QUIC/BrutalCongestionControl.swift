//
//  BrutalCongestionControl.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

// MARK: - BrutalCongestionControl

nonisolated final class BrutalCongestionControl {

    /// Seconds of per-second ack/loss slots over which the loss rate is computed.
    private static let slotCount = 5
    /// Below this many ack+loss samples the loss rate is treated as 0.
    private static let minSampleCount: UInt64 = 50
    /// Loss-rate cap; beyond this the cwnd grows pathologically and floods the link.
    private static let maxLossRate: Double = 0.2
    private static let congestionWindowMultiplier: Double = 2.0
    /// 10 MSS matches RFC 6928 initial cwnd.
    private static let minCwndPackets: UInt64 = 10
    /// Flat cwnd seed until the first RTT sample; the Brutal formula with a synthetic
    /// RTT floor inflates cwnd to multiple MB and causes startup burst loss.
    private static let initialCwndBytes: UInt64 = 10240

    private struct Slot {
        var secondMark: UInt64 = UInt64.max
        var ackCount: UInt64 = 0
        var lossCount: UInt64 = 0
    }

    /// Target send rate in bytes/sec. Updated post-auth.
    private var targetBps: UInt64
    private var slots: [Slot] = Array(repeating: Slot(), count: slotCount)

    init(initialBps: UInt64) {
        self.targetBps = initialBps
    }

    func setTargetBandwidth(_ bps: UInt64) {
        targetBps = bps
    }

    // MARK: - Callbacks (invoked from the ngtcp2 CC trampolines)

    func onPacketAcked(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        let idx = slotIndex(for: ts)
        slots[idx].ackCount &+= 1
        updateCwnd(cstat: cstat, ts: ts)
    }

    func onPacketLost(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        let idx = slotIndex(for: ts)
        slots[idx].lossCount &+= 1
        updateCwnd(cstat: cstat, ts: ts)
    }

    func onAckReceived(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        updateCwnd(cstat: cstat, ts: ts)
    }

    func onPacketSent(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        updateCwnd(cstat: cstat, ts: ts)
    }

    func reset(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        for i in 0..<slots.count {
            slots[i] = Slot()
        }
        updateCwnd(cstat: cstat, ts: ts)
    }

    // MARK: - Internals

    private func slotIndex(for ts: UInt64) -> Int {
        let second = ts / 1_000_000_000
        let idx = Int(second % UInt64(slots.count))
        if slots[idx].secondMark != second {
            slots[idx] = Slot()
            slots[idx].secondMark = second
        }
        return idx
    }

    /// Loss rate over the last `slotCount` seconds including the in-progress one;
    /// excluding it pins `ackRate` at 1.0 during bursty-loss startups.
    private func observedLossRate(at ts: UInt64) -> Double {
        let now = ts / 1_000_000_000
        var totalAck: UInt64 = 0
        var totalLoss: UInt64 = 0
        for i in 0..<Self.slotCount {
            let targetSecond = now &- UInt64(i)
            let idx = Int(targetSecond % UInt64(Self.slotCount))
            let slot = slots[idx]
            guard slot.secondMark == targetSecond else { continue }
            totalAck &+= slot.ackCount
            totalLoss &+= slot.lossCount
        }
        let total = totalAck &+ totalLoss
        if total < Self.minSampleCount { return 0 }
        return Double(totalLoss) / Double(total)
    }

    private func updateCwnd(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        guard targetBps > 0 else { return }

        let smoothedRtt = cstat.pointee.smoothed_rtt
        let mss = UInt64(cstat.pointee.max_tx_udp_payload_size)

        var lossRate = observedLossRate(at: ts)
        if lossRate < 0 { lossRate = 0 }
        if lossRate > Self.maxLossRate { lossRate = Self.maxLossRate }

        // Pace at target / ackRate so that over time paced_rate * ackRate ≈ target.
        let ackRate = 1.0 - lossRate
        let pacingBps = Double(targetBps) / ackRate

        // Flat seed until ngtcp2 produces a real smoothed RTT (see initialCwndBytes).
        let minCwnd = Self.minCwndPackets &* max(mss, 1)
        let cwnd: UInt64
        if smoothedRtt == 0 {
            cwnd = max(Self.initialCwndBytes, minCwnd)
        } else {
            // bps * RTT * 2 / ackRate, raw RTT with no floor (a 50 ms clamp
            // inflated cwnd 5-50× on low-RTT links).
            let cwndBytes = pacingBps * Self.congestionWindowMultiplier * Double(smoothedRtt) / 1_000_000_000.0
            cwnd = max(UInt64(cwndBytes), minCwnd)
        }

        // ngtcp2 defines pacing_interval_m as (ns/byte) << 10, so
        // pacing_interval_m = (1e9 / pacing_bps) * 1024.
        let pacingIntervalM: UInt64
        if pacingBps >= 1.0 {
            let nsPerByte = 1_000_000_000.0 / pacingBps
            pacingIntervalM = UInt64(nsPerByte * 1024.0)
        } else {
            pacingIntervalM = 0 // library default pacing
        }

        // send_quantum = 1 ms of bytes (floor 10 MSS, cap 64 KB); otherwise
        // we'd inherit CUBIC's static 10 MSS (~14 KB).
        let mssFloor = Self.minCwndPackets &* max(mss, 1)
        let bytesPerMs = pacingBps / 1000.0
        let cappedQuantum = UInt64(min(bytesPerMs, 64.0 * 1024.0))
        let sendQuantum = max(cappedQuantum, mssFloor)

        cstat.pointee.cwnd = cwnd
        cstat.pointee.pacing_interval_m = pacingIntervalM
        cstat.pointee.send_quantum = Int(sendQuantum)
    }
}

// MARK: - Registry keyed by the `ngtcp2_cc *` the trampolines receive.

private let brutalRegistryLock = UnfairLock()
private var brutalRegistry: [OpaquePointer: BrutalCongestionControl] = [:]

extension BrutalCongestionControl {
    /// Associates `cc` with its Swift Brutal instance. Call once per connection.
    static func register(_ brutal: BrutalCongestionControl, for cc: OpaquePointer) {
        brutalRegistryLock.lock()
        brutalRegistry[cc] = brutal
        brutalRegistryLock.unlock()
    }

    static func unregister(cc: OpaquePointer) {
        brutalRegistryLock.lock()
        brutalRegistry.removeValue(forKey: cc)
        brutalRegistryLock.unlock()
    }
}

private func brutalForCC(_ cc: OpaquePointer?) -> BrutalCongestionControl? {
    guard let cc else { return nil }
    brutalRegistryLock.lock()
    defer { brutalRegistryLock.unlock() }
    return brutalRegistry[cc]
}

// MARK: - @_cdecl trampolines (called by ngtcp2 via the CC callback table)

// The ngtcp2 CC packet/ack structs are forward-declared opaque in the bridging
// header; Brutal only bumps counters, so OpaquePointer is sufficient.

@_cdecl("ngtcp2_swift_brutal_on_pkt_acked")
func ngtcp2_swift_brutal_on_pkt_acked(
    cc: OpaquePointer?,
    cstat: UnsafeMutablePointer<ngtcp2_conn_stat>?,
    pkt: OpaquePointer?,
    ts: UInt64
) {
    guard let cstat, let brutal = brutalForCC(cc) else { return }
    brutal.onPacketAcked(cstat: cstat, ts: ts)
    _ = pkt
}

@_cdecl("ngtcp2_swift_brutal_on_pkt_lost")
func ngtcp2_swift_brutal_on_pkt_lost(
    cc: OpaquePointer?,
    cstat: UnsafeMutablePointer<ngtcp2_conn_stat>?,
    pkt: OpaquePointer?,
    ts: UInt64
) {
    guard let cstat, let brutal = brutalForCC(cc) else { return }
    brutal.onPacketLost(cstat: cstat, ts: ts)
    _ = pkt
}

@_cdecl("ngtcp2_swift_brutal_on_ack_recv")
func ngtcp2_swift_brutal_on_ack_recv(
    cc: OpaquePointer?,
    cstat: UnsafeMutablePointer<ngtcp2_conn_stat>?,
    ack: OpaquePointer?,
    ts: UInt64
) {
    guard let cstat, let brutal = brutalForCC(cc) else { return }
    brutal.onAckReceived(cstat: cstat, ts: ts)
    _ = ack
}

@_cdecl("ngtcp2_swift_brutal_on_pkt_sent")
func ngtcp2_swift_brutal_on_pkt_sent(
    cc: OpaquePointer?,
    cstat: UnsafeMutablePointer<ngtcp2_conn_stat>?,
    pkt: OpaquePointer?
) {
    guard let cstat, let brutal = brutalForCC(cc) else { return }
    // on_pkt_sent has no ts arg; sample the same monotonic clock as QUICConnection.
    brutal.onPacketSent(cstat: cstat, ts: DispatchTime.now().uptimeNanoseconds)
    _ = pkt
}

@_cdecl("ngtcp2_swift_brutal_reset")
func ngtcp2_swift_brutal_reset(
    cc: OpaquePointer?,
    cstat: UnsafeMutablePointer<ngtcp2_conn_stat>?,
    ts: UInt64
) {
    guard let cstat, let brutal = brutalForCC(cc) else { return }
    brutal.reset(cstat: cstat, ts: ts)
}
