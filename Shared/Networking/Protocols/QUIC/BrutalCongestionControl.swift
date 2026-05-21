//
//  BrutalCongestionControl.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

// MARK: - BrutalCongestionControl

nonisolated final class BrutalCongestionControl {

    /// 5 seconds of per-second ack/loss slots — the window over which the
    /// observed loss rate is computed.
    private static let slotCount = 5
    /// Below this many ack+loss samples the loss rate is treated as 0 — too
    /// little data to react to.
    private static let minSampleCount: UInt64 = 50
    /// Cap the observed loss rate; beyond this ngtcp2 would grant a
    /// pathological cwnd and flood the link.
    private static let maxLossRate: Double = 0.2
    /// cwnd multiplier — Brutal overshoots to cover brief bursts of loss.
    private static let congestionWindowMultiplier: Double = 2.0
    /// Minimum cwnd in packets. 10 MSS matches RFC 6928 initial cwnd and
    /// keeps the connection from starving on tiny links — also acts as the
    /// safety net at very low RTT where the raw Brutal formula would
    /// otherwise compute a cwnd of only a few hundred bytes.
    private static let minCwndPackets: UInt64 = 10
    /// Flat cwnd seed used until ngtcp2 produces its first RTT sample.
    /// The Brutal formula (`bps * rtt * 2 / ackRate`) is only meaningful
    /// with a real RTT; without this seed, applying the formula with a
    /// synthetic RTT floor would produce a multi-MB cwnd at high `targetBps`
    /// and cause startup burst loss. A flat 10 KB seed avoids that.
    private static let initialCwndBytes: UInt64 = 10240

    private struct Slot {
        var secondMark: UInt64 = UInt64.max
        var ackCount: UInt64 = 0
        var lossCount: UInt64 = 0
    }

    /// Target send rate in bytes/sec. Updated post-auth when the server's
    /// Hysteria-CC-RX is known.
    private var targetBps: UInt64
    private var slots: [Slot] = Array(repeating: Slot(), count: slotCount)

    init(initialBps: UInt64) {
        self.targetBps = initialBps
    }

    /// Called from `HysteriaSession` once the server's CC-RX response is
    /// parsed. All operations happen on the QUIC queue, so no locking.
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

    /// Returns the index of the slot for `ts`, resetting it if a new second
    /// has started.
    private func slotIndex(for ts: UInt64) -> Int {
        let second = ts / 1_000_000_000
        let idx = Int(second % UInt64(slots.count))
        if slots[idx].secondMark != second {
            slots[idx] = Slot()
            slots[idx].secondMark = second
        }
        return idx
    }

    /// Computes loss rate over the last `slotCount` seconds — *including*
    /// the current (in-progress) second.
    ///
    /// Excluding the current second (a previous behaviour) starved the
    /// window of fresh samples and pinned `ackRate` at 1.0 for an extra
    /// second on bursty-loss startups — the cwnd inflation that Brutal does
    /// to compensate for loss then arrived a full second late. Slots whose
    /// `secondMark` doesn't match a recent second are ignored (stale /
    /// never updated).
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

    /// Recomputes `cstat->cwnd`, `pacing_interval_m`, and `send_quantum`
    /// from the target bandwidth, smoothed RTT, and recent loss rate.
    private func updateCwnd(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        guard targetBps > 0 else { return }

        let smoothedRtt = cstat.pointee.smoothed_rtt
        let mss = UInt64(cstat.pointee.max_tx_udp_payload_size)

        var lossRate = observedLossRate(at: ts)
        if lossRate < 0 { lossRate = 0 }
        if lossRate > Self.maxLossRate { lossRate = Self.maxLossRate }

        // Pace at `target / ackRate`: over time `paced_rate * ackRate ≈
        // target`. `maxLossRate` caps inflation at ~1.25× target.
        let ackRate = 1.0 - lossRate
        let pacingBps = Double(targetBps) / ackRate

        // Initial-cwnd window: ngtcp2 hasn't produced a smoothed RTT yet.
        // The Brutal formula (`bps * rtt * 2 / ackRate`) is only meaningful
        // with a real RTT — synthesising one with a floor produces a
        // multi-MB cwnd at high `targetBps` (e.g. 2.5 MB at 100 Mbit/s),
        // and the first burst is what causes startup loss. Use the flat
        // seed instead; the next pkt-acked callback brings a real RTT and
        // the formula takes over from there.
        let minCwnd = Self.minCwndPackets &* max(mss, 1)
        let cwnd: UInt64
        if smoothedRtt == 0 {
            cwnd = max(Self.initialCwndBytes, minCwnd)
        } else {
            // Brutal's window formula: bps * RTT * 2 / ackRate, with raw RTT
            // and no floor. A previous version clamped RTT at 50 ms; that
            // systematically inflated cwnd by 5-50× on low-RTT links and
            // could drive startup burst loss. `minCwnd` already bounds the
            // result from below for the unrealistically-fast case where the
            // formula would otherwise yield a few hundred bytes.
            let cwndBytes = pacingBps * Self.congestionWindowMultiplier * Double(smoothedRtt) / 1_000_000_000.0
            cwnd = max(UInt64(cwndBytes), minCwnd)
        }

        // ngtcp2 defines pacing_interval_m as (ns/byte) << 10 — i.e.
        // `wait_ns = (pktlen * pacing_interval_m) >> 10`, so
        // `pacing_interval_m = (1e9 / pacing_bps) * 1024`.
        let pacingIntervalM: UInt64
        if pacingBps >= 1.0 {
            let nsPerByte = 1_000_000_000.0 / pacingBps
            pacingIntervalM = UInt64(nsPerByte * 1024.0)
        } else {
            pacingIntervalM = 0 // library default pacing
        }

        // `send_quantum` is the max burst before re-pacing. Size it to
        // 1 ms of bytes at the current rate, floored at 10 MSS, capped
        // at 64 KB — without this update we'd inherit CUBIC's static
        // 10 MSS and cap single bursts around 14 KB.
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
    /// Associates `cc` with the Swift Brutal instance. Call once per QUIC
    /// connection, after `ngtcp2_swift_install_brutal`.
    static func register(_ brutal: BrutalCongestionControl, for cc: OpaquePointer) {
        brutalRegistryLock.lock()
        brutalRegistry[cc] = brutal
        brutalRegistryLock.unlock()
    }

    /// Drops the registration when a QUIC connection closes so the Swift
    /// instance can be released.
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

// The ngtcp2 CC packet/ack structs are forward-declared opaque in the
// Swift bridging header, so they surface here as `OpaquePointer`. Brutal
// doesn't need any field inside them — it only bumps ack/loss counters —
// so opaque is sufficient.

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
    // on_pkt_sent has no ts arg; sample from the same monotonic source
    // as QUICConnection.currentTimestamp so slot bookkeeping is consistent.
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
