//
//  BrutalCongestionControl.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

// MARK: - BrutalCongestionControl

final class BrutalCongestionControl {

    /// 5 seconds of per-second ack/loss slots (1 current + 4 history).
    private static let slotCount = 5
    /// Skip this many slots from the front when computing loss rate — the
    /// current second isn't closed yet so its ratio is noisy.
    private static let slotsToSkip = 1
    /// Below this many ack+loss samples the loss rate is treated as 0 — too
    /// little data to react to.
    private static let minSampleCount: UInt64 = 50
    /// Cap the observed loss rate; beyond this ngtcp2 would grant a
    /// pathological cwnd and flood the link.
    private static let maxLossRate: Double = 0.2
    /// cwnd multiplier — Brutal overshoots to cover brief bursts of loss.
    private static let congestionWindowMultiplier: Double = 2.0
    /// Minimum cwnd in packets. 10 MSS matches RFC 6928 initial cwnd and
    /// keeps the connection from starving on tiny links.
    private static let minCwndPackets: UInt64 = 10
    /// RTT floor used when ngtcp2 hasn't produced a sample yet (or reports
    /// an absurdly small value that would collapse cwnd).
    private static let minRTTNs: UInt64 = 50_000_000 // 50 ms

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
        updateCwnd(cstat: cstat)
    }

    func onPacketLost(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        let idx = slotIndex(for: ts)
        slots[idx].lossCount &+= 1
        updateCwnd(cstat: cstat)
    }

    func onAckReceived(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>, ts: UInt64) {
        updateCwnd(cstat: cstat)
    }

    func onPacketSent(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>) {
        updateCwnd(cstat: cstat)
    }

    func reset(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>) {
        for i in 0..<slots.count {
            slots[i] = Slot()
        }
        updateCwnd(cstat: cstat)
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

    /// Computes loss rate over the last (slotCount - slotsToSkip) seconds.
    /// Slots whose `secondMark` doesn't match a recent second are ignored —
    /// they're stale and were never updated.
    private func observedLossRate(at ts: UInt64) -> Double {
        let now = ts / 1_000_000_000
        var totalAck: UInt64 = 0
        var totalLoss: UInt64 = 0
        for i in Self.slotsToSkip..<Self.slotCount {
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

    /// Recomputes `cstat->cwnd` and `cstat->pacing_interval_m` from the
    /// target bandwidth, smoothed RTT, and recent loss rate.
    private func updateCwnd(cstat: UnsafeMutablePointer<ngtcp2_conn_stat>) {
        guard targetBps > 0 else { return }

        let rttNs = max(cstat.pointee.smoothed_rtt, Self.minRTTNs)
        let mss = UInt64(cstat.pointee.max_tx_udp_payload_size)

        var lossRate = observedLossRate(at: cstat.pointee.first_rtt_sample_ts &+ rttNs)
        if lossRate < 0 { lossRate = 0 }
        if lossRate > Self.maxLossRate { lossRate = Self.maxLossRate }

        // Inflate the send rate so (rate * (1 - loss)) = target.
        let effectiveBps = Double(targetBps) / (1.0 - lossRate) * Self.congestionWindowMultiplier

        // cwnd bytes = effectiveBps * rttSeconds
        let cwndBytes = effectiveBps * Double(rttNs) / 1_000_000_000.0
        let minCwnd = Self.minCwndPackets &* max(mss, 1)
        let cwnd = max(UInt64(cwndBytes), minCwnd)

        // pacing_interval_m = (1 / pacing_rate) * MSS, in units of 1/1024 ns.
        // ngtcp2 schedules one MSS per interval, so interval = MSS / rate.
        // Divide-by-zero guarded by the `targetBps > 0` check above and the
        // constant multiplier ensures effectiveBps > 0.
        let pacingRateBps = effectiveBps
        let pacingIntervalM: UInt64
        if pacingRateBps >= 1.0 {
            let seconds = Double(mss) / pacingRateBps
            let nanos = seconds * 1_000_000_000.0
            pacingIntervalM = UInt64(nanos * 1024.0)
        } else {
            pacingIntervalM = 0 // "library default pacing"
        }

        cstat.pointee.cwnd = cwnd
        cstat.pointee.pacing_interval_m = pacingIntervalM
    }
}

// MARK: - Registry keyed by the `ngtcp2_cc *` the trampolines receive.

private let brutalRegistryLock = UnfairLock()
private var brutalRegistry: [OpaquePointer: BrutalCongestionControl] = [:]

/// Associates `cc` with the Swift Brutal instance. Call once per QUIC
/// connection, after `ngtcp2_swift_install_brutal`.
func brutalRegistryInstall(cc: OpaquePointer, brutal: BrutalCongestionControl) {
    brutalRegistryLock.lock()
    brutalRegistry[cc] = brutal
    brutalRegistryLock.unlock()
}

/// Drops the registration when a QUIC connection closes so the Swift
/// instance can be released.
func brutalRegistryRemove(cc: OpaquePointer) {
    brutalRegistryLock.lock()
    brutalRegistry.removeValue(forKey: cc)
    brutalRegistryLock.unlock()
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
    brutal.onPacketSent(cstat: cstat)
    _ = pkt
}

@_cdecl("ngtcp2_swift_brutal_reset")
func ngtcp2_swift_brutal_reset(
    cc: OpaquePointer?,
    cstat: UnsafeMutablePointer<ngtcp2_conn_stat>?,
    ts: UInt64
) {
    guard let cstat, let brutal = brutalForCC(cc) else { return }
    brutal.reset(cstat: cstat)
    _ = ts
}
