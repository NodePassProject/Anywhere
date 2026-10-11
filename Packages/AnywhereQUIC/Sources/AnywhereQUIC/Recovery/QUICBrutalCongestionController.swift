//
//  QUICBrutalCongestionController.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public final class QUICBrutalCongestionController: QUICCongestionController {
    private struct Slot {
        var second = UInt64.max
        var acknowledged: UInt64 = 0
        var lost: UInt64 = 0
    }

    public var bytesPerSecond: UInt64
    private var slots = [Slot](repeating: Slot(), count: 5)
    private let fallback = QUICCubicCongestionController()

    public init(bytesPerSecond: UInt64) {
        self.bytesPerSecond = bytesPerSecond
    }

    public func reset(state: inout QUICCongestionState, now: QUICInstant) {
        self.slots = [Slot](repeating: Slot(), count: 5)
        self.fallback.reset(state: &state, now: now)
        self.update(&state, now: now)
    }

    public func onPacketSent(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant) {
        self.fallback.onPacketSent(packet, state: &state, now: now)
        self.update(&state, now: now)
    }

    public func onPacketAcknowledged(
        _ packet: QUICSentPacketInfo,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        self.record(lost: false, now: now)
        if self.bytesPerSecond == 0 {
            self.fallback.onPacketAcknowledged(packet, state: &state, now: now)
        }
        self.update(&state, now: now)
    }

    public func onPacketLost(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant) {
        self.record(lost: true, now: now)
        self.update(&state, now: now)
    }

    public func onAcknowledgementReceived(
        _ summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        self.update(&state, now: now)
    }

    public func onCongestionEvent(
        largestLostSentAt: QUICInstant,
        summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        if self.bytesPerSecond == 0 {
            self.fallback.onCongestionEvent(
                largestLostSentAt: largestLostSentAt,
                summary: summary,
                state: &state,
                now: now
            )
        }
    }

    public func onPersistentCongestion(state: inout QUICCongestionState, now: QUICInstant) {
        if self.bytesPerSecond == 0 {
            self.fallback.onPersistentCongestion(state: &state, now: now)
        }
        self.update(&state, now: now)
    }

    private func record(lost: Bool, now: QUICInstant) {
        let second = now.nanoseconds / Time.second
        let index = Int(second % 5)
        if self.slots[index].second != second {
            self.slots[index] = Slot(second: second)
        }
        if lost {
            self.slots[index].lost += 1
        } else {
            self.slots[index].acknowledged += 1
        }
    }

    private func update(_ state: inout QUICCongestionState, now: QUICInstant) {
        guard self.bytesPerSecond > 0 else {
            return
        }
        let second = now.nanoseconds / Time.second
        var lost: UInt64 = 0
        var acknowledged: UInt64 = 0
        for slot in self.slots where slot.second <= second && second - slot.second < 5 {
            lost += slot.lost
            acknowledged += slot.acknowledged
        }
        let count = lost + acknowledged
        let loss = count < 50 ? 0 : Swift.min(0.2, Double(lost) / Double(count))
        let rate = Double(self.bytesPerSecond) / (1 - loss)
        let minimum = UInt64(10 * state.maxSendUDPPayloadSize)
        state.congestionWindow = state.hasRTTSample
            ? Swift.max(minimum, CongestionMath.integer(rate * 2 * Double(state.smoothedRTTNanoseconds) / 1e9))
            : Swift.max(minimum, 10240)
        CongestionMath.setPacing(&state, rate: rate, minimumPackets: 10)
    }
}
