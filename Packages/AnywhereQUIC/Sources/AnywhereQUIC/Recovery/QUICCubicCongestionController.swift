//
//  QUICCubicCongestionController.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

public final class QUICCubicCongestionController: QUICCongestionController {
    private var epoch: QUICInstant?
    private var lastMaximum = 0.0
    private var origin = 0.0
    private var k = 0.0
    private var renoWindow = 0.0
    private var fractionalGrowth = 0.0
    private var lastSentAt: QUICInstant?

    public init() { }

    public func reset(state: inout QUICCongestionState, now: QUICInstant) {
        self.epoch = nil
        self.lastMaximum = 0
        self.fractionalGrowth = 0
        self.lastSentAt = nil
        self.updatePacing(&state)
    }

    public func onPacketSent(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant) {
        if state.bytesInFlight == UInt64(packet.size), let last = self.lastSentAt, let epoch = self.epoch {
            self.epoch = epoch + now.duration(since: last)
        }
        self.lastSentAt = now
    }

    public func onPacketAcknowledged(
        _ packet: QUICSentPacketInfo,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        guard !state.isInCongestionRecovery(sentAt: packet.sentAt) else {
            return
        }
        if state.congestionWindow < state.slowStartThreshold {
            state.congestionWindow = state.congestionWindow.addingClamped(UInt64(packet.size))
            self.updatePacing(&state)
            return
        }
        let mss = Double(state.maxSendUDPPayloadSize)
        let window = Double(state.congestionWindow) / mss
        if self.epoch == nil {
            self.epoch = now
            self.renoWindow = window
            self.origin = Swift.max(self.lastMaximum, window)
            self.k = cbrt((self.origin - window) / 0.4)
        }
        let seconds = Double(now.nanoseconds.subtractingClamped(self.epoch!.nanoseconds)) / 1e9
        let rttNanoseconds = state.minRTTNanoseconds == Time.never
            ? state.smoothedRTTNanoseconds
            : state.minRTTNanoseconds
        let rtt = Double(rttNanoseconds) / 1e9
        let delta = seconds + rtt - self.k
        let target = Swift.max(window, Swift.min(0.4 * delta * delta * delta + self.origin, window * 1.5))
        let acknowledged = Double(packet.size) / mss
        self.renoWindow += (3 * 0.3 / 1.7) * acknowledged / Swift.max(self.renoWindow, 1)
        let increase = Swift.max((target - window) * acknowledged / Swift.max(window, 1), self.renoWindow - window)
        self.fractionalGrowth += Swift.max(0, increase * mss)
        let whole = CongestionMath.integer(self.fractionalGrowth)
        self.fractionalGrowth -= Double(whole)
        state.congestionWindow = state.congestionWindow.addingClamped(whole)
        self.updatePacing(&state)
    }

    public func onCongestionEvent(
        largestLostSentAt: QUICInstant,
        summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        guard !state.isInCongestionRecovery(sentAt: largestLostSentAt) else {
            return
        }
        let window = Double(state.congestionWindow) / Double(state.maxSendUDPPayloadSize)
        self.lastMaximum = window < self.lastMaximum ? window * 0.85 : window
        self.epoch = nil
        self.fractionalGrowth = 0
        state.congestionRecoveryStartTime = now
        state.congestionWindow = Swift.max(
            2 * UInt64(state.maxSendUDPPayloadSize),
            CongestionMath.integer(Double(state.congestionWindow) * 0.7)
        )
        state.slowStartThreshold = state.congestionWindow
        self.updatePacing(&state)
    }

    public func onPersistentCongestion(state: inout QUICCongestionState, now: QUICInstant) {
        self.epoch = nil
        self.lastMaximum = 0
        self.fractionalGrowth = 0
        state.congestionWindow = 2 * UInt64(state.maxSendUDPPayloadSize)
        state.congestionRecoveryStartTime = nil
        self.updatePacing(&state)
    }

    private func updatePacing(_ state: inout QUICCongestionState) {
        let rtt = Swift.max(state.smoothedRTTNanoseconds, Time.millisecond)
        CongestionMath.setPacing(
            &state,
            rate: 1.25 * Double(state.congestionWindow) * 1e9 / Double(rtt),
            minimumPackets: 10
        )
    }
}
