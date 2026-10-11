//
//  QUICNewRenoCongestionController.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public final class QUICNewRenoCongestionController: QUICCongestionController {
    private static let pacingGainPercent: UInt64 = 125
    private var pendingAdd: UInt64 = 0

    public init() { }

    public func reset(state: inout QUICCongestionState, now: QUICInstant) {
        self.pendingAdd = 0
        Self.updatePacing(&state)
        state.sendQuantum = 10 * state.maxSendUDPPayloadSize
    }

    public func onPacketAcknowledged(
        _ packet: QUICSentPacketInfo,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        if state.isInCongestionRecovery(sentAt: packet.sentAt) {
            return
        }
        let size = UInt64(packet.size)
        if state.congestionWindow < state.slowStartThreshold {
            state.congestionWindow += size
            Self.updatePacing(&state)
            return
        }
        let increase = UInt64(state.maxSendUDPPayloadSize) * size + self.pendingAdd
        self.pendingAdd = increase % state.congestionWindow
        state.congestionWindow += increase / state.congestionWindow
        Self.updatePacing(&state)
    }

    public func onCongestionEvent(
        largestLostSentAt: QUICInstant,
        summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        if state.isInCongestionRecovery(sentAt: largestLostSentAt) {
            return
        }
        state.congestionRecoveryStartTime = now
        state.congestionWindow >>= 1
        state.congestionWindow = Swift.max(state.congestionWindow, 2 * UInt64(state.maxSendUDPPayloadSize))
        state.slowStartThreshold = state.congestionWindow
        self.pendingAdd = 0
        Self.updatePacing(&state)
    }

    public func onPersistentCongestion(state: inout QUICCongestionState, now: QUICInstant) {
        state.congestionWindow = 2 * UInt64(state.maxSendUDPPayloadSize)
        state.congestionRecoveryStartTime = nil
        Self.updatePacing(&state)
    }

    private static func updatePacing(_ state: inout QUICCongestionState) {
        let rtt = state.hasRTTSample ? Swift.max(state.smoothedRTTNanoseconds, 1) : Time.millisecond
        let window = Swift.max(state.congestionWindow, 1)
        let rate = window.multipliedReportingOverflow(by: Time.second * Self.pacingGainPercent / 100)
        state.pacingRate = rate.overflow ? .max : Swift.max(rate.partialValue / rtt, 1)
        let quantum = Swift.min(UInt64(64 * 1024), state.pacingRate / 1000)
        state.sendQuantum = Int(Swift.max(quantum, 10 * UInt64(state.maxSendUDPPayloadSize)))
    }
}
