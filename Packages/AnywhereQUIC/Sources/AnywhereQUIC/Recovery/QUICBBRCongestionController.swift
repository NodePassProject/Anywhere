//
//  QUICBBRCongestionController.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

public final class QUICBBRCongestionController: QUICCongestionController {
    private static let highGain = 2.885
    private static let gains: [Double] = [1.25, 0.75, 1, 1, 1, 1, 1, 1]

    enum Mode {
        case startup
        case drain
        case probeBandwidth
        case probeRTT
    }

    private(set) var mode: Mode = .startup
    private(set) var bandwidth: UInt64 = 0
    private var rounds: UInt64 = 0
    private var nextRoundDelivered: UInt64 = 0
    private var rates: [(round: UInt64, rate: UInt64)] = []
    private var fullBandwidth: UInt64 = 0
    private var plateauRounds = 0
    private var isPipeFull = false
    private var minRTT: Nanoseconds = Time.never
    private var minRTTStamp: Nanoseconds = 0
    private var cycleIndex = 0
    private var cycleStarted: Nanoseconds = 0
    private var probeRTTEnds: Nanoseconds?
    private var probeRTTRound: UInt64 = 0
    private var priorWindow: UInt64 = 0
    private var recoveryUntil: QUICInstant?
    private var packetConservation = false
    private var idleRestart = false

    public init() { }

    public func reset(state: inout QUICCongestionState, now: QUICInstant) {
        self.mode = .startup
        self.bandwidth = 0
        self.rounds = 0
        self.nextRoundDelivered = 0
        self.rates.removeAll(keepingCapacity: true)
        self.fullBandwidth = 0
        self.plateauRounds = 0
        self.isPipeFull = false
        self.minRTT = Time.never
        self.minRTTStamp = now.nanoseconds
        self.cycleStarted = now.nanoseconds
        self.probeRTTEnds = nil
        self.priorWindow = state.congestionWindow
        self.recoveryUntil = nil
        self.packetConservation = false
        self.idleRestart = false
        self.updatePacing(&state)
    }

    public func onPacketSent(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant) {
        if state.bytesInFlight == UInt64(packet.size) {
            self.idleRestart = true
            if self.mode == .probeBandwidth, self.bandwidth > 0 {
                CongestionMath.setPacing(&state, rate: Double(self.bandwidth))
            }
        }
    }

    public func onPacketAcknowledged(
        _ packet: QUICSentPacketInfo,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) { }

    public func onAcknowledgementReceived(
        _ summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        guard summary.bytesDelivered > 0 else {
            return
        }
        var isNewRound = false
        if let sample = summary.deliveryRate {
            if sample.priorDelivered >= self.nextRoundDelivered {
                self.nextRoundDelivered = sample.totalDelivered
                self.rounds += 1
                isNewRound = true
                self.packetConservation = false
            }
            if !sample.isApplicationLimited || sample.bytesPerSecond >= self.bandwidth {
                self.rates.removeAll { self.rounds - $0.round >= 10 }
                if let last = self.rates.indices.last, self.rates[last].round == self.rounds {
                    self.rates[last].rate = Swift.max(self.rates[last].rate, sample.bytesPerSecond)
                } else {
                    self.rates.append((self.rounds, sample.bytesPerSecond))
                }
                self.bandwidth = self.rates.map(\.rate).max() ?? sample.bytesPerSecond
            }
            if isNewRound, !sample.isApplicationLimited, !self.isPipeFull {
                if Double(self.bandwidth) >= Double(self.fullBandwidth) * 1.25 {
                    self.fullBandwidth = self.bandwidth
                    self.plateauRounds = 0
                } else {
                    self.plateauRounds += 1
                    self.isPipeFull = self.plateauRounds >= 3
                }
            }
        }
        let expired = Time.elapsed(self.minRTTStamp, 10 * Time.second, now.nanoseconds)
        if let rtt = summary.rtt {
            let sample = rtt.clampedNanoseconds
            if sample > 0, sample < self.minRTT || expired {
                self.minRTT = Swift.max(sample, 1)
                self.minRTTStamp = now.nanoseconds
            }
        }
        if expired, !self.idleRestart, self.mode != .probeRTT {
            self.priorWindow = Swift.max(self.priorWindow, state.congestionWindow)
            self.mode = .probeRTT
            self.probeRTTEnds = nil
        }
        if self.mode == .startup, self.isPipeFull {
            self.mode = .drain
        }
        if self.mode == .drain, state.bytesInFlight <= self.targetWindow(gain: 1, state: state) {
            self.enterProbeBandwidth(now: now)
        }
        if self.mode == .probeBandwidth {
            let elapsed = now.nanoseconds.subtractingClamped(self.cycleStarted)
            let roundTime = self.minRTT == Time.never ? state.smoothedRTTNanoseconds : self.minRTT
            let gain = Self.gains[self.cycleIndex]
            let fullCycle = elapsed >= roundTime
            let advance: Bool
            if gain > 1 {
                advance = fullCycle
                    && (summary.bytesLost > 0 || state.bytesInFlight >= self.targetWindow(gain: gain, state: state))
            } else if gain < 1 {
                advance = fullCycle || state.bytesInFlight <= self.targetWindow(gain: 1, state: state)
            } else {
                advance = fullCycle
            }
            if advance {
                self.cycleIndex = (self.cycleIndex + 1) % Self.gains.count
                self.cycleStarted = now.nanoseconds
            }
        }
        if self.mode == .probeRTT {
            if self.probeRTTEnds == nil, state.bytesInFlight <= UInt64(4 * state.maxSendUDPPayloadSize) {
                self.probeRTTEnds = now.nanoseconds.addingClamped(200 * Time.millisecond)
                self.probeRTTRound = self.rounds
            }
            if let ends = self.probeRTTEnds, now.nanoseconds >= ends, self.rounds > self.probeRTTRound {
                self.minRTTStamp = now.nanoseconds
                state.congestionWindow = Swift.max(state.congestionWindow, self.priorWindow)
                if self.isPipeFull {
                    self.enterProbeBandwidth(now: now)
                } else {
                    self.mode = .startup
                }
            }
        }
        self.updatePacing(&state)
        let minimum = UInt64(4 * state.maxSendUDPPayloadSize)
        if let recovery = self.recoveryUntil, let sent = summary.largestAcknowledgedSentAt, sent > recovery {
            self.recoveryUntil = nil
            self.packetConservation = false
            state.congestionWindow = Swift.max(state.congestionWindow, self.priorWindow)
        }
        if self.packetConservation {
            state.congestionWindow = Swift.max(
                state.congestionWindow,
                state.bytesInFlight.addingClamped(summary.bytesDelivered)
            )
        } else {
            let target = self.targetWindow(gain: 2, state: state)
            let totalDelivered = summary.deliveryRate?.totalDelivered ?? 0
            if self.isPipeFull {
                state.congestionWindow = Swift.min(target, state.congestionWindow.addingClamped(summary.bytesDelivered))
            } else if state.congestionWindow < target || totalDelivered < self.initialWindow(state) {
                state.congestionWindow = state.congestionWindow.addingClamped(summary.bytesDelivered)
            }
        }
        state.congestionWindow = Swift.max(minimum, state.congestionWindow)
        if self.mode == .probeRTT {
            state.congestionWindow = minimum
        }
        self.idleRestart = false
    }

    public func onCongestionEvent(
        largestLostSentAt: QUICInstant,
        summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) {
        if self.recoveryUntil == nil {
            self.priorWindow = state.congestionWindow
            self.packetConservation = true
            self.recoveryUntil = now
            state.congestionWindow = state.bytesInFlight.addingClamped(summary.bytesDelivered)
        }
        state.congestionWindow = Swift.max(
            UInt64(4 * state.maxSendUDPPayloadSize),
            state.congestionWindow.subtractingClamped(summary.bytesLost)
        )
    }

    public func onPersistentCongestion(state: inout QUICCongestionState, now: QUICInstant) {
        state.congestionWindow = UInt64(4 * state.maxSendUDPPayloadSize)
        self.reset(state: &state, now: now)
    }

    private func initialWindow(_ state: QUICCongestionState) -> UInt64 {
        return QUICCongestionState.initialCongestionWindow(maxSendUDPPayloadSize: state.maxSendUDPPayloadSize)
    }

    private func targetWindow(gain: Double, state: QUICCongestionState) -> UInt64 {
        guard self.bandwidth > 0, self.minRTT != Time.never else {
            return self.initialWindow(state)
        }
        let bdp = gain * Double(self.bandwidth) * Double(self.minRTT) / 1e9
        return CongestionMath.integer(bdp).addingClamped(UInt64(3 * state.sendQuantum))
    }

    private func updatePacing(_ state: inout QUICCongestionState) {
        let gain: Double
        switch self.mode {
        case .startup:
            gain = Self.highGain
        case .drain:
            gain = 1 / Self.highGain
        case .probeBandwidth:
            gain = Self.gains[self.cycleIndex]
        case .probeRTT:
            gain = 1
        }
        let rtt = Swift.max(state.smoothedRTTNanoseconds, Time.millisecond)
        let estimate = self.bandwidth > 0
            ? Double(self.bandwidth)
            : Double(self.initialWindow(state)) * 1e9 / Double(rtt)
        let rate = gain * estimate
        if self.isPipeFull || rate > Double(state.pacingRate) || self.mode != .startup {
            CongestionMath.setPacing(&state, rate: rate)
        }
    }

    private func enterProbeBandwidth(now: QUICInstant) {
        self.mode = .probeBandwidth
        self.cycleIndex = Int.random(in: 2..<Self.gains.count)
        self.cycleStarted = now.nanoseconds
    }
}
