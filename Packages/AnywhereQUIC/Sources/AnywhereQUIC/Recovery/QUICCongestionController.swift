//
//  QUICCongestionController.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public struct QUICCongestionState: Sendable {
    public var congestionWindow: UInt64
    public var slowStartThreshold: UInt64
    public var pacingRate: UInt64
    public var sendQuantum: Int
    public internal(set) var bytesInFlight: UInt64
    public internal(set) var maxSendUDPPayloadSize: Int
    public var congestionRecoveryStartTime: QUICInstant?

    var latestRTTNanoseconds: Nanoseconds
    var minRTTNanoseconds: Nanoseconds
    var smoothedRTTNanoseconds: Nanoseconds
    var rttVarianceNanoseconds: Nanoseconds
    var firstRTTSampleTimeNanoseconds: Nanoseconds
    var initialRTTNanoseconds: Nanoseconds

    public var latestRTT: Duration { Duration(nanoseconds: self.latestRTTNanoseconds) }

    public var minRTT: Duration? {
        return self.minRTTNanoseconds == Time.never ? nil : Duration(nanoseconds: self.minRTTNanoseconds)
    }

    public var smoothedRTT: Duration { Duration(nanoseconds: self.smoothedRTTNanoseconds) }

    public var rttVariance: Duration { Duration(nanoseconds: self.rttVarianceNanoseconds) }

    public var hasRTTSample: Bool { self.firstRTTSampleTimeNanoseconds != Time.never }

    public var firstRTTSampleTime: QUICInstant? {
        return self.hasRTTSample ? QUICInstant(nanoseconds: self.firstRTTSampleTimeNanoseconds) : nil
    }

    init(initialRTT: Nanoseconds, maxSendUDPPayloadSize: Int) {
        self.congestionWindow = Self.initialCongestionWindow(maxSendUDPPayloadSize: maxSendUDPPayloadSize)
        self.slowStartThreshold = .max
        self.pacingRate = 0
        self.sendQuantum = 64 * 1024
        self.bytesInFlight = 0
        self.maxSendUDPPayloadSize = maxSendUDPPayloadSize
        self.congestionRecoveryStartTime = nil
        self.latestRTTNanoseconds = 0
        self.minRTTNanoseconds = Time.never
        self.smoothedRTTNanoseconds = initialRTT
        self.rttVarianceNanoseconds = initialRTT / 2
        self.firstRTTSampleTimeNanoseconds = Time.never
        self.initialRTTNanoseconds = initialRTT
    }

    public static func initialCongestionWindow(maxSendUDPPayloadSize: Int) -> UInt64 {
        let payload = UInt64(maxSendUDPPayloadSize)
        return Swift.min(10 * payload, Swift.max(2 * payload, 14720))
    }

    mutating func resetCongestion() {
        self.congestionWindow = Self.initialCongestionWindow(maxSendUDPPayloadSize: self.maxSendUDPPayloadSize)
        self.slowStartThreshold = .max
        self.congestionRecoveryStartTime = nil
        self.bytesInFlight = 0
        self.pacingRate = 0
        self.sendQuantum = 64 * 1024
    }

    mutating func resetRecovery() {
        self.latestRTTNanoseconds = 0
        self.minRTTNanoseconds = Time.never
        self.smoothedRTTNanoseconds = self.initialRTTNanoseconds
        self.rttVarianceNanoseconds = self.initialRTTNanoseconds / 2
        self.firstRTTSampleTimeNanoseconds = Time.never
    }

    mutating func updateRTT(
        sample: Nanoseconds,
        ackDelay: Nanoseconds,
        now: Nanoseconds,
        isHandshakeConfirmed: Bool,
        peerMaxACKDelay: Nanoseconds
    ) -> Bool {
        precondition(sample > 0)
        if self.minRTTNanoseconds == Time.never {
            self.latestRTTNanoseconds = sample
            self.minRTTNanoseconds = sample
            self.smoothedRTTNanoseconds = sample
            self.rttVarianceNanoseconds = sample / 2
            self.firstRTTSampleTimeNanoseconds = now
            return true
        }
        var delay = ackDelay
        if isHandshakeConfirmed {
            delay = Swift.min(delay, peerMaxACKDelay)
        } else if delay > 0, sample >= self.minRTTNanoseconds, sample < self.minRTTNanoseconds + delay {
            return false
        }
        self.latestRTTNanoseconds = sample
        self.minRTTNanoseconds = Swift.min(self.minRTTNanoseconds, sample)
        var adjusted = sample
        if adjusted >= self.minRTTNanoseconds + delay {
            adjusted -= delay
        }
        let difference = self.smoothedRTTNanoseconds > adjusted
            ? self.smoothedRTTNanoseconds - adjusted
            : adjusted - self.smoothedRTTNanoseconds
        self.rttVarianceNanoseconds = (self.rttVarianceNanoseconds * 3 + difference) / 4
        self.smoothedRTTNanoseconds = (self.smoothedRTTNanoseconds * 7 + adjusted) / 8
        return true
    }

    func pto(maxACKDelay: Nanoseconds) -> Nanoseconds {
        return self.smoothedRTTNanoseconds
            + Swift.max(4 * self.rttVarianceNanoseconds, Recovery.granularity)
            + maxACKDelay
    }

    var isInCongestionRecovery: Bool { self.congestionRecoveryStartTime != nil }

    func isInCongestionRecovery(sentAt: QUICInstant) -> Bool {
        guard let start = self.congestionRecoveryStartTime else {
            return false
        }
        return sentAt <= start
    }
}

public struct QUICSentPacketInfo: Sendable {
    public var packetNumber: UInt64
    public var size: Int
    public var sentAt: QUICInstant
    public var isACKEliciting: Bool
}

public struct QUICAcknowledgementSummary: Sendable {
    public var bytesDelivered: UInt64
    public var bytesLost: UInt64
    public var largestAcknowledgedSentAt: QUICInstant?
    public var rtt: Duration?
    public var deliveryRate: QUICDeliveryRateSample? = nil
}

public protocol QUICCongestionController: AnyObject {
    func reset(state: inout QUICCongestionState, now: QUICInstant)
    func onPacketSent(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant)
    func onPacketAcknowledged(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant)
    func onPacketLost(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant)
    func onCongestionEvent(
        largestLostSentAt: QUICInstant,
        summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    )
    func onPersistentCongestion(state: inout QUICCongestionState, now: QUICInstant)
    func onAcknowledgementReceived(
        _ summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    )
}

extension QUICCongestionController {
    public func onPacketSent(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant) { }

    public func onPacketLost(_ packet: QUICSentPacketInfo, state: inout QUICCongestionState, now: QUICInstant) { }

    public func onAcknowledgementReceived(
        _ summary: QUICAcknowledgementSummary,
        state: inout QUICCongestionState,
        now: QUICInstant
    ) { }
}

enum Recovery {
    static let packetThreshold: UInt64 = 3
    static let granularity: Nanoseconds = Time.millisecond
    static let persistentCongestionThreshold: Nanoseconds = 3
    static let maxPTOCount = 30
    static let maxPacketThreshold: UInt64 = 256

    static func lossDelay(state: QUICCongestionState) -> Nanoseconds {
        return Swift.max(Swift.max(state.latestRTTNanoseconds, state.smoothedRTTNanoseconds) * 9 / 8, Self.granularity)
    }
}

enum CongestionMath {
    static func integer(_ value: Double) -> UInt64 {
        guard value > 0 else {
            return 0
        }
        guard value < Double(UInt64.max) else {
            return .max
        }
        return UInt64(value)
    }

    static func setPacing(_ state: inout QUICCongestionState, rate: Double, minimumPackets: Int = 2) {
        state.pacingRate = Swift.max(1, Self.integer(rate))
        state.sendQuantum = Swift.max(
            minimumPackets * state.maxSendUDPPayloadSize,
            Int(Swift.min(UInt64(64 * 1024), state.pacingRate / 1000))
        )
    }
}
