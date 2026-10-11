//
//  DeliveryRateSampler.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct DeliverySnapshot {
    var delivered: UInt64
    var deliveredAt: Nanoseconds
    var firstSentAt: Nanoseconds
    var isApplicationLimited: Bool
}

public struct QUICDeliveryRateSample: Sendable {
    public var bytesPerSecond: UInt64
    public var priorDelivered: UInt64
    public var totalDelivered: UInt64
    public var isApplicationLimited: Bool
}

struct DeliveryRateSampler {
    var delivered: UInt64 = 0
    var deliveredAt: Nanoseconds = 0
    var firstSentAt: Nanoseconds = 0
    var applicationLimitedUntil: UInt64 = 0

    mutating func onSend(now: Nanoseconds, inFlight: UInt64, size: Int, applicationLimited: Bool) -> DeliverySnapshot {
        if inFlight == 0 {
            self.firstSentAt = now
            self.deliveredAt = now
        }
        if applicationLimited {
            self.applicationLimitedUntil = self.delivered.addingClamped(inFlight).addingClamped(UInt64(size))
        }
        return DeliverySnapshot(
            delivered: self.delivered,
            deliveredAt: self.deliveredAt,
            firstSentAt: self.firstSentAt,
            isApplicationLimited: self.applicationLimitedUntil > 0
        )
    }

    mutating func onACK(_ packets: [SentPacket], now: Nanoseconds) -> QUICDeliveryRateSample? {
        var newest: SentPacket?
        for packet in packets where packet.countsTowardCongestion {
            self.delivered = self.delivered.addingClamped(UInt64(packet.size))
            guard let snapshot = packet.deliverySnapshot else {
                continue
            }
            if newest == nil || snapshot.delivered >= newest!.deliverySnapshot!.delivered {
                newest = packet
            }
        }
        guard let packet = newest, let snapshot = packet.deliverySnapshot else {
            return nil
        }
        self.deliveredAt = now
        self.firstSentAt = packet.sentAt
        if self.delivered > self.applicationLimitedUntil {
            self.applicationLimitedUntil = 0
        }
        let interval = Swift.max(
            packet.sentAt.subtractingClamped(snapshot.firstSentAt),
            now.subtractingClamped(snapshot.deliveredAt)
        )
        guard interval > 0 else {
            return nil
        }
        let rate = Double(self.delivered - snapshot.delivered) * Double(Time.second) / Double(interval)
        return QUICDeliveryRateSample(
            bytesPerSecond: CongestionMath.integer(rate),
            priorDelivered: snapshot.delivered,
            totalDelivered: self.delivered,
            isApplicationLimited: snapshot.isApplicationLimited
        )
    }
}
