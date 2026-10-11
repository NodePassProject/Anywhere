//
//  ACKTracker.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct ACKTracker {
    static let maxRanges = ACKFrame.maxRanges + 1
    static let maxDuplicateRanges = 256

    private(set) var received = RangeSet()
    private(set) var seen = RangeSet()
    private(set) var largestReceived: UInt64?
    private(set) var largestReceivedAt: Nanoseconds = Time.never
    private(set) var firstUnacknowledgedAt: Nanoseconds = Time.never
    private(set) var ackElicitingSinceLastACK = 0
    private(set) var isImmediateACKRequired = false
    private(set) var isTimerCancelled = false
    private var largestACKElicitingReceived: UInt64?
    private var sentACKs: [(packetNumber: UInt64, largestAcknowledged: UInt64)] = []

    var hasPendingACK: Bool { self.firstUnacknowledgedAt != Time.never }

    func isDuplicate(_ packetNumber: UInt64) -> Bool {
        return self.seen.contains(packetNumber)
    }

    mutating func recordReceived(_ packetNumber: UInt64, isACKEliciting: Bool, now: Nanoseconds, ackThreshold: Int) {
        self.seen.insert(packetNumber)
        if self.seen.count > Self.maxDuplicateRanges {
            self.seen.fillFirstGap()
        }
        if isACKEliciting {
            if let largest = self.largestACKElicitingReceived {
                if packetNumber < largest {
                    self.isImmediateACKRequired = true
                } else if packetNumber != largest + 1, self.seen.firstMissing(from: largest) < packetNumber {
                    self.isImmediateACKRequired = true
                }
            }
            if self.largestACKElicitingReceived == nil || self.largestACKElicitingReceived! < packetNumber {
                self.largestACKElicitingReceived = packetNumber
            }
            if self.firstUnacknowledgedAt == Time.never {
                self.firstUnacknowledgedAt = now
            }
            self.ackElicitingSinceLastACK += 1
            if self.ackElicitingSinceLastACK >= ackThreshold {
                self.isImmediateACKRequired = true
            }
            self.isTimerCancelled = false
        }
        self.received.insert(packetNumber)
        if self.received.count > Self.maxRanges {
            self.received.removeFirst()
        }
        if self.largestReceived == nil || self.largestReceived! < packetNumber {
            self.largestReceived = packetNumber
            self.largestReceivedAt = now
        }
    }

    func requiresACK(maxACKDelay: Nanoseconds, now: Nanoseconds) -> Bool {
        guard self.hasPendingACK else {
            return false
        }
        if self.isImmediateACKRequired {
            return true
        }
        return Time.elapsed(self.firstUnacknowledgedAt, maxACKDelay, now)
    }

    func ackDelayExpiry(maxACKDelay: Nanoseconds) -> Nanoseconds {
        guard self.hasPendingACK, !self.isTimerCancelled else {
            return Time.never
        }
        if self.isImmediateACKRequired {
            return self.firstUnacknowledgedAt
        }
        return self.firstUnacknowledgedAt.addingClamped(maxACKDelay)
    }

    mutating func cancelExpiredTimer(maxACKDelay: Nanoseconds, now: Nanoseconds) {
        if !self.isTimerCancelled,
           self.hasPendingACK,
           self.isImmediateACKRequired || Time.elapsed(self.firstUnacknowledgedAt, maxACKDelay, now) {
            self.isTimerCancelled = true
        }
    }

    mutating func makeACKFrame(
        now: Nanoseconds,
        ackDelay: Nanoseconds,
        ackDelayExponent: UInt64,
        includeDelay: Bool
    ) -> ACKFrame? {
        let delay = self.isImmediateACKRequired ? 0 : ackDelay
        guard self.requiresACK(maxACKDelay: delay, now: now) else {
            return nil
        }
        guard let largestReceived = self.largestReceived, !self.received.isEmpty else {
            self.commitACK()
            return nil
        }
        let ranges = self.received.ranges.reversed()
        var frame = ACKFrame(
            largestAcknowledged: largestReceived,
            ackDelay: 0,
            firstRange: 0,
            additionalRanges: [],
            ecnCounts: nil
        )
        var remaining = ranges[...]
        if let first = remaining.first, first.upperBound >= largestReceived {
            frame.firstRange = largestReceived - first.lowerBound
            remaining = remaining.dropFirst()
        }
        var smallest = largestReceived - frame.firstRange
        for range in remaining.prefix(ACKFrame.maxRanges) {
            let largest = range.upperBound - 1
            guard smallest >= largest + 2 else {
                continue
            }
            frame.additionalRanges.append((
                gap: smallest - largest - 2,
                length: range.upperBound - range.lowerBound - 1
            ))
            smallest = range.lowerBound
        }
        if includeDelay, self.largestReceivedAt != Time.never, now > self.largestReceivedAt {
            frame.ackDelay = (now - self.largestReceivedAt) / Time.microsecond / (1 << ackDelayExponent)
        }
        return frame
    }

    mutating func commitACK() {
        self.isImmediateACKRequired = false
        self.isTimerCancelled = false
        self.firstUnacknowledgedAt = Time.never
        self.ackElicitingSinceLastACK = 0
    }

    mutating func onACKSent(packetNumber: UInt64, largestAcknowledged: UInt64) {
        self.sentACKs.insert((packetNumber, largestAcknowledged), at: 0)
        if self.sentACKs.count > 32 {
            self.sentACKs.removeLast()
        }
    }

    mutating func onACKFrameAcknowledged(_ ack: ACKFrame) {
        var acknowledgedIndex: Int?
        outer: for (index, entry) in self.sentACKs.enumerated() {
            var matched = false
            ack.forEachRange { range in
                if range.contains(entry.packetNumber) {
                    matched = true
                }
            }
            if matched {
                acknowledgedIndex = index
                break outer
            }
        }
        guard let index = acknowledgedIndex else {
            return
        }
        let entry = self.sentACKs[index]
        self.received.remove(0..<entry.largestAcknowledged + 1)
        self.sentACKs.removeSubrange(index...)
    }

    mutating func forget(below packetNumber: UInt64) {
        self.received.removeAll(below: packetNumber)
    }
}
