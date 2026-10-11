//
//  SentPacket.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum SentFrame {
    case ack(largestAcknowledged: UInt64)
    case ping
    case padding
    case crypto(offset: UInt64, length: Int)
    case stream(id: UInt64, offset: UInt64, length: Int, fin: Bool)
    case resetStream(id: UInt64)
    case stopSending(id: UInt64)
    case maxData(UInt64)
    case maxStreamData(id: UInt64, maximum: UInt64)
    case maxStreams(bidirectional: Bool, maximum: UInt64)
    case dataBlocked(UInt64)
    case streamDataBlocked(id: UInt64, limit: UInt64)
    case streamsBlocked(bidirectional: Bool, limit: UInt64)
    case newConnectionID(sequence: UInt64)
    case retireConnectionID(sequence: UInt64)
    case pathChallenge(UInt64)
    case pathResponse(UInt64)
    case connectionClose

    var isRetransmittable: Bool {
        switch self {
        case .ack, .ping, .padding, .pathChallenge, .pathResponse, .connectionClose:
            return false
        default:
            return true
        }
    }
}

struct SentFrames {
    private var first: SentFrame?
    private var second: SentFrame?
    private var rest: [SentFrame] = []

    init() { }

    mutating func append(_ frame: SentFrame) {
        if self.first == nil {
            self.first = frame
        } else if self.second == nil {
            self.second = frame
        } else {
            self.rest.append(frame)
        }
    }
}

extension SentFrames: Sequence {
    struct Iterator: IteratorProtocol {
        let frames: SentFrames
        var index = 0

        mutating func next() -> SentFrame? {
            defer { self.index += 1 }
            switch self.index {
            case 0:
                return self.frames.first
            case 1:
                return self.frames.second
            default:
                let offset = self.index - 2
                return offset < self.frames.rest.count ? self.frames.rest[offset] : nil
            }
        }
    }

    func makeIterator() -> Iterator {
        return Iterator(frames: self)
    }
}

extension SentFrames: ExpressibleByArrayLiteral {
    init(arrayLiteral elements: SentFrame...) {
        self.init()
        for element in elements {
            self.append(element)
        }
    }
}

struct SentPacket {
    var packetNumber: UInt64
    var sentAt: Nanoseconds
    var size: Int
    var frames: SentFrames
    var isACKEliciting: Bool
    var isPTOEliciting: Bool
    var isRetransmittable: Bool
    var isProbe: Bool
    var isPMTUDProbe: Bool
    var isPTOReclaimed = false
    var countsTowardCongestion = true

    var deliverySnapshot: DeliverySnapshot? = nil

    var info: QUICSentPacketInfo {
        return QUICSentPacketInfo(
            packetNumber: self.packetNumber,
            size: self.size,
            sentAt: QUICInstant(nanoseconds: self.sentAt),
            isACKEliciting: self.isACKEliciting
        )
    }
}

struct ACKProcessingResult {
    var hasAcknowledgedACKElicitingPacket = false
    var largestAcknowledgedSentAt: Nanoseconds = Time.never
    var hasNewLargestAcknowledged = false
}

struct SentPacketTracker {
    struct LossDetectionResult {
        var lost: [SentPacket] = []
        var bytesLost: UInt64 = 0
        var latestLostSentAt: Nanoseconds = Time.never
        var oldestLostSentAt: Nanoseconds = Time.never
        var hasPersistentCongestion = false
    }

    private static let compactionThreshold = 32

    private var storage: [SentPacket] = []
    private var head = 0
    private(set) var largestAcknowledged: UInt64?
    private(set) var ackElicitingCount = 0
    private(set) var retransmittableCount = 0
    private(set) var ptoElicitingCount = 0
    private(set) var congestionBytesInFlight: UInt64 = 0
    var lossTime: Nanoseconds = Time.never
    var probePacketsLeft = 0
    private(set) var congestionPacketNumber: UInt64 = 0

    var packets: ArraySlice<SentPacket> { self.storage[self.head...] }

    var isEmpty: Bool { self.head == self.storage.count }

    mutating func add(_ packet: SentPacket, state: inout QUICCongestionState) {
        var packet = packet
        packet.countsTowardCongestion = packet.packetNumber >= self.congestionPacketNumber
        if self.head < self.storage.count {
            precondition(packet.packetNumber > self.storage[self.storage.count - 1].packetNumber)
        }
        self.storage.append(packet)
        if packet.countsTowardCongestion {
            state.bytesInFlight += UInt64(packet.size)
            self.congestionBytesInFlight += UInt64(packet.size)
        }
        if packet.isACKEliciting {
            self.ackElicitingCount += 1
        }
        if packet.isRetransmittable {
            self.retransmittableCount += 1
        }
        if packet.isPTOEliciting {
            self.ptoElicitingCount += 1
        }
    }

    private mutating func accountRemoval(_ packet: SentPacket, state: inout QUICCongestionState) -> UInt64 {
        if packet.isACKEliciting {
            self.ackElicitingCount -= 1
        }
        if packet.isRetransmittable, !packet.isPTOReclaimed {
            self.retransmittableCount -= 1
        }
        if packet.isPTOEliciting {
            self.ptoElicitingCount -= 1
        }
        guard packet.countsTowardCongestion else {
            return 0
        }
        state.bytesInFlight -= UInt64(packet.size)
        self.congestionBytesInFlight -= UInt64(packet.size)
        return packet.isPMTUDProbe ? 0 : UInt64(packet.size)
    }

    private func firstIndex(atOrAbove packetNumber: UInt64) -> Int {
        var low = self.head
        var high = self.storage.count
        while low < high {
            let mid = low + (high - low) / 2
            if self.storage[mid].packetNumber < packetNumber {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }
    
    private mutating func removePackets<Ranges: RandomAccessCollection>(
        in ranges: Ranges
    ) where Ranges.Element == Range<Int>, Ranges.Index == Int {
        guard let first = ranges.first, let last = ranges.last else {
            return
        }
        let removedCount = ranges.reduce(0) { $0 + $1.count }
        let movesTowardsEnd = last.upperBound - self.head - removedCount
        let movesTowardsStart = self.storage.count - first.lowerBound - removedCount
        if movesTowardsEnd <= movesTowardsStart {
            var write = last.upperBound
            var rangeIndex = ranges.count - 1
            var index = last.upperBound
            while index > self.head {
                index -= 1
                while rangeIndex >= 0, ranges[rangeIndex].lowerBound > index {
                    rangeIndex -= 1
                }
                if rangeIndex >= 0, ranges[rangeIndex].contains(index) {
                    continue
                }
                write -= 1
                if write != index {
                    self.storage.swapAt(write, index)
                }
            }
            self.head = write
        } else {
            var write = first.lowerBound
            var rangeIndex = 0
            for index in first.lowerBound..<self.storage.count {
                while rangeIndex < ranges.count, ranges[rangeIndex].upperBound <= index {
                    rangeIndex += 1
                }
                if rangeIndex < ranges.count, ranges[rangeIndex].contains(index) {
                    continue
                }
                if write != index {
                    self.storage.swapAt(write, index)
                }
                write += 1
            }
            self.storage.removeLast(self.storage.count - write)
        }
        if self.head == self.storage.count {
            self.storage.removeAll(keepingCapacity: true)
            self.head = 0
        } else if self.head >= Self.compactionThreshold, self.head * 2 >= self.storage.count {
            self.storage.removeFirst(self.head)
            self.head = 0
        }
    }

    mutating func processACK(
        _ ack: ACKFrame,
        state: inout QUICCongestionState,
        into acknowledged: inout [SentPacket]
    ) throws(TransportError) -> ACKProcessingResult {
        var result = ACKProcessingResult()
        if self.largestAcknowledged == nil || self.largestAcknowledged! < ack.largestAcknowledged {
            self.largestAcknowledged = ack.largestAcknowledged
            result.hasNewLargestAcknowledged = true
        }
        if ack.additionalRanges.isEmpty {
            let range = self.indexRange(acknowledging: (ack.largestAcknowledged - ack.firstRange)...ack.largestAcknowledged)
            guard !range.isEmpty else {
                return result
            }
            self.collect(range, largestAcknowledged: ack.largestAcknowledged, into: &acknowledged, result: &result, state: &state)
            self.removePackets(in: CollectionOfOne(range))
            return result
        }
        var ranges: [Range<Int>] = []
        ack.forEachRange { range in
            let indices = self.indexRange(acknowledging: range)
            if !indices.isEmpty {
                ranges.append(indices)
            }
        }
        guard !ranges.isEmpty else {
            return result
        }
        ranges.sort { $0.lowerBound < $1.lowerBound }
        var merged: [Range<Int>] = []
        merged.reserveCapacity(ranges.count)
        for range in ranges {
            if let previous = merged.last, range.lowerBound <= previous.upperBound {
                merged[merged.count - 1] = previous.lowerBound..<Swift.max(previous.upperBound, range.upperBound)
            } else {
                merged.append(range)
            }
        }
        acknowledged.reserveCapacity(acknowledged.count + merged.reduce(0) { $0 + $1.count })
        for range in merged {
            self.collect(range, largestAcknowledged: ack.largestAcknowledged, into: &acknowledged, result: &result, state: &state)
        }
        self.removePackets(in: merged)
        return result
    }

    private func indexRange(acknowledging range: ClosedRange<UInt64>) -> Range<Int> {
        let lowerBound = self.firstIndex(atOrAbove: range.lowerBound)
        let upperBound = range.upperBound == .max
            ? self.storage.count
            : self.firstIndex(atOrAbove: range.upperBound + 1)
        return lowerBound..<Swift.max(lowerBound, upperBound)
    }

    private mutating func collect(
        _ range: Range<Int>,
        largestAcknowledged: UInt64,
        into acknowledged: inout [SentPacket],
        result: inout ACKProcessingResult,
        state: inout QUICCongestionState
    ) {
        for index in range {
            let packet = self.storage[index]
            if packet.packetNumber == largestAcknowledged {
                result.largestAcknowledgedSentAt = packet.sentAt
            }
            if packet.isACKEliciting {
                result.hasAcknowledgedACKElicitingPacket = true
            }
            _ = self.accountRemoval(packet, state: &state)
            acknowledged.append(packet)
        }
    }

    mutating func detectLost(
        now: Nanoseconds,
        state: inout QUICCongestionState,
        peerMaxACKDelay: Nanoseconds,
        persistentCongestionStart: Nanoseconds,
        isApplicationSpace: Bool
    ) -> LossDetectionResult {
        var result = LossDetectionResult()
        self.lossTime = Time.never
        guard let largestAcknowledged = self.largestAcknowledged else {
            return result
        }
        let threshold = Swift.min(
            Swift.max(
                self.congestionBytesInFlight / UInt64(Swift.max(state.maxSendUDPPayloadSize, 1)) / 2,
                Recovery.packetThreshold
            ),
            Recovery.maxPacketThreshold
        )
        let lossDelay = Recovery.lossDelay(state: state)
        var lostRanges: [Range<Int>] = []
        var index = self.head
        while index < self.storage.count {
            let packetNumber = self.storage[index].packetNumber
            if packetNumber > largestAcknowledged {
                break
            }
            let sentAt = self.storage[index].sentAt
            let lostByTime = Time.elapsed(sentAt, lossDelay, now)
            let lostByPackets = largestAcknowledged >= packetNumber + threshold
            if lostByTime || lostByPackets {
                if let last = lostRanges.last, last.upperBound == index {
                    lostRanges[lostRanges.count - 1] = last.lowerBound..<index + 1
                } else {
                    lostRanges.append(index..<index + 1)
                }
                if result.latestLostSentAt == Time.never {
                    result.latestLostSentAt = sentAt
                    result.oldestLostSentAt = sentAt
                }
                result.latestLostSentAt = Swift.max(result.latestLostSentAt, sentAt)
                result.oldestLostSentAt = Swift.min(result.oldestLostSentAt, sentAt)
            } else {
                let candidate = sentAt.addingClamped(lossDelay)
                self.lossTime = self.lossTime == Time.never ? candidate : Swift.min(self.lossTime, candidate)
            }
            index += 1
        }
        guard !lostRanges.isEmpty else {
            return result
        }
        var lastLostPacketNumber: UInt64?
        var contiguousOldest: Nanoseconds = Time.never
        var contiguousLatest: Nanoseconds = Time.never
        var contiguousRun = false
        result.lost.reserveCapacity(lostRanges.reduce(0) { $0 + $1.count })
        for range in lostRanges {
            for index in range {
                let packet = self.storage[index]
                result.bytesLost += self.accountRemoval(packet, state: &state)
                result.lost.append(packet)
                if packet.sentAt >= persistentCongestionStart {
                    if let last = lastLostPacketNumber, last + 1 == packet.packetNumber, contiguousRun {
                        contiguousLatest = packet.sentAt
                    } else {
                        contiguousRun = true
                        contiguousOldest = packet.sentAt
                        contiguousLatest = packet.sentAt
                    }
                    lastLostPacketNumber = packet.packetNumber
                } else {
                    contiguousRun = false
                    lastLostPacketNumber = nil
                }
            }
        }
        self.removePackets(in: lostRanges)
        if isApplicationSpace,
           result.bytesLost > 0,
           contiguousOldest != Time.never,
           contiguousLatest > contiguousOldest {
            let probeTimeout = state.smoothedRTTNanoseconds
                + Swift.max(4 * state.rttVarianceNanoseconds, Recovery.granularity)
                + peerMaxACKDelay
            let period = probeTimeout * Recovery.persistentCongestionThreshold
            if contiguousLatest - contiguousOldest >= period {
                result.hasPersistentCongestion = true
            }
        }
        return result
    }

    mutating func reclaimOnPTO(count: Int) -> [SentFrame] {
        var reclaimed: [SentFrame] = []
        var remaining = count
        var index = self.storage.count - 1
        while index >= self.head, remaining > 0 {
            if self.storage[index].isRetransmittable, !self.storage[index].isPTOReclaimed {
                let frames = self.storage[index].frames.filter { $0.isRetransmittable }
                self.storage[index].isPTOReclaimed = true
                self.retransmittableCount -= 1
                if self.storage[index].isPTOEliciting {
                    self.storage[index].isPTOEliciting = false
                    self.ptoElicitingCount -= 1
                }
                if !frames.isEmpty {
                    reclaimed.append(contentsOf: frames)
                    remaining -= 1
                }
            }
            index -= 1
        }
        return reclaimed
    }

    mutating func removeAll(state: inout QUICCongestionState) -> [SentPacket] {
        let removed = Array(self.storage[self.head...])
        for packet in removed {
            _ = self.accountRemoval(packet, state: &state)
        }
        self.storage.removeAll()
        self.head = 0
        self.lossTime = Time.never
        return removed
    }

    mutating func resetCongestionState(nextPacketNumber: UInt64) {
        self.congestionPacketNumber = nextPacketNumber
        self.congestionBytesInFlight = 0
        for index in self.head..<self.storage.count {
            self.storage[index].countsTowardCongestion = false
        }
    }
}
