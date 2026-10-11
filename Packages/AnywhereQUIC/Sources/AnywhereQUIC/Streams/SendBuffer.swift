//
//  SendBuffer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct SendBuffer {
    struct Segment {
        var offset: UInt64
        var length: Int
        var fin: Bool
    }

    private var storage: [UInt8] = []
    private var storageStart = 0
    private(set) var baseOffset: UInt64 = 0
    private(set) var sentOffset: UInt64 = 0
    private(set) var acknowledged = RangeSet()
    private(set) var lost = RangeSet()
    private(set) var finOffset: UInt64?
    private(set) var isFINSent = false
    private(set) var isFINAcknowledged = false
    private(set) var isFINLost = false

    var endOffset: UInt64 { self.baseOffset + UInt64(self.storage.count - self.storageStart) }
    var bufferedBytes: Int { self.storage.count - self.storageStart }
    var hasFIN: Bool { self.finOffset != nil }

    var hasPendingData: Bool {
        return !self.lost.isEmpty
            || self.sentOffset < self.endOffset
            || (self.finOffset != nil && (!self.isFINSent || self.isFINLost))
    }

    var isAllAcknowledged: Bool {
        return self.isFINAcknowledged && self.bufferedBytes == 0
    }

    mutating func append(_ bytes: UnsafeRawBufferPointer) {
        precondition(self.finOffset == nil)
        self.storage.append(contentsOf: bytes)
    }

    mutating func append(_ bytes: [UInt8]) {
        precondition(self.finOffset == nil)
        self.storage.append(contentsOf: bytes)
    }

    mutating func markFIN() {
        if self.finOffset == nil {
            self.finOffset = self.endOffset
        }
    }

    func nextSegment(maxLength: Int) -> Segment? {
        if let range = self.lost.first {
            let length = Int(Swift.min(UInt64(maxLength), range.upperBound - range.lowerBound))
            let fin = self.isFINLost
                && self.finOffset == range.lowerBound + UInt64(length)
                && length == Int(range.upperBound - range.lowerBound)
            return Segment(offset: range.lowerBound, length: length, fin: fin)
        }
        if self.isFINLost, self.lost.isEmpty, let finOffset = self.finOffset {
            return Segment(offset: finOffset, length: 0, fin: true)
        }
        if self.sentOffset < self.endOffset {
            let length = Int(Swift.min(UInt64(maxLength), self.endOffset - self.sentOffset))
            let fin = self.finOffset == self.sentOffset + UInt64(length)
            return Segment(offset: self.sentOffset, length: length, fin: fin)
        }
        if let finOffset = self.finOffset, !self.isFINSent, self.sentOffset == finOffset {
            return Segment(offset: finOffset, length: 0, fin: true)
        }
        return nil
    }

    func firstPendingRun() -> (range: Range<UInt64>, isFollowed: Bool)? {
        let hasUnsentData = self.sentOffset < self.endOffset
        guard let first = self.lost.first else {
            return hasUnsentData ? (self.sentOffset..<self.endOffset, false) : nil
        }
        let end = hasUnsentData && first.upperBound == self.sentOffset ? self.endOffset : first.upperBound
        return (first.lowerBound..<end, self.lost.count > 1 || (hasUnsentData && end != self.endOffset))
    }

    func withBytes<Result>(offset: UInt64, length: Int, _ body: (UnsafeRawBufferPointer) -> Result) -> Result {
        precondition(offset >= self.baseOffset && offset + UInt64(length) <= self.endOffset)
        let start = self.storageStart + Int(offset - self.baseOffset)
        return self.storage.withUnsafeBytes { raw in
            return body(UnsafeRawBufferPointer(rebasing: raw[start..<start + length]))
        }
    }

    mutating func markSent(_ segment: Segment) {
        let range = segment.offset..<segment.offset + UInt64(segment.length)
        self.lost.remove(range)
        if segment.offset + UInt64(segment.length) > self.sentOffset {
            self.sentOffset = segment.offset + UInt64(segment.length)
        }
        if segment.fin {
            self.isFINSent = true
            self.isFINLost = false
        }
    }

    mutating func markAcknowledged(offset: UInt64, length: Int, fin: Bool) -> UInt64 {
        let before = self.acknowledgedPrefix
        if fin {
            self.isFINAcknowledged = true
        }
        if length > 0 {
            let range = offset..<offset + UInt64(length)
            self.acknowledged.insert(range)
            self.lost.remove(range)
        }
        let prefix = self.acknowledgedPrefix
        if prefix > self.baseOffset {
            let release = Int(prefix - self.baseOffset)
            self.storageStart += release
            self.baseOffset = prefix
            self.acknowledged.removeAll(below: prefix)
            if self.storageStart > 4096, self.storageStart * 2 >= self.storage.count {
                self.storage.removeFirst(self.storageStart)
                self.storageStart = 0
            }
        }
        return prefix - before
    }

    var acknowledgedPrefix: UInt64 {
        if let first = self.acknowledged.first, first.lowerBound <= self.baseOffset {
            return Swift.max(first.upperBound, self.baseOffset)
        }
        return self.baseOffset
    }

    mutating func markLost(offset: UInt64, length: Int, fin: Bool) {
        if length > 0 {
            var range = offset..<offset + UInt64(length)
            if range.lowerBound < self.baseOffset {
                range = self.baseOffset..<Swift.max(range.upperBound, self.baseOffset)
            }
            if !range.isEmpty {
                var pending = RangeSet(range)
                for acked in self.acknowledged.ranges {
                    pending.remove(acked)
                }
                for piece in pending.ranges {
                    self.lost.insert(piece)
                }
            }
        }
        if fin, !self.isFINAcknowledged {
            self.isFINLost = true
        }
    }

    mutating func discardAll() {
        self.storage.removeAll()
        self.storageStart = 0
        self.baseOffset = self.sentOffset
        self.lost.removeAll()
        self.isFINLost = false
    }
}
