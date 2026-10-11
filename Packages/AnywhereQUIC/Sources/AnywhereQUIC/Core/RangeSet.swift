//
//  RangeSet.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct RangeSet: Hashable, Sendable {
    private(set) var ranges: [Range<UInt64>] = []

    init() { }

    init(_ range: Range<UInt64>) {
        if !range.isEmpty {
            self.ranges = [range]
        }
    }

    var isEmpty: Bool { self.ranges.isEmpty }
    var count: Int { self.ranges.count }
    var first: Range<UInt64>? { self.ranges.first }
    var last: Range<UInt64>? { self.ranges.last }

    var lowerBound: UInt64? { self.ranges.first?.lowerBound }
    var upperBound: UInt64? { self.ranges.last?.upperBound }

    var totalLength: UInt64 {
        return self.ranges.reduce(0) { $0 + ($1.upperBound - $1.lowerBound) }
    }

    private func indexOfFirstRange(endingAfter value: UInt64) -> Int {
        var low = 0
        var high = self.ranges.count
        while low < high {
            let mid = (low + high) / 2
            if self.ranges[mid].upperBound <= value {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }

    func contains(_ value: UInt64) -> Bool {
        let index = self.indexOfFirstRange(endingAfter: value)
        return index < self.ranges.count && self.ranges[index].lowerBound <= value
    }

    func contains(_ range: Range<UInt64>) -> Bool {
        if range.isEmpty {
            return true
        }
        let index = self.indexOfFirstRange(endingAfter: range.lowerBound)
        return index < self.ranges.count
            && self.ranges[index].lowerBound <= range.lowerBound
            && self.ranges[index].upperBound >= range.upperBound
    }

    func intersects(_ range: Range<UInt64>) -> Bool {
        if range.isEmpty {
            return false
        }
        let index = self.indexOfFirstRange(endingAfter: range.lowerBound)
        return index < self.ranges.count && self.ranges[index].lowerBound < range.upperBound
    }

    mutating func insert(_ range: Range<UInt64>) {
        if range.isEmpty {
            return
        }
        var newRange = range
        var index = self.indexOfFirstRange(endingAfter: range.lowerBound)
        if index > 0, self.ranges[index - 1].upperBound == range.lowerBound {
            index -= 1
        }
        var end = index
        while end < self.ranges.count, self.ranges[end].lowerBound <= newRange.upperBound {
            let lowerBound = Swift.min(newRange.lowerBound, self.ranges[end].lowerBound)
            let upperBound = Swift.max(newRange.upperBound, self.ranges[end].upperBound)
            newRange = lowerBound..<upperBound
            end += 1
        }
        self.ranges.replaceSubrange(index..<end, with: CollectionOfOne(newRange))
    }

    mutating func insert(_ value: UInt64) {
        self.insert(value..<value + 1)
    }

    mutating func remove(_ range: Range<UInt64>) {
        if range.isEmpty || self.ranges.isEmpty {
            return
        }
        let start = self.indexOfFirstRange(endingAfter: range.lowerBound)
        var replacement: [Range<UInt64>] = []
        var end = start
        while end < self.ranges.count, self.ranges[end].lowerBound < range.upperBound {
            let existing = self.ranges[end]
            if existing.lowerBound < range.lowerBound {
                replacement.append(existing.lowerBound..<range.lowerBound)
            }
            if existing.upperBound > range.upperBound {
                replacement.append(range.upperBound..<existing.upperBound)
            }
            end += 1
        }
        if start < end {
            self.ranges.replaceSubrange(start..<end, with: replacement)
        }
    }

    mutating func removeAll(below value: UInt64) {
        self.remove(0..<value)
    }

    mutating func removeFirst() {
        self.ranges.removeFirst()
    }

    mutating func removeLast() {
        self.ranges.removeLast()
    }

    mutating func removeAll() {
        self.ranges.removeAll(keepingCapacity: true)
    }

    mutating func fillFirstGap() {
        let start = self.firstMissing(from: 0)
        self.insert(start..<(self.nextRange(coveringOrAfter: start)?.lowerBound ?? .max))
    }

    func firstMissing(from value: UInt64) -> UInt64 {
        let index = self.indexOfFirstRange(endingAfter: value)
        if index < self.ranges.count, self.ranges[index].lowerBound <= value {
            return self.ranges[index].upperBound
        }
        return value
    }

    func nextRange(coveringOrAfter value: UInt64) -> Range<UInt64>? {
        let index = self.indexOfFirstRange(endingAfter: value)
        return index < self.ranges.count ? self.ranges[index] : nil
    }
}
