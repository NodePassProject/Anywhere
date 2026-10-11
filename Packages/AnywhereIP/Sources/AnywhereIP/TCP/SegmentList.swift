//
//  SegmentList.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct SegmentList {
    private(set) var first: Segment?
    private(set) var last: Segment?
    private(set) var count = 0

    var isEmpty: Bool {
        first == nil
    }

    mutating func append(_ segment: Segment) {
        segment.next = nil
        segment.isQueued = true
        if let last {
            last.next = segment
        } else {
            first = segment
        }
        last = segment
        count += 1
    }

    mutating func prepend(_ segment: Segment) {
        segment.next = first
        segment.isQueued = true
        first = segment
        if last == nil {
            last = segment
        }
        count += 1
    }

    mutating func insert(_ segment: Segment, after predecessor: Segment) {
        segment.next = predecessor.next
        segment.isQueued = true
        predecessor.next = segment
        if last == predecessor {
            last = segment
        }
        count += 1
    }

    mutating func insertOrdered(_ segment: Segment) {
        var predecessor: Segment?
        var candidate = first
        while let current = candidate, Sequence.lessThan(current.sequenceNumber, segment.sequenceNumber) {
            predecessor = current
            candidate = current.next
        }
        if let predecessor {
            insert(segment, after: predecessor)
        } else {
            prepend(segment)
        }
    }

    mutating func prepend(contentsOf list: consuming SegmentList) {
        guard let tail = list.last else { return }
        tail.next = first
        first = list.first
        if last == nil {
            last = tail
        }
        count += list.count
    }

    mutating func removeFirst() -> Segment? {
        guard let head = first else { return nil }
        first = head.next
        if first == nil {
            last = nil
        }
        head.next = nil
        count -= 1
        return head
    }

    mutating func detachAll() -> SegmentList {
        let detached = self
        self = SegmentList()
        return detached
    }
}
