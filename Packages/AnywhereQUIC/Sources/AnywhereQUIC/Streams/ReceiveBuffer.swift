//
//  ReceiveBuffer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

struct ReceiveBuffer {
    private struct Chunk {
        var offset: UInt64
        var data: [UInt8]

        var end: UInt64 { self.offset + UInt64(self.data.count) }
    }

    private static let compactionThreshold = 32

    private(set) var readOffset: UInt64 = 0
    private var pending: [Chunk] = []
    private var pendingHead = 0
    private var discardedRanges = RangeSet()
    private(set) var bufferedBytes = 0
    private(set) var isBuffering = true

    var hasPendingData: Bool { self.pendingHead < self.pending.count }

    mutating func receive(
        offset: UInt64,
        data: UnsafeRawBufferPointer,
        slice: (UnsafeRawBufferPointer) -> Data? = { _ in nil }
    ) -> Data? {
        let end = offset + UInt64(data.count)
        if end <= self.readOffset {
            return nil
        }
        var start = offset
        var bytes = data
        if start < self.readOffset {
            let skip = Int(self.readOffset - start)
            bytes = UnsafeRawBufferPointer(rebasing: bytes[skip...])
            start = self.readOffset
        }
        if start == self.readOffset {
            self.readOffset = end
            guard self.hasPendingData, self.pending[self.pendingHead].offset <= end else {
                if bytes.isEmpty {
                    return Data()
                }
                return slice(bytes) ?? Data(bytes: bytes.baseAddress!, count: bytes.count)
            }
            var delivered = Data(capacity: bytes.count + self.deliverableBufferedBytes())
            bytes.withMemoryRebound(to: UInt8.self) { delivered.append($0) }
            self.drainPending(into: &delivered, keepingData: true)
            return delivered
        }
        guard self.isBuffering else {
            self.discardedRanges.insert(start..<end)
            return nil
        }
        self.insertPending(offset: start, bytes: bytes)
        return nil
    }

    private func deliverableBufferedBytes() -> Int {
        var cursor = self.readOffset
        var count = 0
        var index = self.pendingHead
        while index < self.pending.count, self.pending[index].offset <= cursor {
            let end = self.pending[index].end
            if end > cursor {
                count += Int(end - cursor)
                cursor = end
            }
            index += 1
        }
        return count
    }

    private mutating func drainPending(into delivered: inout Data, keepingData: Bool) {
        var index = self.pendingHead
        while index < self.pending.count, self.pending[index].offset <= self.readOffset {
            let chunk = self.pending[index]
            self.pending[index].data = []
            index += 1
            self.bufferedBytes -= chunk.data.count
            let end = chunk.end
            if end <= self.readOffset {
                continue
            }
            if keepingData {
                let skip = Int(self.readOffset - chunk.offset)
                delivered.append(contentsOf: chunk.data[skip...])
            }
            self.readOffset = end
        }
        if index == self.pending.count {
            self.pending.removeAll(keepingCapacity: true)
            self.pendingHead = 0
        } else if index >= Self.compactionThreshold, index * 2 >= self.pending.count {
            self.pending.removeFirst(index)
            self.pendingHead = 0
        } else {
            self.pendingHead = index
        }
    }

    private func firstPendingIndex(endingAfter value: UInt64) -> Int {
        var low = self.pendingHead
        var high = self.pending.count
        while low < high {
            let mid = low + (high - low) / 2
            if self.pending[mid].end <= value {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }

    private mutating func insertPending(offset: UInt64, bytes: UnsafeRawBufferPointer) {
        var start = offset
        var remaining = bytes
        var index = self.firstPendingIndex(endingAfter: start)
        while index < self.pending.count, !remaining.isEmpty {
            let existingOffset = self.pending[index].offset
            if existingOffset > start {
                let gap = Int(Swift.min(UInt64(remaining.count), existingOffset - start))
                let piece = Chunk(offset: start, data: Array(UnsafeRawBufferPointer(rebasing: remaining[..<gap])))
                self.pending.insert(piece, at: index)
                self.bufferedBytes += gap
                remaining = UnsafeRawBufferPointer(rebasing: remaining[gap...])
                start += UInt64(gap)
                index += 1
                continue
            }
            let overlap = Int(Swift.min(UInt64(remaining.count), self.pending[index].end - start))
            remaining = UnsafeRawBufferPointer(rebasing: remaining[overlap...])
            start += UInt64(overlap)
            index += 1
        }
        if !remaining.isEmpty {
            self.pending.append(Chunk(offset: start, data: Array(remaining)))
            self.bufferedBytes += remaining.count
        }
    }

    mutating func stopBuffering() {
        self.isBuffering = false
        for chunk in self.pending[self.pendingHead...] {
            self.discardedRanges.insert(chunk.offset..<chunk.end)
        }
        self.pending.removeAll()
        self.pendingHead = 0
        self.bufferedBytes = 0
    }

    mutating func discardOrderedData(upTo offset: UInt64) -> UInt64 {
        guard offset > self.readOffset else {
            return 0
        }
        var dropped = Data()
        let previous = self.readOffset
        self.readOffset = offset
        self.drainPending(into: &dropped, keepingData: false)
        self.readOffset = self.discardedRanges.firstMissing(from: Swift.max(self.readOffset, offset))
        self.discardedRanges.removeAll(below: self.readOffset)
        return self.readOffset - previous
    }
}
