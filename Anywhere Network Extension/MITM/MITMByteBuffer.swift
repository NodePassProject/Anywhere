//
//  MITMByteBuffer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

nonisolated struct MITMByteBuffer {
    private static let compactAbsoluteThreshold = 64 * 1024

    private var storage: Data
    private var offset: Int

    init() {
        self.storage = Data()
        self.offset = 0
    }

    var count: Int { storage.count - offset }

    var isEmpty: Bool { offset >= storage.count }

    var startIndex: Int { 0 }

    var endIndex: Int { count }

    subscript(_ index: Int) -> UInt8 {
        storage[storage.startIndex + offset + index]
    }

    func prefix(_ maxLength: Int) -> Data {
        let take = Swift.min(maxLength, count)
        let absoluteStart = storage.startIndex + offset
        return storage.subdata(in: absoluteStart..<(absoluteStart + take))
    }

    func subdata(in range: Range<Int>) -> Data {
        let base = storage.startIndex + offset
        return storage.subdata(in: (base + range.lowerBound)..<(base + range.upperBound))
    }

    func appendPrefix(_ count: Int, to data: inout Data) {
        let take = Swift.min(count, self.count)
        guard take > 0 else { return }
        let absoluteStart = storage.startIndex + offset
        data.append(storage[absoluteStart..<(absoluteStart + take)])
    }

    func withUnsafeBytes<R>(in range: Range<Int>, _ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        let base = storage.startIndex + offset
        return try storage[(base + range.lowerBound)..<(base + range.upperBound)].withUnsafeBytes(body)
    }

    func range(of pattern: Data, from start: Int = 0) -> Range<Int>? {
        let base = storage.startIndex + offset
        let clamped = Swift.max(0, Swift.min(start, count))
        guard let found = storage.range(of: pattern, in: (base + clamped)..<storage.endIndex) else {
            return nil
        }
        return (found.lowerBound - base)..<(found.upperBound - base)
    }

    func firstCRLF(from start: Int = 0) -> Int? {
        guard count >= 2 else { return nil }
        var index = Swift.max(0, Swift.min(start, count))
        let last = count - 1
        while index < last {
            if self[index] == 0x0D, self[index + 1] == 0x0A {
                return index
            }
            index += 1
        }
        return nil
    }

    mutating func append(_ other: Data) {
        compactIfNeeded()
        storage.append(other)
    }

    mutating func removeFirst(_ k: Int) {
        offset += k
        if offset >= storage.count {
            storage.removeAll(keepingCapacity: true)
            offset = 0
        }
    }

    mutating func removeAll(keepingCapacity: Bool = false) {
        storage.removeAll(keepingCapacity: keepingCapacity)
        offset = 0
    }

    private mutating func compactIfNeeded() {
        guard offset > 0 else { return }
        if offset >= Self.compactAbsoluteThreshold || offset * 2 > storage.count {
            storage = storage.subdata(in: (storage.startIndex + offset)..<storage.endIndex)
            offset = 0
        }
    }
}

nonisolated struct MITMByteQueue {
    private static let compactHeadThreshold = 32

    private var chunks: [Data] = []
    private var head = 0
    private var headOffset = 0

    private(set) var count = 0

    var isEmpty: Bool { count == 0 }

    mutating func append(_ data: Data) {
        guard !data.isEmpty else { return }
        chunks.append(data)
        count += data.count
    }

    mutating func popChunks(_ maxCount: Int) -> [Data] {
        var needed = min(max(maxCount, 0), count)
        guard needed > 0 else { return [] }
        count -= needed
        var out: [Data] = []
        while needed > 0 {
            let chunk = chunks[head]
            let start = chunk.startIndex + headOffset
            let available = chunk.endIndex - start
            if needed < available {
                out.append(chunk[start..<(start + needed)])
                headOffset += needed
                needed = 0
            } else {
                out.append(headOffset == 0 ? chunk : chunk[start..<chunk.endIndex])
                needed -= available
                advanceHead()
            }
        }
        return out
    }

    private mutating func advanceHead() {
        chunks[head] = Data()
        head += 1
        headOffset = 0
        if head == chunks.count {
            chunks.removeAll(keepingCapacity: true)
            head = 0
        } else if head >= Self.compactHeadThreshold, head * 2 >= chunks.count {
            chunks.removeFirst(head)
            head = 0
        }
    }
}
