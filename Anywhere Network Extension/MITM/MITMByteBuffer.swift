//
//  MITMByteBuffer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

/// Cursor-style byte buffer: Data plus a read offset so prefix removal is O(1)
/// (not the O(n²) memmove of `Data.removeFirst`). The visible region is always 0-indexed.
struct MITMByteBuffer {

    /// Compact once the consumed prefix exceeds this; 64 KiB = 4× the upstream TLS plaintext record size.
    private static let compactAbsoluteThreshold = 64 * 1024

    private var storage: Data
    private var offset: Int

    init() {
        self.storage = Data()
        self.offset = 0
    }

    var count: Int { storage.count - offset }

    var isEmpty: Bool { offset >= storage.count }

    /// Always 0; the underlying storage offset is hidden from callers.
    var startIndex: Int { 0 }

    var endIndex: Int { count }

    subscript(_ i: Int) -> UInt8 {
        return storage[storage.startIndex + offset + i]
    }

    func prefix(_ n: Int) -> Data {
        let take = Swift.min(n, count)
        let s = storage.startIndex + offset
        return storage.subdata(in: s..<(s + take))
    }

    func subdata(in range: Range<Int>) -> Data {
        let s = storage.startIndex + offset
        return storage.subdata(in: (s + range.lowerBound)..<(s + range.upperBound))
    }

    /// 0-relative range of the first occurrence of `pattern` at or after `start` (clamped).
    /// Incremental scans must overlap by `pattern.count - 1` to catch straddling matches.
    func range(of pattern: Data, from start: Int = 0) -> Range<Int>? {
        let s = storage.startIndex + offset
        let clamped = Swift.max(0, Swift.min(start, count))
        guard let r = storage.range(of: pattern, in: (s + clamped)..<storage.endIndex) else {
            return nil
        }
        return (r.lowerBound - s)..<(r.upperBound - s)
    }

    /// Index of the CR in the first CRLF at or after `start` (clamped).
    /// Incremental scans pass the prior `count - 1` to catch a straddling CRLF.
    func firstCRLF(from start: Int = 0) -> Int? {
        guard count >= 2 else { return nil }
        var i = Swift.max(0, Swift.min(start, count))
        let last = count - 1
        while i < last {
            if self[i] == 0x0D, self[i + 1] == 0x0A {
                return i
            }
            i += 1
        }
        return nil
    }

    mutating func append(_ other: Data) {
        compactIfNeeded()
        storage.append(other)
    }

    /// Drops ``n`` bytes from the front in O(1) by advancing the read offset.
    mutating func removeFirst(_ n: Int) {
        // Overshoot past count is tolerated — the reset below clamps to empty.
        offset += n
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
