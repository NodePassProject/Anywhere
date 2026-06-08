//
//  MITMByteBuffer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

/// Cursor-style byte buffer used by the MITM stream parsers. Wraps a
/// ``Data`` plus a read offset so prefix removal is O(1) instead of
/// ``Data/removeFirst(_:)``'s `O(remaining)` memmove. A chunked body
/// arriving as N small chunks streams through ``Data``-based parsers
/// at `O(N²)` because each `removeFirst` shifts every byte still in
/// the buffer; ``MITMByteBuffer`` advances an offset instead and
/// compacts only when the consumed prefix grows past a threshold.
///
/// The visible region is 0-indexed: callers see ``startIndex == 0``
/// and ``endIndex == count`` regardless of how much storage has been
/// consumed. ``range(of:)`` returns 0-relative indices so a call site
/// can swap ``Data`` for this type without reworking its index math.
struct MITMByteBuffer {

    /// Compact when the consumed prefix grows past this many bytes,
    /// even if it's less than half the storage. 64 KiB matches the
    /// upstream-side TLS record size — for chunked bodies this means
    /// at most one record's worth of dead bytes sits in storage
    /// before reclaim.
    private static let compactAbsoluteThreshold = 64 * 1024

    private var storage: Data
    private var offset: Int

    init() {
        self.storage = Data()
        self.offset = 0
    }

    /// Number of unconsumed bytes available to read.
    var count: Int { storage.count - offset }

    var isEmpty: Bool { offset >= storage.count }

    /// Always 0. The consumable region is presented as if it starts
    /// at the buffer's front; the underlying storage offset is hidden.
    var startIndex: Int { 0 }

    /// Equivalent to ``count``. Provided for symmetry with ``Data``-
    /// shaped call sites.
    var endIndex: Int { count }

    /// Byte at 0-relative index ``i`` in the consumable region.
    subscript(_ i: Int) -> UInt8 {
        return storage[storage.startIndex + offset + i]
    }

    /// Returns the first ``n`` bytes as a fresh ``Data``. Clamped to
    /// ``count`` so callers don't have to range-check.
    func prefix(_ n: Int) -> Data {
        let take = Swift.min(n, count)
        let s = storage.startIndex + offset
        return storage.subdata(in: s..<(s + take))
    }

    /// Returns the bytes at the given 0-relative range as a fresh
    /// ``Data``.
    func subdata(in range: Range<Int>) -> Data {
        let s = storage.startIndex + offset
        return storage.subdata(in: (s + range.lowerBound)..<(s + range.upperBound))
    }

    /// Returns the 0-relative range of the first occurrence of ``pattern``
    /// at or after the 0-relative index ``start``, or nil when absent.
    ///
    /// ``start`` lets a caller re-scanning a buffer that only grows at the end
    /// (an HTTP head accumulating across TLS records, say) resume past the
    /// region it already searched instead of re-walking the whole buffer on
    /// every append — turning a repeated O(n²) scan into O(n). To stay correct
    /// the caller must overlap by ``pattern.count - 1`` bytes so a match
    /// straddling the boundary between already-scanned and freshly-appended
    /// bytes is still found. ``start`` is clamped to the consumable region.
    func range(of pattern: Data, from start: Int = 0) -> Range<Int>? {
        let s = storage.startIndex + offset
        let clamped = Swift.max(0, Swift.min(start, count))
        guard let r = storage.range(of: pattern, in: (s + clamped)..<storage.endIndex) else {
            return nil
        }
        return (r.lowerBound - s)..<(r.upperBound - s)
    }

    /// Index of the CR in the first CRLF sequence at or after the
    /// 0-relative index ``start``, or nil when no CRLF is present.
    /// Specialized scanner used by the HTTP/1 stream parsers; faster
    /// than ``range(of:)`` for the short CRLF pattern since it avoids
    /// the Foundation pattern-search setup.
    ///
    /// ``start`` lets a caller re-scanning a buffer that only grows at the end
    /// (a chunk-size line or trailer line dribbling in across TLS records)
    /// resume past the bytes it already searched instead of re-walking the
    /// whole prefix on every append — turning a repeated O(n²) scan into O(n).
    /// Pass the index of the first byte not yet checked as a CR candidate
    /// (i.e. the prior ``count - 1``); the boundary byte is re-checked so a
    /// CRLF straddling the old end and a freshly-appended byte is still found.
    /// ``start`` is clamped to the consumable region.
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

    /// Appends ``other`` to the storage. Compacts the consumed prefix
    /// first when it has grown large enough to matter, so the storage
    /// doesn't drift unbounded for long-lived buffers.
    mutating func append(_ other: Data) {
        compactIfNeeded()
        storage.append(other)
    }

    /// Drops ``n`` bytes from the front in O(1) — advances the read
    /// offset without touching the storage. When the offset catches
    /// up to the storage length the storage is cleared so the next
    /// append starts from a known-empty state.
    mutating func removeFirst(_ n: Int) {
        // Overshoot past ``count`` is tolerated — the reset below clamps it to empty.
        offset += n
        if offset >= storage.count {
            storage.removeAll(keepingCapacity: true)
            offset = 0
        }
    }

    /// Clears the buffer. ``keepingCapacity`` is forwarded to the
    /// underlying ``Data.removeAll`` so callers can opt out of
    /// holding onto a previously-grown allocation.
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
