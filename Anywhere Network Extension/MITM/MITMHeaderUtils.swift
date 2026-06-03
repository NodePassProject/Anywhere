//
//  MITMHeaderUtils.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Parses an HTTP status code as exactly three ASCII digits (RFC 9112 §4
/// status-code / RFC 9113 §8.3.2 `:status`). Returns nil for anything else —
/// `+200`, `0204`, `2xx`, `99999`, or any token that isn't three digits — so a
/// malformed status can't be leniently coerced (as bare `Int(_:)` would) into a
/// body-framing decision that diverges from how a strict peer frames the same
/// wire bytes. Surrounding ASCII whitespace is tolerated: an HTTP/1 status token
/// is already split on SP, and HTTP/2 `:status` carries none.
func parseHTTPStatusCode(_ raw: some StringProtocol) -> Int? {
    let trimmed = String(raw).trimmingCharacters(in: .whitespaces)
    guard trimmed.utf8.count == 3 else { return nil }
    var value = 0
    for byte in trimmed.utf8 {
        guard (0x30...0x39).contains(byte) else { return nil }
        value = value * 10 + Int(byte - 0x30)
    }
    return value
}

extension String {

    /// Case-insensitive ASCII comparison. Returns true iff the two
    /// strings share the same UTF-8 byte length and bytes that match
    /// after folding A–Z to a–z (0x41–0x5A → 0x61–0x7A). Other code
    /// points must match exactly.
    ///
    /// Allocation-free; intended for HTTP header-name comparisons.
    /// RFC 9110 §5.6.2 restricts header field-names to `token`
    /// characters — all ASCII — so the simpler fold is exhaustive in
    /// practice. Swift's built-in ``lowercased`` allocates a new
    /// ``String`` on every call, and the MITM hot path was running
    /// dozens of ``name.lowercased() == "host"``-style checks per
    /// message head; this turns each into a single UTF-8 walk with no
    /// heap traffic.
    func equalsIgnoringASCIICase(_ other: String) -> Bool {
        let lhs = self.utf8
        let rhs = other.utf8
        guard lhs.count == rhs.count else { return false }
        var i = lhs.startIndex
        var j = rhs.startIndex
        while i < lhs.endIndex {
            let l = lhs[i]
            let r = rhs[j]
            // 0x20 is the case bit for ASCII A–Z. Any non-letter byte
            // skips the fold and falls through to the strict equality
            // check, which preserves byte identity for the long tail
            // of legitimate token characters (digits, `-`, `_`, etc.).
            let foldedL = (l >= 0x41 && l <= 0x5A) ? l | 0x20 : l
            let foldedR = (r >= 0x41 && r <= 0x5A) ? r | 0x20 : r
            if foldedL != foldedR { return false }
            i = lhs.index(after: i)
            j = rhs.index(after: j)
        }
        return true
    }

    /// Case-insensitive ASCII substring test. Returns true iff
    /// ``needle`` appears anywhere inside ``self`` under the same
    /// ASCII A–Z fold rule as ``equalsIgnoringASCIICase``.
    ///
    /// Iterates ``UTF8View`` indices directly rather than materialising
    /// ``[UInt8]`` arrays, which would allocate twice per call and
    /// defeat the "allocation-free" intent the companion comparator
    /// documents.
    func containsIgnoringASCIICase(_ needle: String) -> Bool {
        let hay = self.utf8
        let pat = needle.utf8
        let hayCount = hay.count
        let patCount = pat.count
        guard patCount > 0 else { return true }
        guard hayCount >= patCount else { return false }
        var startIdx = hay.startIndex
        let lastStart = hay.index(hay.startIndex, offsetBy: hayCount - patCount)
        while startIdx <= lastStart {
            var hi = startIdx
            var pi = pat.startIndex
            var matched = true
            while pi < pat.endIndex {
                let h = hay[hi]
                let n = pat[pi]
                let fh = (h >= 0x41 && h <= 0x5A) ? h | 0x20 : h
                let fn = (n >= 0x41 && n <= 0x5A) ? n | 0x20 : n
                if fh != fn {
                    matched = false
                    break
                }
                hi = hay.index(after: hi)
                pi = pat.index(after: pi)
            }
            if matched { return true }
            startIdx = hay.index(after: startIdx)
        }
        return false
    }
}
