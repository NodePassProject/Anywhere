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

/// RFC 9110 §5.6.2: an HTTP header field-name is a `token` — one or more
/// `tchar` (ASCII alphanumerics plus the punctuation set
/// `! # $ % & ' * + - . ^ _ ` | ~`). Empty names are rejected. Anything
/// outside that set (whitespace, CTL, `:`, CR, LF, …) would either be
/// misparsed by the receiver or, worst case, let an injected CR LF break
/// out of the current line.
///
/// Canonical home for the field-name token check shared by the HTTP/1 and
/// HTTP/2 rewriters, the rule compiler (``MITMRewritePolicy``), and the
/// script engine's `Anywhere.respond` / `ctx.headers` paths — every site
/// that splices a name onto the wire must apply the identical rule, so it
/// lives here once instead of in four byte-identical copies. Also gates
/// HTTP method tokens, which share the field-name alphabet (RFC 9110 §9.1).
func isValidHTTPHeaderName(_ name: String) -> Bool {
    guard !name.isEmpty else { return false }
    for byte in name.utf8 {
        switch byte {
        case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x2A, 0x2B, 0x2D, 0x2E,
             0x5E, 0x5F, 0x60, 0x7C, 0x7E:
            continue
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
            continue
        default:
            return false
        }
    }
    return true
}

/// RFC 9110 §5.5 / RFC 9113 §8.2.1: an HTTP header field-value must not
/// contain CR, LF, or NUL. Those bytes are exactly what splits a wire
/// message into two — permitting any of them when a value is written
/// verbatim onto an HTTP/1 head, spliced onto a start line, or re-encoded
/// into an HPACK block is the classic request-/response-splitting
/// primitive.
///
/// Shared canonical check for every site that emits a field-value: the
/// HTTP/1 and HTTP/2 rewriters, the rule compiler, and the script engine.
/// Both transports forbid the identical byte set, so one check serves both.
func isValidHTTPHeaderValue(_ value: String) -> Bool {
    for byte in value.utf8 {
        if byte == 0x0D || byte == 0x0A || byte == 0x00 {
            return false
        }
    }
    return true
}

/// Returns the value of the first header named ``name`` (ASCII
/// case-insensitive), or nil when absent. Shared by the HTTP/1 and HTTP/2
/// rewriters — both represent a header list as `(name, value)` pairs; HTTP/2
/// also reads pseudo-headers (`:method`, `:path`, `:status`, …) through it.
func firstHeaderValue(_ headers: [(name: String, value: String)], name: String) -> String? {
    for (n, v) in headers where n.equalsIgnoringASCIICase(name) {
        return v
    }
    return nil
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
