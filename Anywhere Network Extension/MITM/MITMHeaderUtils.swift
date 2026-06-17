//
//  MITMHeaderUtils.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Parses a status code as exactly three ASCII digits (RFC 9112 §4); stricter
/// than `Int(_:)` so a malformed status can't skew a body-framing decision.
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

/// RFC 9110 §5.6.2: a field-name is one or more `tchar`; anything else risks
/// receiver misparse or header injection. Also validates method tokens (RFC 9110 §9.1).
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

/// Rejects CR/LF/NUL in a field-value — the classic request-/response-splitting
/// primitive (RFC 9110 §5.5 / RFC 9113 §8.2.1).
func isValidHTTPHeaderValue(_ value: String) -> Bool {
    for byte in value.utf8 {
        if byte == 0x0D || byte == 0x0A || byte == 0x00 {
            return false
        }
    }
    return true
}

/// Rejects a decoded HTTP/2 header list carrying CR/LF/NUL in any field-value, or a non-`tchar`
/// regular field-name — the splitting vector mitmproxy guards via `validate_headers` (RFC 9113
/// §8.2.1). HPACK decoding only validates UTF-8, so control bytes otherwise slip through and get
/// laundered to the peer (or downcast to HTTP/1.1). Pseudo-header names (`:`-prefixed) are validated
/// structurally by the pseudo-header checker, so only their values are screened here.
func http2HeaderOctetsValid(_ headers: [(name: String, value: String)]) -> Bool {
    for (name, value) in headers {
        if !isValidHTTPHeaderValue(value) { return false }
        if !name.hasPrefix(":"), !isValidHTTPHeaderName(name) { return false }
    }
    return true
}

/// First value for `name` (ASCII case-insensitive), or nil.
func firstHeaderValue(_ headers: [(name: String, value: String)], name: String) -> String? {
    for (n, v) in headers where n.equalsIgnoringASCIICase(name) {
        return v
    }
    return nil
}

extension String {

    /// Allocation-free ASCII case-insensitive comparison; field-names are all-ASCII
    /// token chars (RFC 9110 §5.6.2), so the A–Z fold is exhaustive.
    func equalsIgnoringASCIICase(_ other: String) -> Bool {
        let lhs = self.utf8
        let rhs = other.utf8
        guard lhs.count == rhs.count else { return false }
        var i = lhs.startIndex
        var j = rhs.startIndex
        while i < lhs.endIndex {
            let l = lhs[i]
            let r = rhs[j]
            // 0x20 is the ASCII case bit; non-letters skip the fold.
            let foldedL = (l >= 0x41 && l <= 0x5A) ? l | 0x20 : l
            let foldedR = (r >= 0x41 && r <= 0x5A) ? r | 0x20 : r
            if foldedL != foldedR { return false }
            i = lhs.index(after: i)
            j = rhs.index(after: j)
        }
        return true
    }

    /// ASCII case-insensitive substring test without materialising `[UInt8]`.
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

extension Data {

    /// Appends a header field-name or field-value as its on-the-wire bytes. HTTP/1 header octets and
    /// HPACK string literals are byte strings (RFC 9110 §5.5 obs-text; RFC 7541 §5.2), so a value
    /// parsed as ISO-8859-1 round-trips to the exact same octets when re-emitted the same way. Falls
    /// back to UTF-8 only for a rule-/script-injected value carrying scalars > 0xFF, which latin-1
    /// can't represent — preserving the prior behavior for those.
    mutating func appendHeaderFieldBytes(_ field: String) {
        if let latin1 = field.data(using: .isoLatin1) {
            append(latin1)
        } else {
            append(contentsOf: field.utf8)
        }
    }
}
