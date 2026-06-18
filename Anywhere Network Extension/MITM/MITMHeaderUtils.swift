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

/// Screens decoded HTTP/2 header octets (RFC 9113 §8.2.1): a non-conformant field is rejected, not
/// folded, since HPACK only validates UTF-8 and bad octets would otherwise launder to the peer or
/// downcast to HTTP/1.1. Pseudo-header names allowed (leading `:` at index 0).
func http2HeaderOctetsValid(_ headers: [(name: String, value: String)]) -> Bool {
    for (name, value) in headers {
        if !http2FieldNameValid(name) { return false }
        if !http2FieldValueValid(value) { return false }
    }
    return true
}

/// RFC 9113 §8.2.1: a field name MUST be non-empty and MUST NOT contain an uppercase letter
/// (0x41–0x5A), any byte ≤0x20 or ≥0x7F, or a colon other than a single leading pseudo-header sigil.
/// Not the HTTP/1 `tchar` set — h2 permits visible punctuation like `"`, `(`, `@` and bans only
/// these ranges, so the tchar check is both too strict and too lax here.
private func http2FieldNameValid(_ name: String) -> Bool {
    let bytes = name.utf8
    guard !bytes.isEmpty else { return false }
    for (i, c) in bytes.enumerated() {
        if c >= 0x41, c <= 0x5A { return false }   // uppercase
        if c <= 0x20 || c >= 0x7F { return false } // control / SP / DEL / high
        if c == 0x3A, i != 0 { return false }      // colon only as the leading pseudo-header sigil
    }
    return true
}

/// RFC 9113 §8.2.1: an empty value is permitted; a non-empty value MUST NOT carry NUL/LF/CR at any
/// position, nor begin or end with an ASCII whitespace character (SP 0x20 or HTAB 0x09).
private func http2FieldValueValid(_ value: String) -> Bool {
    let bytes = value.utf8
    guard let first = bytes.first else { return true } // empty value: allowed
    if first == 0x20 || first == 0x09 { return false }
    if let last = bytes.last, last == 0x20 || last == 0x09 { return false }
    for c in bytes {
        if c == 0x00 || c == 0x0A || c == 0x0D { return false }
    }
    return true
}

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

    /// Appends a header field as its on-the-wire bytes. HTTP/1 octets and HPACK string literals are
    /// byte strings (RFC 9110 §5.5 obs-text; RFC 7541 §5.2), so a value parsed as ISO-8859-1
    /// round-trips to the same octets. Falls back to UTF-8 only for scalars > 0xFF latin-1 can't hold.
    mutating func appendHeaderFieldBytes(_ field: String) {
        if let latin1 = field.data(using: .isoLatin1) {
            append(latin1)
        } else {
            append(contentsOf: field.utf8)
        }
    }
}
