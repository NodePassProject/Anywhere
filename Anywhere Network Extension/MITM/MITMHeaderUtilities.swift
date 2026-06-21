//
//  MITMHeaderUtilities.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

enum HTTPHeader {
    /// Parses a status code as exactly three ASCII digits (RFC 9112 §4).
    static func parseStatusCode(_ raw: some StringProtocol) -> Int? {
        let trimmed = String(raw).trimmingCharacters(in: .whitespaces)
        guard trimmed.utf8.count == 3 else { return nil }
        var value = 0
        for byte in trimmed.utf8 {
            guard (0x30...0x39).contains(byte) else { return nil }
            value = value * 10 + Int(byte - 0x30)
        }
        return value
    }

    /// RFC 9110 §5.6.2: a field-name is one or more `tchar`.
    /// Also validates method tokens (RFC 9110 §9.1).
    static func isValidName(_ name: String) -> Bool {
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
    static func isValidValue(_ value: String) -> Bool {
        for byte in value.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return false
            }
        }
        return true
    }

    /// First value whose name matches `name` case-insensitively (RFC 9110 §5.1), or nil.
    static func firstValue(in headers: [(name: String, value: String)], named name: String) -> String? {
        for (n, v) in headers where ASCII.equalsIgnoringCase(n, name) {
            return v
        }
        return nil
    }

    /// Screens decoded HTTP/2 header octets (RFC 9113 §8.2.1): the first non-conformant field, with a
    /// short reason (failing rule, octet, position), or nil when every field conforms.
    static func firstInvalidOctet(_ headers: [(name: String, value: String)]) -> (name: String, reason: String)? {
        for (name, value) in headers {
            if let reason = nameInvalidReason(name) { return (name, reason) }
            if let reason = valueInvalidReason(value) { return (name, reason) }
        }
        return nil
    }

    /// Renders a header field *name* for logs: printable ASCII verbatim, every other byte (and the
    /// escape char itself) as `\xHH`, bounded to `max` bytes so a hostile or corrupt peer can't flood
    /// the log.
    static func escapedForLog(_ fieldName: String, max: Int = 48) -> String {
        var out = ""
        var emittedByteCount = 0
        for b in fieldName.utf8 {
            if emittedByteCount >= max { out += "…"; break }
            if b >= 0x20, b < 0x7F, b != 0x5C {
                out.append(Character(Unicode.Scalar(b)))
            } else {
                out.append("\\x")
                out.append(hexDigits[Int(b >> 4)])
                out.append(hexDigits[Int(b & 0x0F)])
            }
            emittedByteCount += 1
        }
        return out
    }

    /// Appends a header field as its on-the-wire bytes to `data`. HTTP/1 octets and HPACK string
    /// literals are byte strings (RFC 9110 §5.5 obs-text; RFC 7541 §5.2), so a value parsed as
    /// ISO-8859-1 round-trips to the same octets. Falls back to UTF-8 only for scalars > 0xFF that
    /// latin-1 can't represent.
    static func appendFieldBytes(_ field: String, to data: inout Data) {
        if let latin1 = field.data(using: .isoLatin1) {
            data.append(latin1)
        } else {
            data.append(contentsOf: field.utf8)
        }
    }

    // MARK: - Private

    /// RFC 9113 §8.2.1: a field name MUST be non-empty and MUST NOT contain an uppercase letter
    /// (0x41–0x5A), any byte ≤0x20 or ≥0x7F, or a colon other than a single leading pseudo-header sigil.
    /// Not the HTTP/1 `tchar` set — h2 permits visible punctuation like `"`, `(`, `@` and bans only
    /// these ranges, so the tchar check is both too strict and too lax here. Returns nil when conformant.
    private static func nameInvalidReason(_ name: String) -> String? {
        let bytes = name.utf8
        guard !bytes.isEmpty else { return "empty field name" }
        for (i, c) in bytes.enumerated() {
            if c >= 0x41, c <= 0x5A { return "uppercase \(hexByte(c)) at \(i)" }
            if c <= 0x20 || c >= 0x7F { return "control/SP/DEL/high \(hexByte(c)) at \(i)" }
            if c == 0x3A, i != 0 { return "non-leading colon at \(i)" }
        }
        return nil
    }

    /// RFC 9113 §8.2.1: an empty value is permitted; a non-empty value MUST NOT carry NUL/LF/CR at any
    /// position — the request-/response-splitting primitive once these octets reach the HTTP/1.1 wire.
    private static func valueInvalidReason(_ value: String) -> String? {
        for (i, c) in value.utf8.enumerated() {
            if c == 0x00 || c == 0x0A || c == 0x0D { return "NUL/LF/CR \(hexByte(c)) at \(i)" }
        }
        return nil
    }

    private static let hexDigits = Array("0123456789abcdef")

    /// `0xHH` rendering of a byte for diagnostics.
    private static func hexByte(_ byte: UInt8) -> String {
        "0x\(hexDigits[Int(byte >> 4)])\(hexDigits[Int(byte & 0x0F)])"
    }
}

enum ASCII {
    /// Allocation-free ASCII case-insensitive equality. HTTP field-names and the tokens compared
    /// against them are all-ASCII (RFC 9110 §5.6.2).
    static func equalsIgnoringCase(_ a: String, _ b: String) -> Bool {
        let lhs = a.utf8
        let rhs = b.utf8
        guard lhs.count == rhs.count else { return false }
        var i = lhs.startIndex
        var j = rhs.startIndex
        while i < lhs.endIndex {
            let leftByte = lhs[i]
            let r = rhs[j]
            // 0x20 is the ASCII case bit; non-letters skip the fold.
            let foldedL = (leftByte >= 0x41 && leftByte <= 0x5A) ? leftByte | 0x20 : leftByte
            let foldedR = (r >= 0x41 && r <= 0x5A) ? r | 0x20 : r
            if foldedL != foldedR { return false }
            i = lhs.index(after: i)
            j = rhs.index(after: j)
        }
        return true
    }
}
