//
//  MITMHeaderUtilities.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

nonisolated enum HTTPHeader {
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

    static func isValidValue(_ value: String) -> Bool {
        for byte in value.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return false
            }
        }
        return true
    }

    static func firstValue(in headers: [(name: String, value: String)], named name: String) -> String? {
        for (fieldName, fieldValue) in headers where ASCII.equalsIgnoringCase(fieldName, name) {
            return fieldValue
        }
        return nil
    }

    static func firstInvalidOctet(_ headers: [(name: String, value: String)]) -> (name: String, reason: String)? {
        for (name, value) in headers {
            if let reason = nameInvalidReason(name) { return (name, reason) }
            if let reason = valueInvalidReason(value) { return (name, reason) }
        }
        return nil
    }

    static func escapedForLog(_ fieldName: String, maxLength: Int = 48) -> String {
        var out = ""
        var emittedByteCount = 0
        for byte in fieldName.utf8 {
            if emittedByteCount >= maxLength {
                out += "…"
                break
            }
            if byte >= 0x20, byte < 0x7F, byte != 0x5C {
                out.append(Character(Unicode.Scalar(byte)))
            } else {
                out.append("\\x")
                out.append(hexDigits[Int(byte >> 4)])
                out.append(hexDigits[Int(byte & 0x0F)])
            }
            emittedByteCount += 1
        }
        return out
    }

    static func appendFieldBytes(_ field: String, to data: inout Data) {
        if let latin1 = field.data(using: .isoLatin1) {
            data.append(latin1)
        } else {
            data.append(contentsOf: field.utf8)
        }
    }

    // MARK: - Private

    private static func nameInvalidReason(_ name: String) -> String? {
        let bytes = name.utf8
        guard !bytes.isEmpty else { return "empty field name" }
        for (index, byte) in bytes.enumerated() {
            if byte >= 0x41, byte <= 0x5A { return "uppercase \(hexByte(byte)) at \(index)" }
            if byte <= 0x20 || byte >= 0x7F { return "control/SP/DEL/high \(hexByte(byte)) at \(index)" }
            if byte == 0x3A, index != 0 { return "non-leading colon at \(index)" }
        }
        return nil
    }

    private static func valueInvalidReason(_ value: String) -> String? {
        for (index, byte) in value.utf8.enumerated() {
            if byte == 0x00 || byte == 0x0A || byte == 0x0D { return "NUL/LF/CR \(hexByte(byte)) at \(index)" }
        }
        return nil
    }

    private static let hexDigits = Array("0123456789abcdef")

    private static func hexByte(_ byte: UInt8) -> String {
        "0x\(hexDigits[Int(byte >> 4)])\(hexDigits[Int(byte & 0x0F)])"
    }
}

nonisolated enum ASCII {
    static func equalsIgnoringCase(_ lhs: String, _ rhs: String) -> Bool {
        let lhsBytes = lhs.utf8
        let rhsBytes = rhs.utf8
        guard lhsBytes.count == rhsBytes.count else { return false }
        var i = lhsBytes.startIndex
        var j = rhsBytes.startIndex
        while i < lhsBytes.endIndex {
            let leftByte = lhsBytes[i]
            let rightByte = rhsBytes[j]
            // 0x20 is the ASCII case bit; non-letters skip the fold.
            let foldedLeft = (leftByte >= 0x41 && leftByte <= 0x5A) ? leftByte | 0x20 : leftByte
            let foldedRight = (rightByte >= 0x41 && rightByte <= 0x5A) ? rightByte | 0x20 : rightByte
            if foldedLeft != foldedRight { return false }
            i = lhsBytes.index(after: i)
            j = rhsBytes.index(after: j)
        }
        return true
    }
}
