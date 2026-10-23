//
//  Scanner+Input.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

// MARK: - Character classes

extension Scanner {
    func byte(at offset: Int = 0) -> UInt8 {
        let index = position + offset
        return index < input.count ? input[index] : 0
    }

    func matches(_ character: Unicode.Scalar, at offset: Int = 0) -> Bool {
        byte(at: offset) == UInt8(ascii: character)
    }

    func isEnd(at offset: Int = 0) -> Bool {
        position + offset >= input.count
    }

    func isBlank(at offset: Int = 0) -> Bool {
        matches(" ", at: offset) || matches("\t", at: offset)
    }

    func isBreak(at offset: Int = 0) -> Bool {
        switch byte(at: offset) {
        case UInt8(ascii: "\r"), UInt8(ascii: "\n"):
            return true
        case 0xC2:
            return byte(at: offset + 1) == 0x85
        case 0xE2:
            return byte(at: offset + 1) == 0x80 && (byte(at: offset + 2) == 0xA8 || byte(at: offset + 2) == 0xA9)
        default:
            return false
        }
    }

    func isBreakOrEnd(at offset: Int = 0) -> Bool {
        isBreak(at: offset) || isEnd(at: offset)
    }

    func isWhitespaceOrEnd(at offset: Int = 0) -> Bool {
        isBlank(at: offset) || isBreakOrEnd(at: offset)
    }

    func isDigit(at offset: Int = 0) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte(at: offset))
    }

    func isHexDigit(at offset: Int = 0) -> Bool {
        hexDigitValue(at: offset) != nil
    }

    func hexDigitValue(at offset: Int = 0) -> UInt32? {
        let byte = byte(at: offset)
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return UInt32(byte - UInt8(ascii: "0"))
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return UInt32(byte - UInt8(ascii: "A") + 10)
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return UInt32(byte - UInt8(ascii: "a") + 10)
        default:
            return nil
        }
    }

    func isWordCharacter(at offset: Int = 0) -> Bool {
        switch byte(at: offset) {
        case UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "A")...UInt8(ascii: "Z"),
             UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "_"),
             UInt8(ascii: "-"):
            return true
        default:
            return false
        }
    }

    func isByteOrderMark() -> Bool {
        byte() == 0xEF && byte(at: 1) == 0xBB && byte(at: 2) == 0xBF
    }

    func isDocumentIndicator(_ indicator: Unicode.Scalar) -> Bool {
        mark.column == 0
            && matches(indicator)
            && matches(indicator, at: 1)
            && matches(indicator, at: 2)
            && isWhitespaceOrEnd(at: 3)
    }
}

// MARK: - Advancing

extension Scanner {
    static func sequenceLength(leadingByte: UInt8) -> Int {
        switch leadingByte {
        case 0x00...0x7F: 1
        case 0xC0...0xDF: 2
        case 0xE0...0xEF: 3
        case 0xF0...0xF7: 4
        default: 0
        }
    }

    private var characterLength: Int {
        isEnd() ? 1 : Self.sequenceLength(leadingByte: byte())
    }

    mutating func skip() {
        position += characterLength
        mark.index += 1
        mark.column += 1
    }

    mutating func skipLineBreak() {
        if matches("\r") && matches("\n", at: 1) {
            position += 2
            mark.index += 2
        } else if isBreak() {
            position += characterLength
            mark.index += 1
        } else {
            return
        }
        mark.line += 1
        mark.column = 0
    }

    mutating func read(into buffer: inout [UInt8]) {
        let byte = byte()
        if byte < 0x80 {
            buffer.append(byte)
            position += 1
        } else {
            let end = position + Self.sequenceLength(leadingByte: byte)
            buffer.append(contentsOf: input[position..<end])
            position = end
        }
        mark.index += 1
        mark.column += 1
    }

    mutating func readLineBreak(into buffer: inout [UInt8]) {
        if matches("\r") && matches("\n", at: 1) {
            buffer.append(UInt8(ascii: "\n"))
            position += 2
            mark.index += 2
        } else if matches("\r") || matches("\n") {
            buffer.append(UInt8(ascii: "\n"))
            position += 1
            mark.index += 1
        } else if byte() == 0xC2 && byte(at: 1) == 0x85 {
            buffer.append(UInt8(ascii: "\n"))
            position += 2
            mark.index += 1
        } else if isBreak() {
            buffer.append(contentsOf: input[position..<position + 3])
            position += 3
            mark.index += 1
        } else {
            return
        }
        mark.line += 1
        mark.column = 0
    }
}
