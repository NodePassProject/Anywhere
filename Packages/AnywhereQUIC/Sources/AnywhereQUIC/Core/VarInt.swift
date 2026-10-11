//
//  VarInt.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum VarInt {
    static let max: UInt64 = (1 << 62) - 1

    static func encodedLength(_ value: UInt64) -> Int {
        if value < 1 << 6 {
            return 1
        }
        if value < 1 << 14 {
            return 2
        }
        if value < 1 << 30 {
            return 4
        }
        return 8
    }

    static func decodedLength(firstByte: UInt8) -> Int {
        return 1 << Int(firstByte >> 6)
    }

    static func encode(_ value: UInt64, into bytes: inout [UInt8]) {
        precondition(value <= Self.max)
        switch Self.encodedLength(value) {
        case 1:
            bytes.append(UInt8(value))
        case 2:
            bytes.append(UInt8(value >> 8) | 0x40)
            bytes.append(UInt8(truncatingIfNeeded: value))
        case 4:
            bytes.append(UInt8(value >> 24) | 0x80)
            bytes.append(UInt8(truncatingIfNeeded: value >> 16))
            bytes.append(UInt8(truncatingIfNeeded: value >> 8))
            bytes.append(UInt8(truncatingIfNeeded: value))
        default:
            bytes.append(UInt8(value >> 56) | 0xC0)
            for shift in stride(from: 48, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
            }
        }
    }

    static func encode(_ value: UInt64) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(8)
        Self.encode(value, into: &bytes)
        return bytes
    }

    static func write(_ value: UInt64, length: Int, to pointer: UnsafeMutablePointer<UInt8>) {
        precondition(value <= Self.max)
        switch length {
        case 1:
            precondition(value < 1 << 6)
            pointer[0] = UInt8(value)
        case 2:
            precondition(value < 1 << 14)
            pointer[0] = UInt8(value >> 8) | 0x40
            pointer[1] = UInt8(truncatingIfNeeded: value)
        case 4:
            precondition(value < 1 << 30)
            pointer[0] = UInt8(value >> 24) | 0x80
            pointer[1] = UInt8(truncatingIfNeeded: value >> 16)
            pointer[2] = UInt8(truncatingIfNeeded: value >> 8)
            pointer[3] = UInt8(truncatingIfNeeded: value)
        case 8:
            pointer[0] = UInt8(value >> 56) | 0xC0
            var shift = 48
            for index in 1..<8 {
                pointer[index] = UInt8(truncatingIfNeeded: value >> UInt64(shift))
                shift -= 8
            }
        default:
            preconditionFailure("invalid varint length")
        }
    }

    static func read(from bytes: UnsafeRawBufferPointer) -> (value: UInt64, length: Int)? {
        guard let first = bytes.first else {
            return nil
        }
        let length = Self.decodedLength(firstByte: first)
        guard bytes.count >= length else {
            return nil
        }
        var value = UInt64(first & 0x3F)
        for index in 1..<length {
            value = value << 8 | UInt64(bytes[index])
        }
        return (value, length)
    }
}
