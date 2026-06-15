//
//  QUICVarInt.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

// MARK: - QUICVarInt

/// QUIC variable-length integer codec (RFC 9000 §16). The two high bits of the first
/// byte select a 1/2/4/8-byte encoding; the remaining bits hold the value. A transport
/// primitive shared by the HTTP/3 framing and QPACK layers, which ride QUIC streams.
enum QUICVarInt {

    static func encode(_ value: UInt64) -> Data {
        var data = Data()
        if value <= 63 {
            data.append(UInt8(value))
        } else if value <= 16383 {
            data.append(UInt8(0x40 | (value >> 8)))
            data.append(UInt8(value & 0xFF))
        } else if value <= 1_073_741_823 {
            data.append(UInt8(0x80 | (value >> 24)))
            data.append(UInt8((value >> 16) & 0xFF))
            data.append(UInt8((value >> 8) & 0xFF))
            data.append(UInt8(value & 0xFF))
        } else {
            data.append(UInt8(0xC0 | (value >> 56)))
            data.append(UInt8((value >> 48) & 0xFF))
            data.append(UInt8((value >> 40) & 0xFF))
            data.append(UInt8((value >> 32) & 0xFF))
            data.append(UInt8((value >> 24) & 0xFF))
            data.append(UInt8((value >> 16) & 0xFF))
            data.append(UInt8((value >> 8) & 0xFF))
            data.append(UInt8(value & 0xFF))
        }
        return data
    }

    /// Returns (value, bytesConsumed) or nil. `offset` is relative to `data.startIndex`
    /// so callers can pass a zero-copy slice directly.
    static func decode(from data: Data, offset: Int = 0) -> (UInt64, Int)? {
        guard offset < data.count else { return nil }
        let base = data.startIndex
        let first = data[base + offset]
        let prefix = first >> 6

        switch prefix {
        case 0:
            return (UInt64(first), 1)
        case 1:
            guard offset + 2 <= data.count else { return nil }
            let value = (UInt64(first & 0x3F) << 8) | UInt64(data[base + offset + 1])
            return (value, 2)
        case 2:
            guard offset + 4 <= data.count else { return nil }
            var value = UInt64(first & 0x3F) << 24
            value |= UInt64(data[base + offset + 1]) << 16
            value |= UInt64(data[base + offset + 2]) << 8
            value |= UInt64(data[base + offset + 3])
            return (value, 4)
        case 3:
            guard offset + 8 <= data.count else { return nil }
            var value = UInt64(first & 0x3F) << 56
            for i in 1..<8 {
                value |= UInt64(data[base + offset + i]) << ((7 - i) * 8)
            }
            return (value, 8)
        default:
            return nil
        }
    }
}
