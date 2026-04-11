//
//  HTTP3Framer.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

// MARK: - Frame Types

enum HTTP3FrameType: UInt64 {
    case data           = 0x00
    case headers        = 0x01
    case cancelPush     = 0x03
    case settings       = 0x04
    case pushPromise    = 0x05
    case goaway         = 0x07
    case maxPushId      = 0x0D
}

// MARK: - Settings IDs

enum HTTP3SettingsID: UInt64 {
    case maxFieldSectionSize = 0x06
    case qpackMaxTableCapacity = 0x01
    case qpackBlockedStreams = 0x07
}

// MARK: - HTTP3Framer

enum HTTP3Framer {

    // MARK: - Variable-Length Integer (RFC 9000 §16)

    /// Encodes a variable-length integer per QUIC encoding.
    static func encodeVarInt(_ value: UInt64) -> Data {
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

    /// Decodes a variable-length integer. Returns (value, bytesConsumed) or nil.
    static func decodeVarInt(from data: Data, offset: Int = 0) -> (UInt64, Int)? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        let prefix = first >> 6

        switch prefix {
        case 0:
            return (UInt64(first), 1)
        case 1:
            guard offset + 2 <= data.count else { return nil }
            let value = (UInt64(first & 0x3F) << 8) | UInt64(data[offset + 1])
            return (value, 2)
        case 2:
            guard offset + 4 <= data.count else { return nil }
            var value = UInt64(first & 0x3F) << 24
            value |= UInt64(data[offset + 1]) << 16
            value |= UInt64(data[offset + 2]) << 8
            value |= UInt64(data[offset + 3])
            return (value, 4)
        case 3:
            guard offset + 8 <= data.count else { return nil }
            var value = UInt64(first & 0x3F) << 56
            for i in 1..<8 {
                value |= UInt64(data[offset + i]) << ((7 - i) * 8)
            }
            return (value, 8)
        default:
            return nil
        }
    }

    // MARK: - Frame Construction

    /// Builds an HTTP/3 HEADERS frame from QPACK-encoded header block.
    static func headersFrame(headerBlock: Data) -> Data {
        var frame = Data()
        frame.append(contentsOf: encodeVarInt(HTTP3FrameType.headers.rawValue))
        frame.append(contentsOf: encodeVarInt(UInt64(headerBlock.count)))
        frame.append(headerBlock)
        return frame
    }

    /// Builds an HTTP/3 DATA frame.
    static func dataFrame(payload: Data) -> Data {
        var frame = Data()
        frame.append(contentsOf: encodeVarInt(HTTP3FrameType.data.rawValue))
        frame.append(contentsOf: encodeVarInt(UInt64(payload.count)))
        frame.append(payload)
        return frame
    }

    /// Builds an HTTP/3 SETTINGS frame with default client settings.
    static func clientSettingsFrame() -> Data {
        var payload = Data()

        // QPACK_MAX_TABLE_CAPACITY = 0 (no dynamic table)
        payload.append(contentsOf: encodeVarInt(HTTP3SettingsID.qpackMaxTableCapacity.rawValue))
        payload.append(contentsOf: encodeVarInt(0))

        // QPACK_BLOCKED_STREAMS = 0
        payload.append(contentsOf: encodeVarInt(HTTP3SettingsID.qpackBlockedStreams.rawValue))
        payload.append(contentsOf: encodeVarInt(0))

        // MAX_FIELD_SECTION_SIZE = 262144
        payload.append(contentsOf: encodeVarInt(HTTP3SettingsID.maxFieldSectionSize.rawValue))
        payload.append(contentsOf: encodeVarInt(262144))

        var frame = Data()
        frame.append(contentsOf: encodeVarInt(HTTP3FrameType.settings.rawValue))
        frame.append(contentsOf: encodeVarInt(UInt64(payload.count)))
        frame.append(payload)
        return frame
    }

    // MARK: - Frame Parsing

    /// Parsed HTTP/3 frame.
    struct Frame {
        let type: UInt64
        let payload: Data
    }

    /// Attempts to parse one HTTP/3 frame from the buffer.
    /// Returns the frame and the number of bytes consumed, or nil if incomplete.
    static func parseFrame(from data: Data, offset: Int = 0) -> (Frame, Int)? {
        var pos = offset

        guard let (frameType, typeLen) = decodeVarInt(from: data, offset: pos) else { return nil }
        pos += typeLen

        guard let (payloadLen, lenBytes) = decodeVarInt(from: data, offset: pos) else { return nil }
        pos += lenBytes

        let totalLen = pos - offset + Int(payloadLen)
        guard offset + totalLen <= data.count else { return nil }

        let payload = Data(data[pos..<(pos + Int(payloadLen))])
        return (Frame(type: frameType, payload: payload), totalLen)
    }
}
