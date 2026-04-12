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
    case qpackMaxTableCapacity  = 0x01
    case maxFieldSectionSize    = 0x06
    case qpackBlockedStreams    = 0x07
    /// RFC 9220 — enables extended CONNECT with the `:protocol` pseudo-header.
    case enableConnectProtocol  = 0x08
    /// RFC 9297 — HTTP Datagrams for CONNECT-UDP and friends.
    case h3Datagram             = 0x33
}

// MARK: - Error Codes (RFC 9114 §8.1)

/// Application error codes carried on QUIC CONNECTION_CLOSE / RESET_STREAM /
/// STOP_SENDING frames for the HTTP/3 protocol layer.
enum HTTP3ErrorCode: UInt64 {
    case noError                = 0x0100
    case generalProtocolError   = 0x0101
    case internalError          = 0x0102
    case streamCreationError    = 0x0103
    case closedCriticalStream   = 0x0104
    case frameUnexpected        = 0x0105
    case frameError             = 0x0106
    case excessiveLoad          = 0x0107
    case idError                = 0x0108
    case settingsError          = 0x0109
    case missingSettings        = 0x010A
    case requestRejected        = 0x010B
    case requestCancelled       = 0x010C
    case requestIncomplete      = 0x010D
    case messageError           = 0x010E
    case connectError           = 0x010F
    case versionFallback        = 0x0110
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

        // SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 (RFC 9220 — extended CONNECT)
        payload.append(contentsOf: encodeVarInt(HTTP3SettingsID.enableConnectProtocol.rawValue))
        payload.append(contentsOf: encodeVarInt(1))

        // SETTINGS_H3_DATAGRAM = 1 (RFC 9297 — HTTP Datagrams / CONNECT-UDP)
        payload.append(contentsOf: encodeVarInt(HTTP3SettingsID.h3Datagram.rawValue))
        payload.append(contentsOf: encodeVarInt(1))

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
