//
//  HTTP2Framer.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation

// MARK: - Frame Types and Flags

/// HTTP/2 frame types (RFC 7540 §6).
enum HTTP2FrameType: UInt8 {
    case data         = 0x0
    case headers      = 0x1
    case rstStream    = 0x3
    case settings     = 0x4
    case ping         = 0x6
    case goaway       = 0x7
    case windowUpdate = 0x8
}

/// HTTP/2 frame flag constants.
enum HTTP2FrameFlags {
    /// DATA: indicates this is the last frame the endpoint will send for the stream.
    /// HEADERS: same.
    static let endStream: UInt8    = 0x1
    /// SETTINGS, PING: acknowledgment.
    static let ack: UInt8          = 0x1
    /// HEADERS: indicates the header block is complete (no CONTINUATION).
    static let endHeaders: UInt8   = 0x4
    /// DATA, HEADERS: indicates padding is present.
    static let padded: UInt8       = 0x8
}

// MARK: - Frame

/// A single HTTP/2 frame (RFC 7540 §4.1).
///
/// Wire format (9-byte header + payload):
/// ```
/// [3 bytes] Length  (payload length, unsigned 24-bit)
/// [1 byte]  Type
/// [1 byte]  Flags
/// [4 bytes] Stream ID (bit 0 reserved, always 0)
/// [Length bytes] Payload
/// ```
struct HTTP2Frame {
    let type: HTTP2FrameType
    let flags: UInt8
    let streamID: UInt32
    let payload: Data

    func hasFlag(_ flag: UInt8) -> Bool { flags & flag != 0 }
}

// MARK: - Framer

/// HTTP/2 frame serializer and deserializer.
enum HTTP2Framer {
    static let headerSize = 9
    static let maxDataPayload = 16_384  // HTTP/2 default SETTINGS_MAX_FRAME_SIZE

    // MARK: Serialize

    /// Serializes a frame into wire format (9-byte header + payload).
    static func serialize(_ frame: HTTP2Frame) -> Data {
        let length = UInt32(frame.payload.count)
        var data = Data(capacity: headerSize + frame.payload.count)
        // 24-bit length (big-endian)
        data.append(UInt8((length >> 16) & 0xFF))
        data.append(UInt8((length >> 8) & 0xFF))
        data.append(UInt8(length & 0xFF))
        // Type
        data.append(frame.type.rawValue)
        // Flags
        data.append(frame.flags)
        // 31-bit stream ID (big-endian, reserved bit 0)
        let sid = frame.streamID & 0x7FFFFFFF
        data.append(UInt8((sid >> 24) & 0xFF))
        data.append(UInt8((sid >> 16) & 0xFF))
        data.append(UInt8((sid >> 8) & 0xFF))
        data.append(UInt8(sid & 0xFF))
        // Payload
        data.append(frame.payload)
        return data
    }

    // MARK: Deserialize

    /// Attempts to deserialize one complete frame from `buffer`.
    ///
    /// On success, removes the consumed bytes from `buffer` and returns the frame.
    /// Returns `nil` if `buffer` does not contain a complete frame.
    static func deserialize(from buffer: inout Data) -> HTTP2Frame? {
        guard buffer.count >= headerSize else { return nil }

        let b = buffer  // local copy for reading header
        let s = b.startIndex

        let length = Int(b[s]) << 16 | Int(b[s+1]) << 8 | Int(b[s+2])
        let totalSize = headerSize + length

        guard buffer.count >= totalSize else { return nil }

        let rawType = b[s+3]
        let flags = b[s+4]
        let streamID = UInt32(b[s+5]) << 24 | UInt32(b[s+6]) << 16
                     | UInt32(b[s+7]) << 8 | UInt32(b[s+8])
        let sid = streamID & 0x7FFFFFFF

        let payload = Data(buffer[(s + headerSize)..<(s + totalSize)])
        buffer.removeFirst(totalSize)

        guard let type = HTTP2FrameType(rawValue: rawType) else {
            // Unknown frame type — skip per RFC 7540 §4.1
            return HTTP2Frame(type: HTTP2FrameType.data, flags: 0, streamID: sid, payload: Data())
        }

        return HTTP2Frame(type: type, flags: flags, streamID: sid, payload: payload)
    }

    // MARK: - Convenience Builders

    /// Creates a SETTINGS frame with the given parameters (id, value pairs).
    static func settingsFrame(_ settings: [(id: UInt16, value: UInt32)]) -> HTTP2Frame {
        var payload = Data(capacity: settings.count * 6)
        for (id, value) in settings {
            payload.append(UInt8(id >> 8))
            payload.append(UInt8(id & 0xFF))
            payload.append(UInt8((value >> 24) & 0xFF))
            payload.append(UInt8((value >> 16) & 0xFF))
            payload.append(UInt8((value >> 8) & 0xFF))
            payload.append(UInt8(value & 0xFF))
        }
        return HTTP2Frame(type: HTTP2FrameType.settings, flags: 0, streamID: 0, payload: payload)
    }

    /// Creates a SETTINGS ACK frame.
    static func settingsAckFrame() -> HTTP2Frame {
        HTTP2Frame(type: HTTP2FrameType.settings, flags: HTTP2FrameFlags.ack, streamID: 0, payload: Data())
    }

    /// Creates a WINDOW_UPDATE frame.
    static func windowUpdateFrame(streamID: UInt32, increment: UInt32) -> HTTP2Frame {
        var payload = Data(capacity: 4)
        let inc = increment & 0x7FFFFFFF
        payload.append(UInt8((inc >> 24) & 0xFF))
        payload.append(UInt8((inc >> 16) & 0xFF))
        payload.append(UInt8((inc >> 8) & 0xFF))
        payload.append(UInt8(inc & 0xFF))
        return HTTP2Frame(type: HTTP2FrameType.windowUpdate, flags: 0, streamID: streamID, payload: payload)
    }

    /// Creates a HEADERS frame (END_HEADERS set) with an HPACK-encoded header block.
    static func headersFrame(streamID: UInt32, headerBlock: Data, endStream: Bool = false) -> HTTP2Frame {
        var flags: UInt8 = HTTP2FrameFlags.endHeaders
        if endStream { flags |= HTTP2FrameFlags.endStream }
        return HTTP2Frame(type: HTTP2FrameType.headers, flags: flags, streamID: streamID, payload: headerBlock)
    }

    /// Creates a DATA frame.
    static func dataFrame(streamID: UInt32, payload: Data, endStream: Bool = false) -> HTTP2Frame {
        var flags: UInt8 = 0
        if endStream { flags |= HTTP2FrameFlags.endStream }
        return HTTP2Frame(type: HTTP2FrameType.data, flags: flags, streamID: streamID, payload: payload)
    }

    /// Creates a PING ACK frame echoing back the opaque data.
    static func pingAckFrame(opaqueData: Data) -> HTTP2Frame {
        HTTP2Frame(type: HTTP2FrameType.ping, flags: HTTP2FrameFlags.ack, streamID: 0, payload: opaqueData)
    }

    // MARK: - Payload Parsers

    /// Parses SETTINGS payload into (id, value) pairs.
    static func parseSettings(payload: Data) -> [(id: UInt16, value: UInt32)] {
        var result: [(id: UInt16, value: UInt32)] = []
        var offset = payload.startIndex
        while offset + 6 <= payload.endIndex {
            let id = UInt16(payload[offset]) << 8 | UInt16(payload[offset+1])
            let value = UInt32(payload[offset+2]) << 24 | UInt32(payload[offset+3]) << 16
                      | UInt32(payload[offset+4]) << 8 | UInt32(payload[offset+5])
            result.append((id: id, value: value))
            offset += 6
        }
        return result
    }

    /// Parses WINDOW_UPDATE payload.
    static func parseWindowUpdate(payload: Data) -> UInt32? {
        guard payload.count >= 4 else { return nil }
        let s = payload.startIndex
        return (UInt32(payload[s]) << 24 | UInt32(payload[s+1]) << 16
              | UInt32(payload[s+2]) << 8 | UInt32(payload[s+3])) & 0x7FFFFFFF
    }

    /// Parses GOAWAY payload.
    static func parseGoaway(payload: Data) -> (lastStreamID: UInt32, errorCode: UInt32)? {
        guard payload.count >= 8 else { return nil }
        let s = payload.startIndex
        let lastStreamID = (UInt32(payload[s]) << 24 | UInt32(payload[s+1]) << 16
                          | UInt32(payload[s+2]) << 8 | UInt32(payload[s+3])) & 0x7FFFFFFF
        let errorCode = UInt32(payload[s+4]) << 24 | UInt32(payload[s+5]) << 16
                      | UInt32(payload[s+6]) << 8 | UInt32(payload[s+7])
        return (lastStreamID, errorCode)
    }

    /// Parses RST_STREAM payload.
    static func parseRstStream(payload: Data) -> UInt32? {
        guard payload.count >= 4 else { return nil }
        let s = payload.startIndex
        return UInt32(payload[s]) << 24 | UInt32(payload[s+1]) << 16
             | UInt32(payload[s+2]) << 8 | UInt32(payload[s+3])
    }
}
