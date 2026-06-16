//
//  NaiveHTTP2Framer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

// MARK: - Error

enum NaiveHTTP2Error: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case protocolError(String)
    case tunnelFailed(statusCode: String)
    case authenticationRequired
    case goaway
    case streamReset(UInt32)

    var errorDescription: String? {
        switch self {
        case .notReady: return "HTTP/2 connection not ready"
        case .connectionFailed(let msg): return "HTTP/2 connection failed: \(msg)"
        case .protocolError(let msg): return "HTTP/2 protocol error: \(msg)"
        case .tunnelFailed(let code): return "HTTP/2 CONNECT tunnel failed with status \(code)"
        case .authenticationRequired: return "HTTP/2 proxy authentication required (407)"
        case .goaway: return "HTTP/2 GOAWAY received"
        case .streamReset(let sid): return "HTTP/2 stream \(sid) reset"
        }
    }
}

// MARK: - Frame Types and Flags

/// HTTP/2 frame types (RFC 7540 §6).
enum NaiveHTTP2FrameType: UInt8 {
    case data         = 0x0
    case headers      = 0x1
    case rstStream    = 0x3
    case settings     = 0x4
    case ping         = 0x6
    case goaway       = 0x7
    case windowUpdate = 0x8
}

/// HTTP/2 frame flag constants.
enum NaiveHTTP2FrameFlags {
    /// DATA, HEADERS: last frame the endpoint will send for the stream.
    static let endStream: UInt8    = 0x1
    /// SETTINGS, PING: acknowledgment.
    static let ack: UInt8          = 0x1
    /// HEADERS: indicates the header block is complete (no CONTINUATION).
    static let endHeaders: UInt8   = 0x4
    /// DATA, HEADERS: indicates padding is present.
    static let padded: UInt8       = 0x8
}

// MARK: - Frame

/// A single HTTP/2 frame (RFC 7540 §4.1): 9-byte header + payload.
struct NaiveHTTP2Frame {
    let type: NaiveHTTP2FrameType
    let flags: UInt8
    let streamID: UInt32
    let payload: Data

    func hasFlag(_ flag: UInt8) -> Bool { flags & flag != 0 }

    /// Serializes this frame to wire format (RFC 7540 §4.1): 9-byte header + payload.
    var serialized: Data {
        var data = Data(capacity: NaiveHTTP2Framer.headerSize + payload.count)
        HTTP2FrameWire.appendHeader(type: type.rawValue, flags: flags, streamID: streamID,
                                    payloadLength: payload.count, into: &data)
        data.append(payload)
        return data
    }
}

// MARK: - Framer

enum NaiveHTTP2Framer {
    static let headerSize = HTTP2FrameWire.headerSize
    static let maxDataPayload = 16_384  // HTTP/2 default SETTINGS_MAX_FRAME_SIZE

    // MARK: Deserialize

    /// Deserializes one complete frame from `buffer`, removing the consumed bytes; `nil` if incomplete.
    static func deserialize(from buffer: inout Data) -> NaiveHTTP2Frame? {
        guard buffer.count >= headerSize else { return nil }

        let b = buffer
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

        guard let type = NaiveHTTP2FrameType(rawValue: rawType) else {
            // Unknown frame type — skip per RFC 7540 §4.1
            return NaiveHTTP2Frame(type: NaiveHTTP2FrameType.data, flags: 0, streamID: sid, payload: Data())
        }

        return NaiveHTTP2Frame(type: type, flags: flags, streamID: sid, payload: payload)
    }

    // MARK: - Convenience Builders

    static func settingsFrame(_ settings: [(id: UInt16, value: UInt32)]) -> NaiveHTTP2Frame {
        var payload = Data(capacity: settings.count * 6)
        for (id, value) in settings {
            payload.append(UInt8(id >> 8))
            payload.append(UInt8(id & 0xFF))
            payload.append(UInt8((value >> 24) & 0xFF))
            payload.append(UInt8((value >> 16) & 0xFF))
            payload.append(UInt8((value >> 8) & 0xFF))
            payload.append(UInt8(value & 0xFF))
        }
        return NaiveHTTP2Frame(type: NaiveHTTP2FrameType.settings, flags: 0, streamID: 0, payload: payload)
    }

    static func settingsAckFrame() -> NaiveHTTP2Frame {
        NaiveHTTP2Frame(type: NaiveHTTP2FrameType.settings, flags: NaiveHTTP2FrameFlags.ack, streamID: 0, payload: Data())
    }

    static func windowUpdateFrame(streamID: UInt32, increment: UInt32) -> NaiveHTTP2Frame {
        var payload = Data(capacity: 4)
        HTTP2FrameWire.appendUInt32(increment & 0x7FFFFFFF, into: &payload)
        return NaiveHTTP2Frame(type: NaiveHTTP2FrameType.windowUpdate, flags: 0, streamID: streamID, payload: payload)
    }

    /// Creates a HEADERS frame (END_HEADERS set) with an HPACK-encoded header block.
    static func headersFrame(streamID: UInt32, headerBlock: Data, endStream: Bool = false) -> NaiveHTTP2Frame {
        var flags: UInt8 = NaiveHTTP2FrameFlags.endHeaders
        if endStream { flags |= NaiveHTTP2FrameFlags.endStream }
        return NaiveHTTP2Frame(type: NaiveHTTP2FrameType.headers, flags: flags, streamID: streamID, payload: headerBlock)
    }

    static func dataFrame(streamID: UInt32, payload: Data, endStream: Bool = false) -> NaiveHTTP2Frame {
        var flags: UInt8 = 0
        if endStream { flags |= NaiveHTTP2FrameFlags.endStream }
        return NaiveHTTP2Frame(type: NaiveHTTP2FrameType.data, flags: flags, streamID: streamID, payload: payload)
    }

    static func rstStreamFrame(streamID: UInt32, errorCode: UInt32) -> NaiveHTTP2Frame {
        var payload = Data(capacity: 4)
        HTTP2FrameWire.appendUInt32(errorCode, into: &payload)
        return NaiveHTTP2Frame(type: NaiveHTTP2FrameType.rstStream, flags: 0, streamID: streamID, payload: payload)
    }

    /// Creates a PING ACK frame, echoing back the opaque data as required by RFC 7540 §6.7.
    static func pingAckFrame(opaqueData: Data) -> NaiveHTTP2Frame {
        NaiveHTTP2Frame(type: NaiveHTTP2FrameType.ping, flags: NaiveHTTP2FrameFlags.ack, streamID: 0, payload: opaqueData)
    }

    // MARK: - Payload Parsers

    static func parseSettings(payload: Data) -> [(id: UInt16, value: UInt32)] {
        HTTP2FrameWire.parseSettings(payload)
    }

    static func parseWindowUpdate(payload: Data) -> UInt32? {
        HTTP2FrameWire.readUInt32(payload).map { $0 & 0x7FFFFFFF }
    }

    static func parseGoaway(payload: Data) -> (lastStreamID: UInt32, errorCode: UInt32)? {
        HTTP2FrameWire.parseGoaway(payload)
    }

    static func parseRstStream(payload: Data) -> UInt32? {
        HTTP2FrameWire.readUInt32(payload)
    }
}
