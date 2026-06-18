//
//  MITMHTTP2FrameCodec.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

/// Self-contained HTTP/2 frame primitives for the bridge's two legs (RFC 9113), not a full
/// HTTP/2 stack. Keeps its own frame structs, decode loops, flow control, and state machines,
/// so a stateful protocol fix (e.g. GOAWAY draining) must be applied here too.
enum MITMHTTP2FrameCodec {

    // MARK: Frame type codes

    enum FrameType {
        static let data: UInt8         = 0x0
        static let headers: UInt8      = 0x1
        static let priority: UInt8     = 0x2
        static let rstStream: UInt8    = 0x3
        static let settings: UInt8     = 0x4
        static let pushPromise: UInt8  = 0x5
        static let ping: UInt8         = 0x6
        static let goaway: UInt8       = 0x7
        static let windowUpdate: UInt8 = 0x8
        static let continuation: UInt8 = 0x9
    }

    // MARK: Error codes (RFC 9113 §7)

    enum ErrorCode {
        static let noError: UInt32        = 0x0
        static let protocolError: UInt32  = 0x1
        static let internalError: UInt32  = 0x2
        static let frameSizeError: UInt32 = 0x6
        static let refusedStream: UInt32  = 0x7
        static let cancel: UInt32         = 0x8
        static let compressionError: UInt32 = 0x9
        static let http11Required: UInt32 = 0xd
    }

    // MARK: Sizes

    /// RFC 9113 §6.5.2 mandated minimum SETTINGS_MAX_FRAME_SIZE; the bridge advertises
    /// no larger value, so the client must not exceed it.
    static let maxFramePayloadSize = 16_384

    /// Hard cap on an accepted frame payload, above the advertised 16 KiB so a peer can't force an
    /// unbounded allocation. Frames between 16 KiB and this cap are accepted rather than
    /// FRAME_SIZE_ERROR'd (safe: flow control accounts the true on-wire length); past it, dropped.
    static let maxReceivedFramePayloadSize = 1 * 1024 * 1024

    /// The h2 connection preface octets a client sends first (RFC 9113 §3.4).
    static let clientPrefaceLength = 24

    // MARK: Raw frame

    struct RawFrame {
        var typeCode: UInt8
        var flags: UInt8
        var streamID: UInt32
        var payload: Data
    }

    enum ParseResult {
        case frame(RawFrame)
        case needMore
        /// Length exceeded the receive cap; the buffer is unrecoverable.
        case error
    }

    /// Reads one complete frame, consuming its bytes. `.needMore` when incomplete.
    static func parseFrame(from buffer: inout MITMByteBuffer) -> ParseResult {
        guard buffer.count >= 9 else { return .needMore }
        let length = (Int(buffer[0]) << 16) | (Int(buffer[1]) << 8) | Int(buffer[2])
        if length > maxReceivedFramePayloadSize {
            buffer.removeAll(keepingCapacity: false)
            return .error
        }
        let total = 9 + length
        guard buffer.count >= total else { return .needMore }
        let type = buffer[3]
        let flags = buffer[4]
        let streamID = (UInt32(buffer[5]) << 24
                      | UInt32(buffer[6]) << 16
                      | UInt32(buffer[7]) << 8
                      | UInt32(buffer[8])) & 0x7FFFFFFF
        let payload = buffer.subdata(in: 9..<total)
        buffer.removeFirst(total)
        return .frame(RawFrame(typeCode: type, flags: flags, streamID: streamID, payload: payload))
    }

    // MARK: Header writing

    /// Writes a 9-byte frame header into `out`.
    static func appendFrameHeader(
        typeCode: UInt8,
        flags: UInt8,
        streamID: UInt32,
        payloadLength: Int,
        into out: inout Data
    ) {
        HTTP2FrameWire.appendHeader(type: typeCode, flags: flags, streamID: streamID,
                                    payloadLength: payloadLength, into: &out)
    }

    // MARK: HEADERS / DATA emit

    /// Emits a HEADERS frame plus CONTINUATIONs as needed (RFC 9113 §6.2/§6.10);
    /// END_HEADERS on the final frame, END_STREAM on the first.
    static func emitHeaders(streamID: UInt32, block: Data, endStream: Bool) -> Data {
        let firstChunkSize = min(block.count, maxFramePayloadSize)
        let firstChunkEnd = block.startIndex + firstChunkSize
        let needsContinuation = firstChunkEnd < block.endIndex

        var firstFlags: UInt8 = 0
        if !needsContinuation { firstFlags |= 0x4 } // END_HEADERS
        if endStream { firstFlags |= 0x1 }          // END_STREAM

        var out = Data(capacity: 9 + block.count + 16)
        appendFrameHeader(
            typeCode: FrameType.headers,
            flags: firstFlags,
            streamID: streamID,
            payloadLength: firstChunkSize,
            into: &out
        )
        out.append(block[block.startIndex..<firstChunkEnd])

        var offset = firstChunkEnd
        while offset < block.endIndex {
            let end = min(block.endIndex, offset + maxFramePayloadSize)
            let isLast = end == block.endIndex
            appendFrameHeader(
                typeCode: FrameType.continuation,
                flags: isLast ? 0x4 : 0,
                streamID: streamID,
                payloadLength: end - offset,
                into: &out
            )
            out.append(block[offset..<end])
            offset = end
        }
        return out
    }

    /// Pure DATA framing (no flow-control accounting); an empty payload still yields
    /// one zero-length DATA so END_STREAM survives.
    static func frameData(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        if payload.isEmpty {
            var out = Data(capacity: 9)
            appendFrameHeader(
                typeCode: FrameType.data,
                flags: endStream ? 0x1 : 0,
                streamID: streamID,
                payloadLength: 0,
                into: &out
            )
            return out
        }
        let frameCount = (payload.count + maxFramePayloadSize - 1) / maxFramePayloadSize
        var out = Data(capacity: payload.count + frameCount * 9)
        var offset = payload.startIndex
        while offset < payload.endIndex {
            let end = min(payload.endIndex, offset + maxFramePayloadSize)
            let isLast = end == payload.endIndex
            appendFrameHeader(
                typeCode: FrameType.data,
                flags: (isLast && endStream) ? 0x1 : 0,
                streamID: streamID,
                payloadLength: end - offset,
                into: &out
            )
            out.append(payload[offset..<end])
            offset = end
        }
        return out
    }

    // MARK: Control frames

    /// A SETTINGS ACK (RFC 9113 §6.5.3) for the client's SETTINGS.
    static func settingsAck() -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameType.settings, flags: 0x1, streamID: 0, payloadLength: 0, into: &d)
        return d
    }

    /// A PING ACK echoing the 8 opaque octets (RFC 9113 §6.7).
    static func pingAck(opaque: Data) -> Data {
        var d = Data()
        let body = opaque.count == 8 ? opaque : Data(count: 8)
        appendFrameHeader(typeCode: FrameType.ping, flags: 0x1, streamID: 0, payloadLength: 8, into: &d)
        d.append(body)
        return d
    }

    static func windowUpdate(streamID: UInt32, increment: Int) -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameType.windowUpdate, flags: 0, streamID: streamID, payloadLength: 4, into: &d)
        HTTP2FrameWire.appendUInt32(UInt32(truncatingIfNeeded: increment) & 0x7FFF_FFFF, into: &d)
        return d
    }

    static func rstStream(streamID: UInt32, errorCode: UInt32) -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameType.rstStream, flags: 0, streamID: streamID, payloadLength: 4, into: &d)
        HTTP2FrameWire.appendUInt32(errorCode, into: &d)
        return d
    }

    /// A GOAWAY (RFC 9113 §6.8): names the last stream the sender processed so the peer can
    /// safely retry anything above it. Empty debug data.
    static func goAway(lastStreamID: UInt32, errorCode: UInt32) -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameType.goaway, flags: 0, streamID: 0, payloadLength: 8, into: &d)
        HTTP2FrameWire.appendUInt32(lastStreamID & 0x7FFF_FFFF, into: &d)
        HTTP2FrameWire.appendUInt32(errorCode, into: &d)
        return d
    }

    /// Decodes a WINDOW_UPDATE's 31-bit increment (RFC 9113 §6.9.1); nil for a
    /// non-4-byte payload.
    static func windowUpdateIncrement(_ payload: Data) -> Int? {
        guard payload.count == 4, let value = HTTP2FrameWire.readUInt32(payload) else { return nil }
        return Int(value & 0x7FFF_FFFF)
    }

    // MARK: Padding strippers

    /// Strips PADDED + PRIORITY prefixes from a HEADERS payload; nil for invalid padding.
    static func stripHeadersPadding(payload: Data, flags: UInt8) -> Data? {
        var p = payload
        if flags & 0x8 != 0 { // PADDED
            guard let stripped = stripPadding(&p) else { return nil }
            p = stripped
        }
        if flags & 0x20 != 0 { // PRIORITY
            guard p.count >= 5 else { return nil }
            p = p.subdata(in: (p.startIndex + 5)..<p.endIndex)
        }
        return p
    }

    /// Strips PADDED from a DATA payload; nil for invalid padding.
    static func stripDataPadding(payload: Data, flags: UInt8) -> Data? {
        var p = payload
        if flags & 0x8 != 0 {
            guard let stripped = stripPadding(&p) else { return nil }
            p = stripped
        }
        return p
    }

    private static func stripPadding(_ payload: inout Data) -> Data? {
        guard !payload.isEmpty else { return nil }
        let padLen = Int(payload[payload.startIndex])
        guard payload.count >= 1 + padLen else { return nil }
        return payload.subdata(in: (payload.startIndex + 1)..<(payload.endIndex - padLen))
    }
}
