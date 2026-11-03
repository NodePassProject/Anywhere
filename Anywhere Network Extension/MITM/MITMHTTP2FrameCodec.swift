//
//  MITMHTTP2FrameCodec.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

nonisolated enum MITMHTTP2FrameCodec {

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

    // MARK: Error codes

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

    static let maxFramePayloadSize = 16_384
    static let maxReceivedFramePayloadSize = 1 * 1024 * 1024
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
        case error
    }

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

    static func parseFrame(from buffer: inout MITMByteBuffer, then input: inout Data) -> ParseResult {
        if !buffer.isEmpty {
            if buffer.count < 9 {
                moveBytes(9 - buffer.count, from: &input, to: &buffer)
                guard buffer.count >= 9 else { return .needMore }
            }
            let length = (Int(buffer[0]) << 16) | (Int(buffer[1]) << 8) | Int(buffer[2])
            if length <= maxReceivedFramePayloadSize, buffer.count < 9 + length {
                moveBytes(9 + length - buffer.count, from: &input, to: &buffer)
            }
            return parseFrame(from: &buffer)
        }
        guard input.count >= 9 else { return .needMore }
        let base = input.startIndex
        let length = (Int(input[base]) << 16) | (Int(input[base + 1]) << 8) | Int(input[base + 2])
        if length > maxReceivedFramePayloadSize {
            input = Data()
            return .error
        }
        let total = 9 + length
        guard input.count >= total else { return .needMore }
        let type = input[base + 3]
        let flags = input[base + 4]
        let streamID = (UInt32(input[base + 5]) << 24
                      | UInt32(input[base + 6]) << 16
                      | UInt32(input[base + 7]) << 8
                      | UInt32(input[base + 8])) & 0x7FFFFFFF
        let payload = input.subdata(in: (base + 9)..<(base + total))
        input = input.count == total ? Data() : input[(base + total)...]
        return .frame(RawFrame(typeCode: type, flags: flags, streamID: streamID, payload: payload))
    }

    private static func moveBytes(_ count: Int, from input: inout Data, to buffer: inout MITMByteBuffer) {
        let take = min(count, input.count)
        guard take > 0 else { return }
        let split = input.startIndex + take
        buffer.append(input[..<split])
        input = take == input.count ? Data() : input[split...]
    }

    // MARK: Header writing

    static func appendFrameHeader(
        typeCode: UInt8,
        flags: UInt8,
        streamID: UInt32,
        payloadLength: Int,
        into out: inout Data
    ) {
        HTTP2FrameWire.appendHeader(
            type: typeCode,
            flags: flags,
            streamID: streamID,
            payloadLength: payloadLength,
            into: &out
        )
    }

    // MARK: HEADERS / DATA emit

    static func emitHeaders(streamID: UInt32, block: Data, endStream: Bool) -> Data {
        let firstChunkSize = min(block.count, maxFramePayloadSize)
        let firstChunkEnd = block.startIndex + firstChunkSize
        let needsContinuation = firstChunkEnd < block.endIndex

        var firstFlags: UInt8 = 0
        if !needsContinuation { firstFlags |= 0x4 }
        if endStream { firstFlags |= 0x1 }

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

    static func dataFrames(streamID: UInt32, payload parts: [Data], endStream: Bool) -> [Data] {
        var remaining = parts.reduce(0) { $0 + $1.count }
        var frames: [Data] = []
        var partIndex = 0
        var offset = parts.first?.startIndex ?? 0
        repeat {
            let length = min(remaining, maxFramePayloadSize)
            remaining -= length
            var header = Data(capacity: 9)
            appendFrameHeader(
                typeCode: FrameType.data,
                flags: (remaining == 0 && endStream) ? 0x1 : 0,
                streamID: streamID,
                payloadLength: length,
                into: &header
            )
            frames.append(header)
            var needed = length
            while needed > 0 {
                if offset >= parts[partIndex].endIndex {
                    partIndex += 1
                    offset = parts[partIndex].startIndex
                    continue
                }
                let take = min(needed, parts[partIndex].endIndex - offset)
                frames.append(parts[partIndex][offset..<(offset + take)])
                offset += take
                needed -= take
            }
        } while remaining > 0
        return frames
    }

    // MARK: Control frames

    static func settingsAck() -> Data {
        var frame = Data()
        appendFrameHeader(typeCode: FrameType.settings, flags: 0x1, streamID: 0, payloadLength: 0, into: &frame)
        return frame
    }

    static func pingAck(opaque: Data) -> Data {
        var frame = Data()
        let body = opaque.count == 8 ? opaque : Data(count: 8)
        appendFrameHeader(typeCode: FrameType.ping, flags: 0x1, streamID: 0, payloadLength: 8, into: &frame)
        frame.append(body)
        return frame
    }

    static func windowUpdate(streamID: UInt32, increment: Int) -> Data {
        var frame = Data()
        appendFrameHeader(typeCode: FrameType.windowUpdate, flags: 0, streamID: streamID, payloadLength: 4, into: &frame)
        HTTP2FrameWire.appendUInt32(UInt32(truncatingIfNeeded: increment) & 0x7FFF_FFFF, into: &frame)
        return frame
    }

    static func rstStream(streamID: UInt32, errorCode: UInt32) -> Data {
        var frame = Data()
        appendFrameHeader(typeCode: FrameType.rstStream, flags: 0, streamID: streamID, payloadLength: 4, into: &frame)
        HTTP2FrameWire.appendUInt32(errorCode, into: &frame)
        return frame
    }

    static func goAway(lastStreamID: UInt32, errorCode: UInt32) -> Data {
        var frame = Data()
        appendFrameHeader(typeCode: FrameType.goaway, flags: 0, streamID: 0, payloadLength: 8, into: &frame)
        HTTP2FrameWire.appendUInt32(lastStreamID & 0x7FFF_FFFF, into: &frame)
        HTTP2FrameWire.appendUInt32(errorCode, into: &frame)
        return frame
    }

    static func windowUpdateIncrement(_ payload: Data) -> Int? {
        guard payload.count == 4, let value = HTTP2FrameWire.readUInt32(payload) else { return nil }
        return Int(value & 0x7FFF_FFFF)
    }

    // MARK: Padding strippers

    static func stripHeadersPadding(payload: Data, flags: UInt8) -> Data? {
        var remaining = payload
        if flags & 0x8 != 0 { // PADDED
            guard let stripped = stripPadding(&remaining) else { return nil }
            remaining = stripped
        }
        if flags & 0x20 != 0 { // PRIORITY
            guard remaining.count >= 5 else { return nil }
            remaining = remaining.subdata(in: (remaining.startIndex + 5)..<remaining.endIndex)
        }
        return remaining
    }

    static func stripDataPadding(payload: Data, flags: UInt8) -> Data? {
        var remaining = payload
        if flags & 0x8 != 0 {
            guard let stripped = stripPadding(&remaining) else { return nil }
            remaining = stripped
        }
        return remaining
    }

    private static func stripPadding(_ payload: inout Data) -> Data? {
        guard !payload.isEmpty else { return nil }
        let padLength = Int(payload[payload.startIndex])
        guard payload.count >= 1 + padLength else { return nil }
        return payload.subdata(in: (payload.startIndex + 1)..<(payload.endIndex - padLength))
    }
}
