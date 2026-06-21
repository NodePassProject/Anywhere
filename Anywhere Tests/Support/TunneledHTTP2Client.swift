//
//  TunneledHTTP2Client.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
@testable import Anywhere

enum TunneledHTTP2Client {
    private static let connectionPreface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    private static let streamID: UInt32 = 1
    private static let priorityFlag: UInt8 = 0x20
    
    private static let initialWindowSize: UInt32 = 8 * 1024 * 1024
    private static let connectionWindowBump: UInt32 = 16 * 1024 * 1024
    private static let windowUpdateThreshold = 512 * 1024
    
    static func get(
        stream: ByteStream,
        authorityHost: String,
        port: UInt16,
        path: String
    ) async throws -> HTTPResponse {
        var preamble = Data()
        preamble.append(connectionPreface)
        preamble.append(NaiveHTTP2Framer.settingsFrame([
            (id: 0x2, value: 0),                    // ENABLE_PUSH off
            (id: 0x4, value: initialWindowSize),    // INITIAL_WINDOW_SIZE
            (id: 0x5, value: 16384),                // MAX_FRAME_SIZE (default)
        ]).serialized)
        preamble.append(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: connectionWindowBump).serialized)

        let authority = port == 443 ? authorityHost : "\(authorityHost):\(port)"
        let requestHeaders: [(name: String, value: String)] = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", authority),
            (":path", path),
            ("user-agent", "Anywhere"),
            ("accept", "*/*"),
        ]
        let headerBlock = HPACKEncoder.encodeHeaderBlock(requestHeaders)
        preamble.append(NaiveHTTP2Framer.headersFrame(streamID: streamID, headerBlock: headerBlock, endStream: true).serialized)

        try await stream.sendBytes(preamble)
        
        let decoder = HPACKDecoder()
        var buffer = Data()
        var responseHeaders: [(name: String, value: String)] = []
        var status: Int?
        var body = Data()
        var done = false
        var connectionConsumed = 0
        var streamConsumed = 0

        while !done {
            guard let chunk = try await stream.receiveBytes() else {
                throw HTTPClientError.connectionClosed("HTTP/2 connection closed before END_STREAM")
            }
            buffer.append(chunk)

            var pendingOut = Data()
            while let frame = NaiveHTTP2Framer.deserialize(from: &buffer) {
                switch frame.type {
                case .settings:
                    if !frame.hasFlag(NaiveHTTP2FrameFlags.ack) {
                        pendingOut.append(NaiveHTTP2Framer.settingsAckFrame().serialized)
                    }

                case .ping:
                    if !frame.hasFlag(NaiveHTTP2FrameFlags.ack) {
                        pendingOut.append(NaiveHTTP2Framer.pingAckFrame(opaqueData: frame.payload).serialized)
                    }

                case .goaway:
                    let info = NaiveHTTP2Framer.parseGoaway(payload: frame.payload)
                    throw HTTPClientError.connectionClosed("GOAWAY errorCode=\(info?.errorCode ?? 0)")

                case .rstStream:
                    if frame.streamID == streamID {
                        let code = NaiveHTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                        throw HTTPClientError.connectionClosed("RST_STREAM errorCode=\(code)")
                    }

                case .windowUpdate:
                    break

                case .headers:
                    guard frame.streamID == streamID else { break }
                    if frame.hasFlag(NaiveHTTP2FrameFlags.padded) || (frame.flags & priorityFlag) != 0 {
                        throw HTTPClientError.unsupported("padded/priority HEADERS")
                    }
                    if !frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
                        throw HTTPClientError.unsupported("CONTINUATION frames")
                    }
                    guard let decoded = decoder.decodeHeaders(from: frame.payload) else {
                        throw HTTPClientError.malformedResponse("HPACK decode failed")
                    }
                    
                    if status == nil {
                        responseHeaders = decoded.fields
                        if let raw = decoded.fields.first(where: { $0.name == ":status" })?.value {
                            status = Int(raw)
                        }
                    }
                    if frame.hasFlag(NaiveHTTP2FrameFlags.endStream) { done = true }

                case .data:
                    guard frame.streamID == streamID else { break }
                    body.append(unpaddedDataPayload(frame))
                    
                    let consumed = frame.payload.count
                    connectionConsumed += consumed
                    streamConsumed += consumed
                    if connectionConsumed >= windowUpdateThreshold {
                        pendingOut.append(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: UInt32(connectionConsumed)).serialized)
                        connectionConsumed = 0
                    }
                    if streamConsumed >= windowUpdateThreshold {
                        pendingOut.append(NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: UInt32(streamConsumed)).serialized)
                        streamConsumed = 0
                    }
                    if frame.hasFlag(NaiveHTTP2FrameFlags.endStream) { done = true }
                }
            }

            if !pendingOut.isEmpty {
                try await stream.sendBytes(pendingOut)
            }
        }

        guard let finalStatus = status else {
            throw HTTPClientError.malformedResponse("no :status pseudo-header in response")
        }
        return HTTPResponse(statusCode: finalStatus, headers: responseHeaders, body: body)
    }
    
    private static func unpaddedDataPayload(_ frame: NaiveHTTP2Frame) -> Data {
        guard frame.hasFlag(NaiveHTTP2FrameFlags.padded) else { return frame.payload }
        guard let padLength = frame.payload.first else { return Data() }
        let withoutPadByte = frame.payload.dropFirst()
        guard withoutPadByte.count >= Int(padLength) else { return Data(withoutPadByte) }
        return Data(withoutPadByte.dropLast(Int(padLength)))
    }
}
