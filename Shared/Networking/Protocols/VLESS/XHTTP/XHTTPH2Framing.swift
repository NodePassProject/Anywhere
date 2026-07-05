//
//  XHTTPH2Framing.swift
//  Anywhere
//
//  Created by NodePassProject on 6/14/26.
//

import Foundation
import Synchronization

// MARK: - HTTP/2 Frame Codec (RFC 7540 §4)
//
// One copy of the byte layout shared by the 1:1 and shared-multiplexing H2 paths so they can't drift.

enum H2Framing {
    typealias Frame = (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)

    static let headerSize = 9

    /// Serializes a frame: 24-bit length, 8-bit type, 8-bit flags, 31-bit stream id, payload.
    static func frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        var frameData = Data(capacity: headerSize + payload.count)
        let length = UInt32(payload.count)
        frameData.append(UInt8((length >> 16) & 0xFF))
        frameData.append(UInt8((length >> 8) & 0xFF))
        frameData.append(UInt8(length & 0xFF))
        frameData.append(type)
        frameData.append(flags)
        let sid = streamId & 0x7FFFFFFF
        frameData.append(UInt8((sid >> 24) & 0xFF))
        frameData.append(UInt8((sid >> 16) & 0xFF))
        frameData.append(UInt8((sid >> 8) & 0xFF))
        frameData.append(UInt8(sid & 0xFF))
        frameData.append(payload)
        return frameData
    }

    /// Consumes one complete frame from the front of `buffer`; nil until a full frame is buffered.
    static func parseFrame(from buffer: inout Data) -> Frame? {
        guard buffer.count >= headerSize else { return nil }
        let bytes = buffer
        let length = (UInt32(bytes[bytes.startIndex]) << 16) | (UInt32(bytes[bytes.startIndex + 1]) << 8) | UInt32(bytes[bytes.startIndex + 2])
        let type = bytes[bytes.startIndex + 3]
        let flags = bytes[bytes.startIndex + 4]
        let sid = ((UInt32(bytes[bytes.startIndex + 5]) << 24) | (UInt32(bytes[bytes.startIndex + 6]) << 16)
                   | (UInt32(bytes[bytes.startIndex + 7]) << 8) | UInt32(bytes[bytes.startIndex + 8])) & 0x7FFFFFFF
        let total = headerSize + Int(length)
        guard buffer.count >= total else { return nil }
        let payload = buffer.subdata(in: buffer.startIndex + headerSize ..< buffer.startIndex + total)
        buffer.removeFirst(total)
        // Re-pack so a sliced Data doesn't pin the whole original backing store.
        buffer = buffer.isEmpty ? Data() : Data(buffer)
        return (type, flags, sid, payload)
    }

    /// Big-endian UInt32 from the first 4 bytes of `d`.
    static func readUInt32(_ data: Data) -> UInt32 {
        (UInt32(data[data.startIndex]) << 24) | (UInt32(data[data.startIndex + 1]) << 16)
        | (UInt32(data[data.startIndex + 2]) << 8) | UInt32(data[data.startIndex + 3])
    }

    /// Big-endian 4-byte encoding of `v`.
    static func uint32Data(_ value: UInt32) -> Data {
        var d = Data(count: 4)
        d[0] = UInt8((value >> 24) & 0xFF); d[1] = UInt8((value >> 16) & 0xFF)
        d[2] = UInt8((value >> 8) & 0xFF); d[3] = UInt8(value & 0xFF)
        return d
    }
}

/// Read buffer is independent of connection state and guarded by its own mutex, so both the
/// 1:1 and shared-multiplexing H2 paths can drive one.
nonisolated final class H2FrameReader {
    private let receive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let maxBufferSize: Int

    private struct ReadState {
        var buffer = Data()
        /// Consecutive synchronous parses; trampolined every 16th to bound recursion depth.
        var depth = 0
    }

    private let state = Mutex(ReadState())

    init(maxBufferSize: Int, receive: @escaping (@escaping (Data?, Bool, Error?) -> Void) -> Void) {
        self.maxBufferSize = maxBufferSize
        self.receive = receive
    }

    /// Yields the next complete frame, reading from the transport as needed.
    func readFrame(completion: @escaping (Result<H2Framing.Frame, Error>) -> Void) {
        enum Step {
            case parsed(H2Framing.Frame, trampoline: Bool)
            case needMore
        }
        let step: Step = state.withLock { state in
            if let frame = H2Framing.parseFrame(from: &state.buffer) {
                state.depth += 1
                let trampoline = state.depth >= 16
                if trampoline { state.depth = 0 }
                return .parsed(frame, trampoline: trampoline)
            }
            state.depth = 0
            return .needMore
        }

        switch step {
        case .parsed(let frame, let trampoline):
            if trampoline {
                DispatchQueue.global().async { completion(.success(frame)) }
            } else {
                completion(.success(frame))
            }
        case .needMore:
            receive { [weak self] data, _, error in
                guard let self else {
                    completion(.failure(XHTTPError.connectionClosed))
                    return
                }
                if let error {
                    completion(.failure(error))
                    return
                }
                guard let data, !data.isEmpty else {
                    // Clean transport FIN at a frame boundary is graceful end of stream, not a
                    // failure — consumers convert this to EOF.
                    completion(.failure(XHTTPError.streamEnded))
                    return
                }
                let overflowed = self.state.withLock { state -> Bool in
                    state.buffer.append(data)
                    if state.buffer.count > self.maxBufferSize {
                        state.buffer.removeAll()
                        return true
                    }
                    return false
                }
                if overflowed {
                    completion(.failure(XHTTPError.connectionClosed))
                    return
                }
                self.readFrame(completion: completion)
            }
        }
    }

    func reset() {
        state.withLock {
            $0.buffer = Data()
            $0.depth = 0
        }
    }
}
