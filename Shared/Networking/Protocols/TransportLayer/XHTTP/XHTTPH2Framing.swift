//
//  XHTTPH2Framing.swift
//  Anywhere
//
//  Created by NodePassProject on 6/14/26.
//

import Foundation

// MARK: - HTTP/2 Frame Codec (RFC 7540 §4)
//
// Low-level frame I/O shared by the 1:1 H2 path (XHTTPConnection+H2*.swift) and the xmux
// shared-multiplexing path (XHTTPSharedH2Connection). One copy of the byte layout means the
// two paths can't drift.

enum H2Framing {
    /// Decoded frame header + payload (RFC 7540 §4.1).
    typealias Frame = (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)

    /// Fixed frame-header length.
    static let headerSize = 9

    /// Serializes a frame: 24-bit length, 8-bit type, 8-bit flags, 31-bit stream id, payload.
    static func frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        var f = Data(capacity: headerSize + payload.count)
        let len = UInt32(payload.count)
        f.append(UInt8((len >> 16) & 0xFF))
        f.append(UInt8((len >> 8) & 0xFF))
        f.append(UInt8(len & 0xFF))
        f.append(type)
        f.append(flags)
        let sid = streamId & 0x7FFFFFFF
        f.append(UInt8((sid >> 24) & 0xFF))
        f.append(UInt8((sid >> 16) & 0xFF))
        f.append(UInt8((sid >> 8) & 0xFF))
        f.append(UInt8(sid & 0xFF))
        f.append(payload)
        return f
    }

    /// Parses one complete frame from the front of `buffer`, consuming it; nil until a full
    /// frame is buffered.
    static func parseFrame(from buffer: inout Data) -> Frame? {
        guard buffer.count >= headerSize else { return nil }
        let b = buffer
        let length = (UInt32(b[b.startIndex]) << 16) | (UInt32(b[b.startIndex + 1]) << 8) | UInt32(b[b.startIndex + 2])
        let type = b[b.startIndex + 3]
        let flags = b[b.startIndex + 4]
        let sid = ((UInt32(b[b.startIndex + 5]) << 24) | (UInt32(b[b.startIndex + 6]) << 16)
                   | (UInt32(b[b.startIndex + 7]) << 8) | UInt32(b[b.startIndex + 8])) & 0x7FFFFFFF
        let total = headerSize + Int(length)
        guard buffer.count >= total else { return nil }
        let payload = buffer.subdata(in: buffer.startIndex + headerSize ..< buffer.startIndex + total)
        buffer.removeFirst(total)
        // Re-pack so a sliced Data doesn't pin the whole original backing store.
        buffer = buffer.isEmpty ? Data() : Data(buffer)
        return (type, flags, sid, payload)
    }

    /// Big-endian UInt32 from the first 4 bytes of `d`.
    static func readUInt32(_ d: Data) -> UInt32 {
        (UInt32(d[d.startIndex]) << 24) | (UInt32(d[d.startIndex + 1]) << 16)
        | (UInt32(d[d.startIndex + 2]) << 8) | UInt32(d[d.startIndex + 3])
    }

    /// Big-endian 4-byte encoding of `v`.
    static func uint32Data(_ v: UInt32) -> Data {
        var d = Data(count: 4)
        d[0] = UInt8((v >> 24) & 0xFF); d[1] = UInt8((v >> 16) & 0xFF)
        d[2] = UInt8((v >> 8) & 0xFF); d[3] = UInt8(v & 0xFF)
        return d
    }
}

/// Demultiplexes a byte transport into HTTP/2 frames, yielding one complete frame per
/// `readFrame` call. Its read buffer is independent of any connection state and guarded by
/// its own lock, so both the 1:1 and shared-multiplexing H2 paths drive one.
nonisolated final class H2FrameReader {
    private let receive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let maxBufferSize: Int
    private let lock = UnfairLock()
    private var buffer = Data()
    /// Consecutive synchronous parses; trampolined every 16th to bound recursion depth.
    private var depth = 0

    init(maxBufferSize: Int, receive: @escaping (@escaping (Data?, Bool, Error?) -> Void) -> Void) {
        self.maxBufferSize = maxBufferSize
        self.receive = receive
    }

    /// Yields the next complete frame, reading from the transport as needed. A backlog of
    /// already-buffered frames trampolines every 16th call so it can't overflow the stack.
    func readFrame(completion: @escaping (Result<H2Framing.Frame, Error>) -> Void) {
        lock.lock()
        if let frame = H2Framing.parseFrame(from: &buffer) {
            depth += 1
            let trampoline = depth >= 16
            if trampoline { depth = 0 }
            lock.unlock()
            if trampoline {
                DispatchQueue.global().async { completion(.success(frame)) }
            } else {
                completion(.success(frame))
            }
            return
        }
        depth = 0
        lock.unlock()

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
                completion(.failure(XHTTPError.connectionClosed))
                return
            }
            self.lock.lock()
            self.buffer.append(data)
            if self.buffer.count > self.maxBufferSize {
                self.buffer.removeAll()
                self.lock.unlock()
                completion(.failure(XHTTPError.connectionClosed))
                return
            }
            self.lock.unlock()
            self.readFrame(completion: completion)
        }
    }

    /// Discards buffered bytes (teardown).
    func reset() {
        lock.lock()
        buffer = Data()
        depth = 0
        lock.unlock()
    }
}
