//
//  MITMBodyCodec.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Compression
import Foundation
import zlib

nonisolated private let logger = AnywhereLogger(category: "MITMBodyCodec")

nonisolated enum MITMBodyCodec {
    static let maxBufferedBodyBytes: Int = 4 * 1024 * 1024
    static let maxCodecChainLength = 4

    enum Codec: Equatable {
        case identity
        case gzip
        case deflate
        case brotli
    }

    struct Plan: Equatable {
        let codecs: [Codec]
        let isSupported: Bool

        var requiresDecompression: Bool {
            isSupported && codecs.contains { $0 != .identity }
        }

        static let identity = Plan(codecs: [.identity], isSupported: true)
    }

    static func plan(for contentEncoding: String?) -> Plan {
        guard let raw = contentEncoding, !raw.isEmpty else { return .identity }
        let tokens = raw
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
        if tokens.isEmpty { return .identity }
        var codecs: [Codec] = []
        var isSupported = true
        for token in tokens {
            switch token {
            case "identity":
                codecs.append(.identity)
            case "gzip", "x-gzip":
                codecs.append(.gzip)
            case "deflate":
                codecs.append(.deflate)
            case "br":
                codecs.append(.brotli)
            default:
                isSupported = false
            }
        }
        if codecs.count > maxCodecChainLength {
            isSupported = false
        }
        return Plan(codecs: codecs, isSupported: isSupported)
    }

    static let decodableContentCodings: Set<String> = ["gzip", "x-gzip", "deflate", "br", "identity"]

    static func constrainedAcceptEncoding(_ value: String) -> String {
        let kept = value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { token in
                guard let coding = token.split(separator: ";").first?
                    .trimmingCharacters(in: .whitespaces).lowercased() else { return false }
                return decodableContentCodings.contains(coding)
            }
        return kept.isEmpty ? "identity" : kept.joined(separator: ", ")
    }

    static func decompress(_ data: Data, plan: Plan, host: String) -> Data? {
        guard plan.isSupported else { return nil }
        var current = data
        for codec in plan.codecs.reversed() {
            switch codec {
            case .identity:
                continue
            case .gzip:
                let (decoded, failure) = gunzip(current)
                guard let next = decoded else {
                    logger.warning("[MITM] \(host): gzip decode failed" + (failure.map { ": \($0)" } ?? ""))
                    return nil
                }
                current = next
            case .deflate:
                guard let next = inflateDeflate(current) else {
                    logger.warning("[MITM] \(host): deflate decode failed")
                    return nil
                }
                current = next
            case .brotli:
                guard let next = streamDecode(current, algorithm: COMPRESSION_BROTLI) else {
                    logger.warning("[MITM] \(host): brotli decode failed")
                    return nil
                }
                current = next
            }
        }
        return current
    }

    // MARK: - Single-codec encode/decode

    static func decode(_ data: Data, codec: Codec) -> Data? {
        switch codec {
        case .identity: return data
        case .gzip:     return gunzip(data, allowMultiMember: true).decoded
        case .deflate:  return inflateDeflate(data)
        case .brotli:   return streamDecode(data, algorithm: COMPRESSION_BROTLI)
        }
    }

    static func encode(_ data: Data, codec: Codec) -> Data? {
        switch codec {
        case .identity:
            return data
        case .gzip:
            guard let deflated = streamEncode(data, algorithm: COMPRESSION_ZLIB) else { return nil }
            return gzipWrap(deflated, original: data)
        case .deflate:
            return streamEncode(data, algorithm: COMPRESSION_ZLIB)
        case .brotli:
            return streamEncode(data, algorithm: COMPRESSION_BROTLI)
        }
    }

    // MARK: - gzip (RFC 1952)

    private enum GzipFailure: CustomStringConvertible {
        case firstMember(GzipMemberFailure)
        case capExceeded
        case multiMember
        case trailingMember(GzipMemberFailure)

        var description: String {
            switch self {
            case .firstMember(let reason): return reason.description
            case .capExceeded:             return "output too large"
            case .multiMember:             return "multi-member gzip unsupported"
            case .trailingMember(let reason): return "trailing member: \(reason)"
            }
        }
    }

    private enum GzipMemberFailure: CustomStringConvertible {
        case tooShort
        case badMagic(UInt8, UInt8, UInt8)
        case truncatedHeaderField(String)
        case deflate(status: String)

        var description: String {
            switch self {
            case .tooShort:
                return "member too short"
            case .badMagic(let byte0, let byte1, let byte2):
                return String(format: "bad magic %02x %02x %02x", byte0, byte1, byte2)
            case .truncatedHeaderField(let field):
                return "truncated \(field) field"
            case .deflate(let status):
                return "deflate \(status)"
            }
        }
    }

    private enum GzipMemberOutcome {
        case success(decoded: Data, consumed: Int)
        case failure(GzipMemberFailure)
        case capExceeded
    }

    private static func gunzip(_ data: Data, allowMultiMember: Bool = false) -> (decoded: Data?, failure: GzipFailure?) {
        var combined = Data()
        var cursor = data.startIndex
        let end = data.endIndex
        while cursor < end {
            switch gunzipOneMember(data, from: cursor, producedSoFar: combined.count) {
            case .capExceeded:
                return (nil, .capExceeded)
            case .failure(let reason):
                return combined.isEmpty ? (nil, .firstMember(reason)) : (nil, .trailingMember(reason))
            case .success(let memberBytes, let consumed):
                combined.append(memberBytes)
                cursor = data.index(cursor, offsetBy: consumed)
            }
        }
        if allowMultiMember { return (combined, nil) }
        guard gzipTrailerISIZE(data) == UInt32(truncatingIfNeeded: combined.count),
              gzipTrailerCRC32(data) == crc32(combined) else {
            return (nil, .multiMember)
        }
        return (combined, nil)
    }

    private static func gzipTrailerISIZE(_ data: Data) -> UInt32 {
        guard data.count >= 4 else { return 0 }
        let endIndex = data.endIndex
        return UInt32(data[data.index(endIndex, offsetBy: -4)])
            | (UInt32(data[data.index(endIndex, offsetBy: -3)]) << 8)
            | (UInt32(data[data.index(endIndex, offsetBy: -2)]) << 16)
            | (UInt32(data[data.index(endIndex, offsetBy: -1)]) << 24)
    }

    private static func gzipTrailerCRC32(_ data: Data) -> UInt32 {
        guard data.count >= 8 else { return 0 }
        let endIndex = data.endIndex
        return UInt32(data[data.index(endIndex, offsetBy: -8)])
            | (UInt32(data[data.index(endIndex, offsetBy: -7)]) << 8)
            | (UInt32(data[data.index(endIndex, offsetBy: -6)]) << 16)
            | (UInt32(data[data.index(endIndex, offsetBy: -5)]) << 24)
    }

    private static func gunzipOneMember(
        _ data: Data,
        from offset: Data.Index,
        producedSoFar: Int
    ) -> GzipMemberOutcome {
        let end = data.endIndex
        let available = data.distance(from: offset, to: end)
        guard available >= 18 else { return .failure(.tooShort) }
        let magicByte0 = data[offset]
        let magicByte1 = data[data.index(offset, offsetBy: 1)]
        let magicByte2 = data[data.index(offset, offsetBy: 2)]
        guard magicByte0 == 0x1F, magicByte1 == 0x8B, magicByte2 == 0x08 else {
            return .failure(.badMagic(magicByte0, magicByte1, magicByte2))
        }
        let flags = data[data.index(offset, offsetBy: 3)]
        var index = data.index(offset, offsetBy: 10)
        if flags & 0x04 != 0 {
            guard data.distance(from: index, to: end) >= 2 else { return .failure(.truncatedHeaderField("FEXTRA")) }
            let extraLength = Int(data[index]) | (Int(data[data.index(index, offsetBy: 1)]) << 8)
            guard data.distance(from: index, to: end) >= 2 + extraLength else { return .failure(.truncatedHeaderField("FEXTRA")) }
            index = data.index(index, offsetBy: 2 + extraLength)
        }
        if flags & 0x08 != 0 {
            while index < end, data[index] != 0 { index = data.index(after: index) }
            guard index < end else { return .failure(.truncatedHeaderField("FNAME")) }
            index = data.index(after: index)
        }
        if flags & 0x10 != 0 {
            while index < end, data[index] != 0 { index = data.index(after: index) }
            guard index < end else { return .failure(.truncatedHeaderField("FCOMMENT")) }
            index = data.index(after: index)
        }
        if flags & 0x02 != 0 {
            guard data.distance(from: index, to: end) >= 2 else { return .failure(.truncatedHeaderField("FHCRC")) }
            index = data.index(index, offsetBy: 2)
        }
        let deflateInput = data[index..<end]
        let decoded: Data
        let deflateConsumed: Int
        switch streamDecodeMember(deflateInput, algorithm: COMPRESSION_ZLIB, budgetUsed: producedSoFar) {
        case .success(let output, let consumed):
            decoded = output
            deflateConsumed = consumed
        case .failure(let status):
            return .failure(.deflate(status: status))
        case .capExceeded:
            return .capExceeded
        }
        let trailerStart = data.index(index, offsetBy: deflateConsumed)
        let trailerAvailable = data.distance(from: trailerStart, to: end)
        guard trailerAvailable >= 8 else {
            return .success(decoded: decoded, consumed: data.distance(from: offset, to: end))
        }
        let nextMember = data.index(trailerStart, offsetBy: 8)
        let consumed = data.distance(from: offset, to: nextMember)
        return .success(decoded: decoded, consumed: consumed)
    }

    // MARK: - deflate

    private static func inflateDeflate(_ data: Data) -> Data? {
        guard !data.isEmpty else { return nil }
        if let raw = streamDecode(data, algorithm: COMPRESSION_ZLIB) {
            return raw
        }
        guard data.count > 6 else { return nil }
        let flags = data[data.index(data.startIndex, offsetBy: 1)]
        guard flags & 0x20 == 0 else { return nil }
        let body = data.subdata(in: (data.startIndex + 2)..<(data.endIndex - 4))
        return streamDecode(body, algorithm: COMPRESSION_ZLIB)
    }

    // MARK: - Streaming decoder

    private enum StreamDecodeOutcome {
        case success(decoded: Data, consumed: Int)
        case failure(status: String)
        case capExceeded
    }

    private static func streamDecode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        if case .success(let decoded, _) = streamDecodeMember(data, algorithm: algorithm) {
            return decoded
        }
        return nil
    }

    private static func streamDecodeMember(
        _ data: Data,
        algorithm: compression_algorithm,
        budgetUsed: Int = 0
    ) -> StreamDecodeOutcome {
        guard !data.isEmpty else { return .success(decoded: Data(), consumed: 0) }
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }

        var status = compression_stream_init(stream, COMPRESSION_STREAM_DECODE, algorithm)
        guard status == COMPRESSION_STATUS_OK else {
            return .failure(status: "init-failed")
        }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> StreamDecodeOutcome in
            guard let inputBase = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return .failure(status: "no-base-address")
            }
            stream.pointee.src_ptr = inputBase
            stream.pointee.src_size = data.count
            stream.pointee.dst_ptr = buffer
            stream.pointee.dst_size = bufferSize

            var output = Data()
            let flags = Int32(COMPRESSION_STREAM_FINALIZE.rawValue)
            while true {
                let sourceBefore = stream.pointee.src_size
                status = compression_stream_process(stream, flags)
                switch status {
                case COMPRESSION_STATUS_OK, COMPRESSION_STATUS_END:
                    let written = bufferSize - stream.pointee.dst_size
                    if written > 0 {
                        if budgetUsed + output.count + written > maxBufferedBodyBytes {
                            return .capExceeded
                        }
                        output.append(buffer, count: written)
                    }
                    if status == COMPRESSION_STATUS_END {
                        let consumed = data.count - stream.pointee.src_size
                        return .success(decoded: output, consumed: consumed)
                    }
                    stream.pointee.dst_ptr = buffer
                    stream.pointee.dst_size = bufferSize
                    if written == 0 && stream.pointee.src_size == sourceBefore {
                        return .failure(status: "stalled")
                    }
                case COMPRESSION_STATUS_ERROR:
                    return .failure(status: "error")
                default:
                    return .failure(status: "unexpected")
                }
            }
        }
    }

    // MARK: - Streaming encoder

    private static func streamEncode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }

        var status = compression_stream_init(stream, COMPRESSION_STREAM_ENCODE, algorithm)
        guard status == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        func run(sourceBase: UnsafePointer<UInt8>?, sourceCount: Int) -> Data? {
            stream.pointee.src_ptr = sourceBase ?? UnsafePointer(buffer)
            stream.pointee.src_size = sourceCount
            stream.pointee.dst_ptr = buffer
            stream.pointee.dst_size = bufferSize

            var output = Data()
            let flags = Int32(COMPRESSION_STREAM_FINALIZE.rawValue)
            while true {
                status = compression_stream_process(stream, flags)
                switch status {
                case COMPRESSION_STATUS_OK, COMPRESSION_STATUS_END:
                    let written = bufferSize - stream.pointee.dst_size
                    if written > 0 {
                        if output.count + written > maxBufferedBodyBytes {
                            return nil
                        }
                        output.append(buffer, count: written)
                    }
                    if status == COMPRESSION_STATUS_END {
                        return output
                    }
                    if stream.pointee.dst_size == 0 {
                        stream.pointee.dst_ptr = buffer
                        stream.pointee.dst_size = bufferSize
                    }
                case COMPRESSION_STATUS_ERROR:
                    return nil
                default:
                    return nil
                }
            }
        }

        if data.isEmpty {
            return run(sourceBase: nil, sourceCount: 0)
        }
        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Data? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return run(sourceBase: base, sourceCount: data.count)
        }
    }

    // MARK: - gzip framing

    private static func gzipWrap(_ deflated: Data, original: Data) -> Data {
        var out = Data(capacity: 10 + deflated.count + 8)
        out.append(contentsOf: [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF])
        out.append(deflated)
        let crc = crc32(original)
        let isize = UInt32(truncatingIfNeeded: original.count)
        out.append(
            contentsOf: [
                UInt8(crc & 0xFF), UInt8((crc >> 8) & 0xFF),
                UInt8((crc >> 16) & 0xFF), UInt8((crc >> 24) & 0xFF),
                UInt8(isize & 0xFF), UInt8((isize >> 8) & 0xFF),
                UInt8((isize >> 16) & 0xFF), UInt8((isize >> 24) & 0xFF),
            ]
        )
        return out
    }

    private static func crc32(_ data: Data) -> UInt32 {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: Bytef.self) else { return 0 }
            return UInt32(truncatingIfNeeded: crc32_z(0, base, raw.count))
        }
    }
}
