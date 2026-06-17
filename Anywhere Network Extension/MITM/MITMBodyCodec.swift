//
//  MITMBodyCodec.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Compression
import Foundation

private let logger = AnywhereLogger(category: "MITMBodyCodec")

/// `Content-Encoding` decoders so body rules operate on plaintext. Decode-only:
/// after rewriting we emit identity, always implicitly accepted (RFC 7231 §5.3.4).
enum MITMBodyCodec {

    static let maxBufferedBodyBytes: Int = 4 * 1024 * 1024

    /// Max stacked `Content-Encoding` codings; a long crafted `gzip, gzip, …`
    /// chain is a CPU-amplification DoS. Longer chains are treated as unsupported.
    static let maxCodecChainLength = 4

    enum Codec: Equatable {
        case identity
        case gzip
        case deflate
        case brotli
    }

    /// Parsed `Content-Encoding` header value with a flag for full decodability.
    struct Plan: Equatable {
        let codecs: [Codec]
        let supported: Bool

        var requiresDecompression: Bool {
            supported && codecs.contains { $0 != .identity }
        }

        static let identity = Plan(codecs: [.identity], supported: true)
    }

    /// Decoding plan for a `Content-Encoding` header value; nil/empty maps to identity.
    static func plan(for contentEncoding: String?) -> Plan {
        guard let raw = contentEncoding, !raw.isEmpty else { return .identity }
        let tokens = raw
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
        if tokens.isEmpty { return .identity }
        var codecs: [Codec] = []
        var supported = true
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
                supported = false
            }
        }
        if codecs.count > maxCodecChainLength {
            supported = false
        }
        return Plan(codecs: codecs, supported: supported)
    }

    /// Content-codings we can decode for a buffered transform — the set a request's
    /// `Accept-Encoding` is clamped to so an origin never selects an encoding we can't reverse.
    static let decodableContentCodings: Set<String> = ["gzip", "x-gzip", "deflate", "br", "identity"]

    /// Clamps an `Accept-Encoding` value to ``decodableContentCodings`` (mitmproxy's
    /// `constrain_encoding`): drops any coding — notably `zstd` and `*` — we couldn't decode, so a
    /// buffered body rule is never silently defeated by an undecodable `Content-Encoding`. An empty
    /// result falls back to `identity`. Per-coding `;q=` weights are preserved on kept codings.
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

    /// Decompresses in reverse-of-apply order; nil if any codec fails or the plan is unsupported.
    static func decompress(_ data: Data, plan: Plan, host: String) -> Data? {
        guard plan.supported else { return nil }
        var current = data
        for codec in plan.codecs.reversed() {
            switch codec {
            case .identity:
                continue
            case .gzip:
                let (decoded, failure) = gunzip(current)
                guard let next = decoded else {
                    logger.warning("\(host): gzip decode failed — \(failure?.description ?? "unknown") (input \(current.count) B, head=[\(Self.headFingerprint(current))])")
                    return nil
                }
                current = next
            case .deflate:
                guard let next = inflateDeflate(current) else {
                    logger.warning("\(host): deflate decode failed (input \(current.count) B, head=[\(Self.headFingerprint(current))])")
                    return nil
                }
                current = next
            case .brotli:
                guard let next = streamDecode(current, algorithm: COMPRESSION_BROTLI) else {
                    logger.warning("\(host): brotli decode failed (input \(current.count) B, head=[\(Self.headFingerprint(current))])")
                    return nil
                }
                current = next
            }
        }
        return current
    }

    /// Leading bytes as hex for failure logs; capped at 4 bytes so a mislabeled
    /// identity body can't spill plaintext.
    private static func headFingerprint(_ data: Data, maxBytes: Int = 4) -> String {
        data.prefix(maxBytes).map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    // MARK: - Single-codec encode/decode (JS `Anywhere.codec` bridge)

    /// Single-codec decode for the JS `Anywhere.codec` bridge; output capped at `maxBufferedBodyBytes`.
    static func decode(_ data: Data, codec: Codec) -> Data? {
        switch codec {
        case .identity: return data
        case .gzip:     return gunzip(data, allowMultiMember: true).decoded
        case .deflate:  return inflateDeflate(data)
        case .brotli:   return streamDecode(data, algorithm: COMPRESSION_BROTLI)
        }
    }

    /// Single-codec encode for the JS `Anywhere.codec` bridge. gzip emits a single
    /// member; deflate emits raw DEFLATE — what servers actually send despite RFC 1950.
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
        /// Decompression-bomb guard tripped, not a malformed stream.
        case capExceeded
        /// Trailer mismatch — effectively always a concatenated multi-member body.
        case multiMember

        var description: String {
            switch self {
            case .firstMember(let reason): return reason.description
            case .capExceeded:             return "output exceeded \(maxBufferedBodyBytes) B cap"
            case .multiMember:             return "multi-member gzip unsupported; forwarding verbatim"
            }
        }
    }

    private enum GzipMemberFailure: CustomStringConvertible {
        case tooShort(available: Int)
        case badMagic(UInt8, UInt8, UInt8)
        case truncatedHeaderField(String)
        case deflate(status: String, consumed: Int, of: Int, produced: Int)

        var description: String {
            switch self {
            case .tooShort(let n):
                return "gzip member too short (\(n) B, need ≥18)"
            case .badMagic(let a, let b, let c):
                return String(format: "not gzip — magic %02x %02x %02x (want 1f 8b 08)", a, b, c)
            case .truncatedHeaderField(let field):
                return "truncated \(field) header field"
            case .deflate(let status, let consumed, let total, let produced):
                return "deflate \(status) after \(consumed)/\(total) B in, \(produced) B out"
            }
        }
    }

    /// `capExceeded` stays distinct from `failure` so gunzip aborts the whole
    /// body (bomb guard) instead of treating it as a recoverable trailing-member failure.
    private enum GzipMemberOutcome {
        /// `consumed` is the member's total wire span.
        case success(decoded: Data, consumed: Int)
        case failure(GzipMemberFailure)
        case capExceeded
    }

    /// Decodes a gzip body per RFC 1952. The Compression framework's raw-deflate
    /// decoder swallows the whole input while emitting just member 1, so the loop
    /// never advances past it; the trailer check catches the multi-member case.
    /// When `allowMultiMember` is true (the single-codec JS `Anywhere.codec.gzip` bridge) every
    /// concatenated member is returned. The default fails closed on a multi-member trailer mismatch
    /// so the buffered transform forwards such a body verbatim rather than risk corrupting it.
    private static func gunzip(_ data: Data, allowMultiMember: Bool = false) -> (decoded: Data?, failure: GzipFailure?) {
        var combined = Data()
        var cursor = data.startIndex
        let end = data.endIndex
        while cursor < end {
            // Budget each member against the running total so peak memory stays near the cap.
            switch gunzipOneMember(data, from: cursor, producedSoFar: combined.count) {
            case .capExceeded:
                logger.warning("gzip multi-member output would exceed cap \(maxBufferedBodyBytes) B; aborting")
                return (nil, .capExceeded)
            case .failure(let reason):
                // First-member failure is fatal; trailing junk after a decoded prefix is recoverable.
                return combined.isEmpty ? (nil, .firstMember(reason)) : (combined, nil)
            case .success(let memberBytes, let consumed):
                combined.append(memberBytes)
                cursor = data.index(cursor, offsetBy: consumed)
            }
        }
        // The single-codec bridge wants every member's plaintext; only the buffered transform
        // fails closed on a multi-member body (forwarding it verbatim instead of rewriting).
        if allowMultiMember { return (combined, nil) }
        // Multi-member detection via the whole-body trailer pair (RFC 1952 §2.3.1):
        // a member-1-only decode of a multi-member body fails the ISIZE/CRC-32 check.
        // On mismatch fail closed — forward verbatim so the client decodes all members.
        guard gzipTrailerISIZE(data) == UInt32(truncatingIfNeeded: combined.count),
              gzipTrailerCRC32(data) == crc32(combined) else {
            return (nil, .multiMember)
        }
        return (combined, nil)
    }

    /// Little-endian ISIZE (RFC 1952 §2.3.1) from the last 4 bytes; 0 for a
    /// too-short body, which then mismatches and fails closed.
    private static func gzipTrailerISIZE(_ data: Data) -> UInt32 {
        guard data.count >= 4 else { return 0 }
        let e = data.endIndex
        return UInt32(data[data.index(e, offsetBy: -4)])
            | (UInt32(data[data.index(e, offsetBy: -3)]) << 8)
            | (UInt32(data[data.index(e, offsetBy: -2)]) << 16)
            | (UInt32(data[data.index(e, offsetBy: -1)]) << 24)
    }

    /// Little-endian CRC-32 (RFC 1952 §2.3.1): the 4 bytes preceding ISIZE;
    /// 0 for a too-short body, which then mismatches and fails closed.
    private static func gzipTrailerCRC32(_ data: Data) -> UInt32 {
        guard data.count >= 8 else { return 0 }
        let e = data.endIndex
        return UInt32(data[data.index(e, offsetBy: -8)])
            | (UInt32(data[data.index(e, offsetBy: -7)]) << 8)
            | (UInt32(data[data.index(e, offsetBy: -6)]) << 16)
            | (UInt32(data[data.index(e, offsetBy: -5)]) << 24)
    }

    private static func gunzipOneMember(
        _ data: Data,
        from offset: Data.Index,
        producedSoFar: Int
    ) -> GzipMemberOutcome {
        let end = data.endIndex
        // Minimum: 10-byte fixed header + 8-byte trailer.
        let available = data.distance(from: offset, to: end)
        guard available >= 18 else { return .failure(.tooShort(available: available)) }
        let b0 = data[offset]
        let b1 = data[data.index(offset, offsetBy: 1)]
        let b2 = data[data.index(offset, offsetBy: 2)]
        guard b0 == 0x1F, b1 == 0x8B, b2 == 0x08 else {
            return .failure(.badMagic(b0, b1, b2))
        }
        let flags = data[data.index(offset, offsetBy: 3)]
        var idx = data.index(offset, offsetBy: 10)
        if flags & 0x04 != 0 { // FEXTRA
            guard data.distance(from: idx, to: end) >= 2 else { return .failure(.truncatedHeaderField("FEXTRA")) }
            let xlen = Int(data[idx]) | (Int(data[data.index(idx, offsetBy: 1)]) << 8)
            // Distance-check first: index(_:offsetBy:) past end can trap.
            guard data.distance(from: idx, to: end) >= 2 + xlen else { return .failure(.truncatedHeaderField("FEXTRA")) }
            idx = data.index(idx, offsetBy: 2 + xlen)
        }
        if flags & 0x08 != 0 { // FNAME (NUL-terminated)
            while idx < end, data[idx] != 0 { idx = data.index(after: idx) }
            guard idx < end else { return .failure(.truncatedHeaderField("FNAME")) }
            idx = data.index(after: idx)
        }
        if flags & 0x10 != 0 { // FCOMMENT (NUL-terminated)
            while idx < end, data[idx] != 0 { idx = data.index(after: idx) }
            guard idx < end else { return .failure(.truncatedHeaderField("FCOMMENT")) }
            idx = data.index(after: idx)
        }
        if flags & 0x02 != 0 { // FHCRC
            guard data.distance(from: idx, to: end) >= 2 else { return .failure(.truncatedHeaderField("FHCRC")) }
            idx = data.index(idx, offsetBy: 2)
        }
        let deflateInput = data.subdata(in: idx..<end)
        let decoded: Data
        let deflateConsumed: Int
        switch streamDecodeMember(deflateInput, algorithm: COMPRESSION_ZLIB, budgetUsed: producedSoFar) {
        case .success(let d, let c):
            decoded = d
            deflateConsumed = c
        case .failure(let status, let consumedInput, let producedOutput):
            return .failure(.deflate(status: status, consumed: consumedInput, of: deflateInput.count, produced: producedOutput))
        case .capExceeded:
            return .capExceeded
        }
        let trailerStart = data.index(idx, offsetBy: deflateConsumed)
        let trailerAvailable = data.distance(from: trailerStart, to: end)
        // <8 trailer bytes: trailer truncated or swallowed by the raw-deflate
        // decoder (its consumed count can run into it). The payload is whole — accept.
        guard trailerAvailable >= 8 else {
            return .success(decoded: decoded, consumed: data.distance(from: offset, to: end))
        }
        let nextMember = data.index(trailerStart, offsetBy: 8)
        let consumed = data.distance(from: offset, to: nextMember)
        return .success(decoded: decoded, consumed: consumed)
    }

    // MARK: - deflate (RFC 7230 §4.2.2)

    /// Tries raw deflate first (what most servers actually send despite RFC 1950),
    /// then falls back to zlib-wrapped.
    private static func inflateDeflate(_ data: Data) -> Data? {
        // Empty input fails closed rather than silently blanking the body.
        guard !data.isEmpty else { return nil }
        if let raw = streamDecode(data, algorithm: COMPRESSION_ZLIB) {
            return raw
        }
        // zlib-wrapped fallback: strip 2-byte header + 4-byte adler32 footer.
        // Require >6 bytes or the strip yields an empty slice "successfully" decoded blank.
        guard data.count > 6 else { return nil }
        // FDICT (FLG bit 5, RFC 1950 §2.2): a 4-byte DICTID follows the 2-byte header, so the
        // simple 2-byte strip would be wrong — and the Compression framework can't supply a preset
        // dictionary anyway. Fail closed (forward verbatim) rather than mis-strip into garbage.
        let flg = data[data.index(data.startIndex, offsetBy: 1)]
        guard flg & 0x20 == 0 else { return nil }
        let body = data.subdata(in: (data.startIndex + 2)..<(data.endIndex - 4))
        return streamDecode(body, algorithm: COMPRESSION_ZLIB)
    }

    // MARK: - Streaming decoder

    /// Failure carries decoder progress (truncated vs corrupt stream);
    /// `capExceeded` is the bomb guard, distinct from a genuine error.
    private enum StreamDecodeOutcome {
        case success(decoded: Data, consumed: Int)
        case failure(status: String, consumedInput: Int, producedOutput: Int)
        case capExceeded(producedOutput: Int)
    }

    /// Streaming decode; nil on error or when output would exceed `maxBufferedBodyBytes`.
    private static func streamDecode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        if case .success(let decoded, _) = streamDecodeMember(data, algorithm: algorithm) {
            return decoded
        }
        return nil
    }

    /// Like `streamDecode` but reports consumed-input count and failure progress.
    /// Does not log — failure may be expected (`inflateDeflate` probes raw deflate first).
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
            return .failure(status: "init-failed", consumedInput: 0, producedOutput: 0)
        }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> StreamDecodeOutcome in
            guard let inputBase = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return .failure(status: "no-base-address", consumedInput: 0, producedOutput: 0)
            }
            stream.pointee.src_ptr = inputBase
            stream.pointee.src_size = data.count
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
                        // budgetUsed bounds *cumulative* multi-member output.
                        if budgetUsed + output.count + written > maxBufferedBodyBytes {
                            logger.warning("decompress output would exceed cap \(maxBufferedBodyBytes) B; aborting")
                            return .capExceeded(producedOutput: output.count)
                        }
                        output.append(buffer, count: written)
                    }
                    if status == COMPRESSION_STATUS_END {
                        let consumed = data.count - stream.pointee.src_size
                        return .success(decoded: output, consumed: consumed)
                    }
                    if stream.pointee.dst_size == 0 {
                        stream.pointee.dst_ptr = buffer
                        stream.pointee.dst_size = bufferSize
                    }
                case COMPRESSION_STATUS_ERROR:
                    return .failure(status: "error", consumedInput: data.count - stream.pointee.src_size, producedOutput: output.count)
                default:
                    return .failure(status: "unexpected", consumedInput: data.count - stream.pointee.src_size, producedOutput: output.count)
                }
            }
        }
    }

    // MARK: - Streaming encoder (JS codec bridge)

    /// Streaming encode; nil on error or when output would exceed `maxBufferedBodyBytes`.
    /// The cap mirrors the decode path so a script can't inflate extension memory by
    /// (re)compressing an input larger than the typed-array budget would otherwise allow.
    private static func streamEncode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }

        var status = compression_stream_init(stream, COMPRESSION_STREAM_ENCODE, algorithm)
        guard status == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        // Factored out so empty input (nil base address from withUnsafeBytes)
        // still produces a valid empty stream instead of nil.
        func run(srcBase: UnsafePointer<UInt8>?, srcCount: Int) -> Data? {
            // src_size 0 means src_ptr is never read; buffer is a safe placeholder.
            stream.pointee.src_ptr = srcBase ?? UnsafePointer(buffer)
            stream.pointee.src_size = srcCount
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
                            logger.warning("encode output would exceed cap \(maxBufferedBodyBytes) B; aborting")
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
            return run(srcBase: nil, srcCount: 0)
        }
        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Data? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return run(srcBase: base, srcCount: data.count)
        }
    }

    // MARK: - gzip framing (RFC 1952)

    /// Wraps raw DEFLATE in a single gzip member: 10-byte fixed header, body,
    /// 8-byte trailer (CRC32 of the uncompressed input + ISIZE, little-endian).
    private static func gzipWrap(_ deflated: Data, original: Data) -> Data {
        var out = Data(capacity: 10 + deflated.count + 8)
        // ID1 ID2 CM FLG | MTIME(4)=0 | XFL=0 OS=0xFF(unknown)
        out.append(contentsOf: [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF])
        out.append(deflated)
        let crc = crc32(original)
        let isize = UInt32(truncatingIfNeeded: original.count)
        out.append(contentsOf: [
            UInt8(crc & 0xFF), UInt8((crc >> 8) & 0xFF),
            UInt8((crc >> 16) & 0xFF), UInt8((crc >> 24) & 0xFF),
            UInt8(isize & 0xFF), UInt8((isize >> 8) & 0xFF),
            UInt8((isize >> 16) & 0xFF), UInt8((isize >> 24) & 0xFF),
        ])
        return out
    }

    /// CRC-32 (reflected, polynomial 0xEDB88320); the Compression framework
    /// computes no checksum for raw DEFLATE, and the gzip trailer needs one.
    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            let idx = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = crc32Table[idx] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    private static let crc32Table: [UInt32] = {
        (0..<256).map { i -> UInt32 in
            var c = UInt32(i)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? (0xEDB8_8320 ^ (c >> 1)) : (c >> 1)
            }
            return c
        }
    }()
}
