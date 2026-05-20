//
//  MITMBodyCodec.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Compression
import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// Decoders for HTTP `Content-Encoding` codecs the body rewriter
/// recognises. Body rewrite materialises plaintext via these so regex
/// rules can operate on the message the application produced rather
/// than the compressed wire bytes.
///
/// We only decode. After rewriting, the rewriter drops the
/// `Content-Encoding` header so the output stream is sent as
/// `identity` — `identity` is always implicitly accepted per
/// RFC 7231 §5.3.4 unless the client forbids it, which no real
/// browser does.
enum MITMBodyCodec {

    /// Largest body the rewriter will buffer. iOS network extensions
    /// run under a tight memory budget (~50 MiB), and a single misfire
    /// here can crash the tunnel. 4 MiB comfortably covers HTML, JSON,
    /// and JavaScript responses while leaving headroom for everything
    /// else the extension is doing concurrently.
    static let maxBufferedBodyBytes: Int = 4 * 1024 * 1024

    /// Lowercased primary `Content-Type` (everything before `;`) with
    /// surrounding whitespace stripped. `nil` when the header is
    /// absent. Used by ``BodyContentTypeFilter`` to compare an
    /// incoming message's type against a user-supplied exact list.
    static func primaryContentType(_ contentType: String?) -> String? {
        guard let raw = contentType else { return nil }
        let primary = raw
            .split(separator: ";").first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        return primary.isEmpty ? nil : primary
    }

    /// One token in a `Content-Encoding` chain. The wire order is the
    /// order the server applied codings; decoding walks this list in
    /// reverse.
    enum Codec: Equatable {
        case identity
        case gzip
        case deflate
        case brotli
    }

    /// Parsed `Content-Encoding` header value plus a flag for whether
    /// every token is one we can decode.
    struct Plan: Equatable {
        let codecs: [Codec]
        let supported: Bool

        /// `true` when at least one non-identity codec is present and
        /// every token is recognised. The HTTP/1.1 and HTTP/2 paths use
        /// this to decide whether to buffer the body for decompression.
        var requiresDecompression: Bool {
            supported && codecs.contains { $0 != .identity }
        }

        static let identity = Plan(codecs: [.identity], supported: true)
    }

    /// Returns the decoding plan for a `Content-Encoding` header value.
    /// `nil` or empty input maps to ``Plan/identity``. Multi-codec
    /// values like `br, gzip` (server applied gzip first, then brotli)
    /// produce a plan whose ``Plan/codecs`` are in apply order.
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
        return Plan(codecs: codecs, supported: supported)
    }

    /// Applies ``plan`` to ``data`` in reverse-of-apply order. Returns
    /// nil if any codec fails to decode or the plan contains an
    /// unsupported codec.
    static func decompress(_ data: Data, plan: Plan) -> Data? {
        guard plan.supported else { return nil }
        var current = data
        for codec in plan.codecs.reversed() {
            switch codec {
            case .identity:
                continue
            case .gzip:
                guard let next = gunzip(current) else {
                    logger.warning("[MITM] gzip decode failed (\(current.count) B)")
                    return nil
                }
                current = next
            case .deflate:
                guard let next = inflateDeflate(current) else {
                    logger.warning("[MITM] deflate decode failed (\(current.count) B)")
                    return nil
                }
                current = next
            case .brotli:
                guard let next = streamDecode(current, algorithm: COMPRESSION_BROTLI) else {
                    logger.warning("[MITM] brotli decode failed (\(current.count) B)")
                    return nil
                }
                current = next
            }
        }
        return current
    }

    // MARK: - gzip (RFC 1952)

    /// Parses one or more concatenated gzip members per RFC 1952 §2.2.
    /// Each member is `<10-byte header><optional fields><deflate body>
    /// <8-byte trailer>`. The previous implementation read only the
    /// first member, dropping silently when an upstream sent
    /// concatenated members (which some CDNs and the bgzf format
    /// produce). Now we loop until the input is exhausted.
    private static func gunzip(_ data: Data) -> Data? {
        var combined = Data()
        var cursor = data.startIndex
        let end = data.endIndex
        while cursor < end {
            guard let (memberBytes, consumed) = gunzipOneMember(data, from: cursor) else {
                // Malformed member: if we already decoded at least
                // one earlier member, return what we have rather
                // than dropping the whole body. The trailing junk is
                // recoverable for the caller (they're presumably
                // logging a warning); the leading bytes were valid
                // gzip.
                return combined.isEmpty ? nil : combined
            }
            if combined.count + memberBytes.count > maxBufferedBodyBytes {
                logger.warning("[MITM] gzip multi-member output would exceed cap \(maxBufferedBodyBytes) B; aborting")
                return nil
            }
            combined.append(memberBytes)
            cursor = data.index(cursor, offsetBy: consumed)
        }
        return combined
    }

    /// Decodes one gzip member starting at ``offset`` in ``data``.
    /// Returns the decoded bytes plus the total number of input bytes
    /// consumed (header + deflate body + trailer), or nil on
    /// malformed input.
    private static func gunzipOneMember(_ data: Data, from offset: Data.Index) -> (decoded: Data, consumed: Int)? {
        let end = data.endIndex
        // Minimum: 10-byte fixed header + 8-byte trailer.
        guard data.distance(from: offset, to: end) >= 18 else { return nil }
        guard data[offset] == 0x1F,
              data[data.index(offset, offsetBy: 1)] == 0x8B,
              data[data.index(offset, offsetBy: 2)] == 0x08
        else { return nil }
        let flags = data[data.index(offset, offsetBy: 3)]
        var idx = data.index(offset, offsetBy: 10)
        if flags & 0x04 != 0 { // FEXTRA
            guard data.distance(from: idx, to: end) >= 2 else { return nil }
            let xlen = Int(data[idx]) | (Int(data[data.index(idx, offsetBy: 1)]) << 8)
            idx = data.index(idx, offsetBy: 2 + xlen)
            guard idx <= end else { return nil }
        }
        if flags & 0x08 != 0 { // FNAME (NUL-terminated)
            while idx < end, data[idx] != 0 { idx = data.index(after: idx) }
            guard idx < end else { return nil }
            idx = data.index(after: idx)
        }
        if flags & 0x10 != 0 { // FCOMMENT (NUL-terminated)
            while idx < end, data[idx] != 0 { idx = data.index(after: idx) }
            guard idx < end else { return nil }
            idx = data.index(after: idx)
        }
        if flags & 0x02 != 0 { // FHCRC
            idx = data.index(idx, offsetBy: 2)
            guard idx <= end else { return nil }
        }
        // Decode the deflate body, also returning how many input
        // bytes the deflate stream actually consumed so we can find
        // this member's trailer (and the next member's header).
        guard let (decoded, deflateConsumed) = streamDecodeMember(
            data.subdata(in: idx..<end),
            algorithm: COMPRESSION_ZLIB
        ) else { return nil }
        // Trailer is the 8 bytes following the deflate stream.
        let trailerStart = data.index(idx, offsetBy: deflateConsumed)
        guard data.distance(from: trailerStart, to: end) >= 8 else { return nil }
        let nextMember = data.index(trailerStart, offsetBy: 8)
        let consumed = data.distance(from: offset, to: nextMember)
        return (decoded, consumed)
    }

    // MARK: - deflate (RFC 7230 §4.2.2)

    /// Tries raw deflate first (what most servers actually send despite
    /// RFC 1950's zlib-wrapped requirement). Falls back to stripping
    /// the 2-byte zlib header + 4-byte adler32 footer when raw fails.
    private static func inflateDeflate(_ data: Data) -> Data? {
        if let raw = streamDecode(data, algorithm: COMPRESSION_ZLIB) {
            return raw
        }
        guard data.count >= 6 else { return nil }
        let body = data.subdata(in: (data.startIndex + 2)..<(data.endIndex - 4))
        return streamDecode(body, algorithm: COMPRESSION_ZLIB)
    }

    // MARK: - Streaming decoder

    /// Wraps `compression_stream_*` for unknown output sizes. Pulls
    /// 64 KiB at a time until the stream finalises or errors. Returns
    /// nil if the cumulative decompressed output would exceed
    /// ``maxBufferedBodyBytes`` — without the cap a 1 MiB gzip of
    /// zeros decompresses to ~1 GiB and exhausts the Network
    /// Extension's ~50 MiB budget (decompression-bomb DoS). The cap
    /// matches the rewriter's buffer limit so a body the rest of the
    /// pipeline couldn't act on anyway never gets fully materialised
    /// in memory; callers that hit the cap fall back to forwarding the
    /// original compressed bytes verbatim, same as a malformed-payload
    /// decode failure.
    private static func streamDecode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        return streamDecodeMember(data, algorithm: algorithm)?.decoded
    }

    /// Variant of ``streamDecode`` that also returns how many input
    /// bytes the decoder actually consumed before signalling end of
    /// stream. Used by ``gunzipOneMember`` to locate the per-member
    /// trailer and the start of any concatenated next member.
    private static func streamDecodeMember(
        _ data: Data,
        algorithm: compression_algorithm
    ) -> (decoded: Data, consumed: Int)? {
        guard !data.isEmpty else { return (Data(), 0) }
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }

        var status = compression_stream_init(stream, COMPRESSION_STREAM_DECODE, algorithm)
        guard status == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> (decoded: Data, consumed: Int)? in
            guard let inputBase = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
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
                        if output.count + written > maxBufferedBodyBytes {
                            logger.warning("[MITM] decompress output would exceed cap \(maxBufferedBodyBytes) B; aborting (likely decompression bomb)")
                            return nil
                        }
                        output.append(buffer, count: written)
                    }
                    if status == COMPRESSION_STATUS_END {
                        let consumed = data.count - stream.pointee.src_size
                        return (output, consumed)
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
    }
}
