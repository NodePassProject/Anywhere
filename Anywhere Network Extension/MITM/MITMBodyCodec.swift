//
//  MITMBodyCodec.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/8/26.
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

    /// Returns `true` when ``contentType`` describes a payload safe to
    /// run regex rules over: an explicit allowlist of textual MIME
    /// types. Everything else — media, fonts, wasm, protobuf, generic
    /// `application/octet-stream`, and any unknown type — is excluded.
    ///
    /// Allowlisting is the safer default. Latin-1 round-tripping
    /// preserves bytes, but a regex hit that lands inside a binary
    /// payload (a JPEG, a wasm module) would still corrupt it. The
    /// universe of textual types is small and well-known; the universe
    /// of binary types is open-ended. Missing the first costs the user
    /// a no-op they'll notice immediately; missing the second silently
    /// breaks downloads.
    ///
    /// Missing `Content-Type` is treated as allowed because APIs
    /// occasionally return JSON without a content type and rules
    /// targeting them are common; explicit binary responses always
    /// carry a type.
    ///
    /// Consumed by ``BodyContentTypeFilter`` as the fallback when a
    /// script rule did not declare its own Content-Type list at import
    /// time.
    static func isRewritableType(_ contentType: String?) -> Bool {
        guard let raw = contentType else { return true }
        let primary = raw
            .split(separator: ";").first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        if primary.isEmpty { return true }

        // text/* is textual by definition (text/html, text/plain,
        // text/css, text/javascript, text/event-stream, ...).
        if primary.hasPrefix("text/") { return true }

        // Known-textual application/* subtypes plus the structured-
        // syntax suffixes from RFC 6839 (`+json`, `+xml`, `+yaml`)
        // which cover the long tail of vendor types like
        // `application/vnd.api+json` or `application/problem+json`.
        if primary.hasPrefix("application/") {
            let subtype = String(primary.dropFirst("application/".count))
            switch subtype {
            case "json",
                 "xml",
                 "javascript",
                 "ecmascript",
                 "x-javascript",
                 "x-ecmascript",
                 "x-www-form-urlencoded",
                 "graphql",
                 "jwt",
                 "yaml",
                 "x-yaml",
                 "csv",
                 "x-amz-json-1.0",
                 "x-amz-json-1.1":
                return true
            default:
                return subtype.hasSuffix("+json")
                    || subtype.hasSuffix("+xml")
                    || subtype.hasSuffix("+yaml")
            }
        }

        return false
    }

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

    /// Strips the gzip member header + trailing CRC32/ISIZE and feeds
    /// the inner deflate stream to ``streamDecode``. Only the first
    /// member is read; concatenated members are rare in HTTP responses
    /// and not handled.
    private static func gunzip(_ data: Data) -> Data? {
        // Minimum: 10-byte fixed header + 8-byte trailer.
        guard data.count >= 18 else { return nil }
        let s = data.startIndex
        guard data[s] == 0x1F, data[s + 1] == 0x8B, data[s + 2] == 0x08 else {
            return nil
        }
        let flags = data[s + 3]
        var idx = s + 10
        let end = data.endIndex
        if flags & 0x04 != 0 { // FEXTRA
            guard idx + 2 <= end else { return nil }
            let xlen = Int(data[idx]) | (Int(data[idx + 1]) << 8)
            idx += 2 + xlen
            guard idx <= end else { return nil }
        }
        if flags & 0x08 != 0 { // FNAME (NUL-terminated)
            while idx < end, data[idx] != 0 { idx += 1 }
            guard idx < end else { return nil }
            idx += 1
        }
        if flags & 0x10 != 0 { // FCOMMENT (NUL-terminated)
            while idx < end, data[idx] != 0 { idx += 1 }
            guard idx < end else { return nil }
            idx += 1
        }
        if flags & 0x02 != 0 { // FHCRC
            idx += 2
            guard idx <= end else { return nil }
        }
        let bodyEnd = end - 8
        guard bodyEnd > idx else { return nil }
        return streamDecode(data.subdata(in: idx..<bodyEnd), algorithm: COMPRESSION_ZLIB)
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
    /// 64 KiB at a time until the stream finalises or errors.
    private static func streamDecode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        guard !data.isEmpty else { return Data() }
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }

        var status = compression_stream_init(stream, COMPRESSION_STREAM_DECODE, algorithm)
        guard status == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Data? in
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
    }
}
