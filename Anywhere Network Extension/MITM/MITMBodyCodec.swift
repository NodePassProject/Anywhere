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

    /// Largest number of stacked `Content-Encoding` codings the rewriter will
    /// decode. Real responses carry one coding (occasionally two, e.g. a CDN
    /// that gzips then brotlis); a longer chain is almost always a crafted
    /// `Content-Encoding: gzip, gzip, gzip, …` whose only purpose is to force
    /// one ``maxBufferedBodyBytes``-capped decode pass per token. Bounded only
    /// by the head size cap, that token count can reach the tens of thousands —
    /// a CPU-amplification DoS on the serial lwIP / script queue, and cheap for
    /// the attacker since re-compressing already-compressed bytes barely grows
    /// the wire body. A chain longer than this fails the plan as *unsupported*,
    /// so the body is forwarded verbatim (the client decodes it) instead of
    /// being decoded for rewriting — fail-closed, the same posture an
    /// unrecognised coding already takes.
    static let maxCodecChainLength = 4

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
        // A chain longer than ``maxCodecChainLength`` is treated as unsupported
        // (fail-closed → the body is forwarded verbatim, the same posture an
        // unrecognised coding takes), bounding the per-token decode amplification
        // a crafted ``gzip, gzip, …`` chain would otherwise force.
        if codecs.count > maxCodecChainLength {
            supported = false
        }
        return Plan(codecs: codecs, supported: supported)
    }

    /// Applies ``plan`` to ``data`` in reverse-of-apply order. Returns
    /// nil if any codec fails to decode or the plan contains an
    /// unsupported codec. ``host`` is used only to attribute a decode
    /// failure in the log to the connection it came from.
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
                    // The reason + head fingerprint together pin the cause:
                    // a non-gzip ``head`` means the body was mislabeled or we
                    // buffered the wrong bytes; a deflate error that consumed
                    // all input points at a truncated stream; a clean magic
                    // with a header-field overrun is a corrupt header.
                    logger.warning("[MITM] \(host): gzip decode failed — \(failure?.description ?? "unknown") (input \(current.count) B, head=[\(Self.headFingerprint(current))])")
                    return nil
                }
                current = next
            case .deflate:
                guard let next = inflateDeflate(current) else {
                    logger.warning("[MITM] \(host): deflate decode failed (input \(current.count) B, head=[\(Self.headFingerprint(current))])")
                    return nil
                }
                current = next
            case .brotli:
                guard let next = streamDecode(current, algorithm: COMPRESSION_BROTLI) else {
                    logger.warning("[MITM] \(host): brotli decode failed (input \(current.count) B, head=[\(Self.headFingerprint(current))])")
                    return nil
                }
                current = next
            }
        }
        return current
    }

    /// Formats the leading bytes as space-separated hex — a compression
    /// fingerprint for the failure log: gzip is `1f 8b 08`, zlib `78 …`,
    /// raw JSON `7b`/`5b`, a gRPC length-prefix `00 …`, brotli has no fixed
    /// magic. Capped at four bytes on purpose: enough to identify the wire
    /// format, too few to spill meaningful plaintext if the body turns out
    /// to be an unencoded identity payload that was mislabeled.
    private static func headFingerprint(_ data: Data, maxBytes: Int = 4) -> String {
        data.prefix(maxBytes).map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    // MARK: - Single-codec encode/decode (JS `Anywhere.codec` bridge)

    /// Decodes a single codec. The transport pipeline already
    /// decompresses the outer `Content-Encoding` for us (see
    /// ``decompress``); this is the entry point the JS
    /// `Anywhere.codec.{gzip,deflate,brotli}.decode` helpers call to
    /// crack open compression that transport pass never sees — a gzipped
    /// field inside a JSON body, a brotli'd protobuf, a base64-of-gzip
    /// token. Honours the same ``maxBufferedBodyBytes`` decompression-
    /// bomb cap as the rewriter (the underlying stream decoders enforce
    /// it), so a payload that would exceed the cap returns nil just like
    /// a malformed one.
    static func decode(_ data: Data, codec: Codec) -> Data? {
        switch codec {
        case .identity: return data
        case .gzip:     return gunzip(data).decoded
        case .deflate:  return inflateDeflate(data)
        case .brotli:   return streamDecode(data, algorithm: COMPRESSION_BROTLI)
        }
    }

    /// Encodes a single codec — the compress side the transport pipeline
    /// never needs (it only ever decodes and re-emits identity) but
    /// scripts do: to re-pack a field they just edited, to hand a
    /// compressed body to `Anywhere.respond`, or to restore a
    /// `Content-Encoding` they want to keep on the wire. gzip emits a
    /// canonical single-member stream (RFC 1952 header + raw DEFLATE +
    /// CRC32/ISIZE trailer); deflate emits raw DEFLATE — what
    /// ``inflateDeflate`` decodes first and what servers actually send
    /// for `Content-Encoding: deflate` despite RFC 1950's zlib wrapper.
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

    /// Why a whole gzip body failed to decode, for the ``decompress``
    /// diagnostic log.
    private enum GzipFailure: CustomStringConvertible {
        /// The first member couldn't be decoded, so nothing was produced.
        case firstMember(GzipMemberFailure)
        /// A member decoded but the running output crossed
        /// ``maxBufferedBodyBytes`` — a decompression-bomb guard tripping,
        /// not a malformed stream.
        case capExceeded

        var description: String {
            switch self {
            case .firstMember(let reason): return reason.description
            case .capExceeded:             return "output exceeded \(maxBufferedBodyBytes) B cap"
            }
        }
    }

    /// Why a single gzip member failed, granular enough to separate the
    /// likely causes at a glance in the log: ``badMagic`` ⇒ the body isn't
    /// gzip (mislabeled `Content-Encoding`, or wrong bytes buffered);
    /// ``deflate`` with `consumed == of` ⇒ a truncated stream (we ran the
    /// decode before the full body arrived, or the peer cut it short);
    /// ``deflate`` erroring partway ⇒ corrupt payload; a header case ⇒ a
    /// structurally broken member. (A final member whose deflate completes
    /// but whose trailer is short isn't a failure — see ``gunzipOneMember``.)
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

    /// Result of decoding one gzip member.
    private enum GzipMemberOutcome {
        /// ``consumed`` is the member's total wire span (header + deflate
        /// body + trailer), so the caller can advance to the next member.
        case success(decoded: Data, consumed: Int)
        case failure(GzipMemberFailure)
        /// The cumulative decompressed output — this member plus everything
        /// ``gunzip`` already decoded — would exceed ``maxBufferedBodyBytes``.
        /// Kept distinct from ``failure`` so ``gunzip`` aborts the whole body
        /// (the decompression-bomb guard) instead of treating it as a
        /// recoverable malformed trailing member and returning a truncated body.
        case capExceeded
    }

    /// Parses one or more concatenated gzip members per RFC 1952 §2.2.
    /// Each member is `<10-byte header><optional fields><deflate body>
    /// <8-byte trailer>`. Loops until the input is exhausted rather than
    /// stopping after the first member: some CDNs and the bgzf format
    /// emit concatenated members, and decoding only the first would
    /// silently drop the rest of the body.
    /// Returns the decoded bytes, plus — when nothing was produced — the
    /// reason the first member failed, which ``decompress`` logs for
    /// diagnosis. ``decoded`` is non-nil (possibly empty) on success.
    private static func gunzip(_ data: Data) -> (decoded: Data?, failure: GzipFailure?) {
        var combined = Data()
        var cursor = data.startIndex
        let end = data.endIndex
        while cursor < end {
            // Pass the running output total as the per-member decode budget so
            // a member is bounded by ``maxBufferedBodyBytes - combined.count``
            // rather than the full cap. Without this each member could decode up
            // to the full cap while ``combined`` already held nearly the cap,
            // letting peak resident memory reach ~2× the intended ceiling.
            switch gunzipOneMember(data, from: cursor, producedSoFar: combined.count) {
            case .capExceeded:
                logger.warning("[MITM] gzip multi-member output would exceed cap \(maxBufferedBodyBytes) B; aborting")
                return (nil, .capExceeded)
            case .failure(let reason):
                // Malformed member: if we already decoded at least one
                // earlier member, return what we have rather than dropping
                // the whole body — the leading bytes were valid gzip and the
                // trailing junk is recoverable. A failure on the very first
                // member means the whole body is undecodable; surface why.
                return combined.isEmpty ? (nil, .firstMember(reason)) : (combined, nil)
            case .success(let memberBytes, let consumed):
                // The per-member budget above already bounded cumulative output
                // to the cap, so this append can't breach it.
                combined.append(memberBytes)
                cursor = data.index(cursor, offsetBy: consumed)
            }
        }
        return (combined, nil)
    }

    /// Decodes one gzip member starting at ``offset`` in ``data``. On
    /// success returns the decoded bytes plus the total input bytes consumed
    /// (header + deflate body + trailer); on failure returns the reason,
    /// which ``gunzip`` surfaces when it's the first member.
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
            // Distance-check the full 2-byte XLEN + extra-field span before
            // forming the index. ``index(_:offsetBy:)`` overshooting ``end`` is a
            // precondition violation that can trap, so never advance past ``end``.
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
            // Distance-check before advancing — see the FEXTRA note on why
            // overshooting ``end`` with ``index(_:offsetBy:)`` must be avoided.
            guard data.distance(from: idx, to: end) >= 2 else { return .failure(.truncatedHeaderField("FHCRC")) }
            idx = data.index(idx, offsetBy: 2)
        }
        // Decode the deflate body, also returning how many input bytes the
        // deflate stream actually consumed so we can find this member's
        // trailer (and the next member's header).
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
        // Trailer is the 8 bytes following the deflate stream.
        let trailerStart = data.index(idx, offsetBy: deflateConsumed)
        let trailerAvailable = data.distance(from: trailerStart, to: end)
        // The deflate stream already reached end-of-stream, so ``decoded`` is
        // the complete payload. The 8-byte trailer (CRC32 + ISIZE) is used
        // only to locate a *concatenated* next member — we never verify the
        // checksum. Fewer than 8 bytes remain only when this is the final
        // member and its trailer is either truncated or, more often, was
        // swallowed by the framework's raw-deflate decoder, whose consumed
        // byte count can run past the logical end of stream into the trailer.
        // Either way the payload is whole, so accept it and consume to the end
        // rather than discard a good decode and forward the body compressed.
        guard trailerAvailable >= 8 else {
            return .success(decoded: decoded, consumed: data.distance(from: offset, to: end))
        }
        let nextMember = data.index(trailerStart, offsetBy: 8)
        let consumed = data.distance(from: offset, to: nextMember)
        return .success(decoded: decoded, consumed: consumed)
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

    /// Outcome of one `compression_stream` decode pass. On failure carries
    /// how far the decoder got, so the gzip layer can separate a *truncated*
    /// stream (consumed all input, never reached end-of-stream) from a
    /// *corrupt* one (errored partway) in the diagnostic log. ``capExceeded``
    /// is the decompression-bomb guard, kept distinct from a genuine error.
    private enum StreamDecodeOutcome {
        case success(decoded: Data, consumed: Int)
        case failure(status: String, consumedInput: Int, producedOutput: Int)
        case capExceeded(producedOutput: Int)
    }

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
        if case .success(let decoded, _) = streamDecodeMember(data, algorithm: algorithm) {
            return decoded
        }
        return nil
    }

    /// Variant of ``streamDecode`` that also reports how many input bytes
    /// the decoder consumed before signalling end of stream (so
    /// ``gunzipOneMember`` can locate the per-member trailer and any
    /// concatenated next member) and, on failure, how far it got. Does not
    /// log: callers decide whether a failure is expected — ``inflateDeflate``
    /// probes raw deflate first and falls back on failure, so a log here
    /// would be noise.
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
                        // ``budgetUsed`` is output already produced by earlier
                        // gzip members in the same body, so the cap bounds the
                        // *cumulative* multi-member output, not just this member.
                        if budgetUsed + output.count + written > maxBufferedBodyBytes {
                            logger.warning("[MITM] decompress output would exceed cap \(maxBufferedBodyBytes) B; aborting")
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

    /// Compresses ``data`` with ``algorithm`` using `compression_stream`
    /// in encode mode — the mirror of ``streamDecode``. Pulls 64 KiB of
    /// output at a time until the stream finalises. Only the JS
    /// `Anywhere.codec` encoders use this; the transport pipeline never
    /// re-compresses. No explicit output cap is applied: compression
    /// doesn't meaningfully expand its input, and the input is itself
    /// bounded by the script engine's typed-array budget, so — unlike
    /// decode — encode carries no decompression-bomb risk.
    private static func streamEncode(_ data: Data, algorithm: compression_algorithm) -> Data? {
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }

        var status = compression_stream_init(stream, COMPRESSION_STREAM_ENCODE, algorithm)
        guard status == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }

        let bufferSize = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        // Drives the encode loop for a given source pointer/size.
        // Factored out so the empty-input case — where
        // `withUnsafeBytes` hands back a nil base address — can still
        // feed the encoder a zero-length source and get back a valid
        // (empty) stream rather than nil.
        func run(srcBase: UnsafePointer<UInt8>?, srcCount: Int) -> Data? {
            // src_size 0 means nothing is read from src_ptr, so reusing
            // `buffer` as a non-null placeholder when empty is safe.
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

    /// Wraps raw DEFLATE output in a single gzip member: the 10-byte
    /// fixed header (no optional fields, unknown OS/MTIME), the deflate
    /// body, then the 8-byte trailer — CRC32 of the *uncompressed* input
    /// and ISIZE (input length mod 2^32), both little-endian. Mirrors
    /// what ``gunzipOneMember`` parses back.
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

    /// CRC-32 (IEEE 802.3: reflected, polynomial 0xEDB88320) over
    /// ``data``. The `Compression` framework computes no checksum for
    /// the raw DEFLATE it emits, so ``gzipWrap`` needs its own to build
    /// a spec-valid gzip trailer.
    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            let idx = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = crc32Table[idx] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    /// Precomputed CRC-32 lookup table (one entry per byte value), built
    /// once on first use.
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
