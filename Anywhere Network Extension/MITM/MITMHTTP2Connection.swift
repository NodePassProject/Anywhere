//
//  MITMHTTP2Connection.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// Per-direction HTTP/2 plaintext translator wired between
/// ``TLSRecordConnection`` legs in ``MITMSession``.
///
/// The h2 protocol is HPACK-stateful (RFC 7541 §2.2: dynamic table is
/// shared per-connection-per-direction), so byte-forwarding HEADERS
/// fragments would desync the receiver's decoder. Instead, every
/// HPACK-bearing frame is decoded with this leg's decoder, optionally
/// rewritten via ``MITMHTTP2Rewriter``, and re-encoded statelessly with
/// literal-without-indexing — keeping the peer's decoder in lockstep
/// without us having to track an outgoing dynamic table.
///
/// Unknown / control frames (SETTINGS, WINDOW_UPDATE, PING, GOAWAY,
/// RST_STREAM, PRIORITY, future frame types) are passed through
/// verbatim. PADDED / PRIORITY flags are stripped on re-emit since
/// neither MITM endpoint requires them.
final class MITMHTTP2Connection {

    /// Which side of the MITM this leg lives on. The connection preface
    /// (24 bytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") is only ever sent
    /// by the client, so only the inbound leg needs to consume it.
    enum Direction {
        /// Browser → real server. The plaintext stream begins with a
        /// 24-byte preface followed by frames.
        case inbound
        /// Real server → browser. Frames only.
        case outbound
    }

    // MARK: - Frame types we touch

    private enum FrameTypeCode {
        static let data: UInt8         = 0x0
        static let headers: UInt8      = 0x1
        static let priority: UInt8     = 0x2
        static let pushPromise: UInt8  = 0x5
        static let continuation: UInt8 = 0x9
    }

    // MARK: - Raw frame

    /// Format-preserving frame view — keeps the wire-level type byte so
    /// frame types we don't recognise pass through unmodified.
    private struct RawFrame {
        var typeCode: UInt8
        var flags: UInt8
        var streamID: UInt32
        var payload: Data
    }

    // MARK: - State

    let direction: Direction
    private let rewriter: MITMHTTP2Rewriter
    private let decoder = HPACKDecoder()

    /// Phase this connection rewrites. Inbound client-to-server traffic is
    /// the request half; outbound server-to-client traffic is the response
    /// half. See RFC 9113 section 8.1.
    private var phase: MITMPhase {
        direction == .inbound ? .httpRequest : .httpResponse
    }

    /// Bytes of the connection preface still to be forwarded verbatim.
    private var prefaceRemaining: Int

    /// Buffer of decrypted plaintext that hasn't yet yielded a complete
    /// frame.
    private var rxBuffer = Data()

    /// Set while a HEADERS / PUSH_PROMISE without END_HEADERS is being
    /// followed by CONTINUATION frames. RFC 9113 §6.10 forbids any
    /// other frame on the connection until END_HEADERS arrives.
    private var pending: PendingHeaders?

    private struct PendingHeaders {
        let streamID: UInt32
        var fragments: Data
        /// Flags from the original HEADERS/PUSH_PROMISE frame; we keep
        /// END_STREAM and clear PADDED/PRIORITY/END_HEADERS on re-emit.
        let originalFlags: UInt8
        let kind: Kind

        enum Kind {
            case headers
            case pushPromise(promisedStreamID: UInt32)
        }
    }

    /// Per-stream body buffer used when at least one body-touching rule
    /// applies for the current direction. Missing entry means pass-through;
    /// present entry means accumulate, decompress per ``codec``, rewrite,
    /// and emit at END_STREAM. ``abandoned`` flips when an identity
    /// stream overflows ``MITMBodyCodec/maxBufferedBodyBytes`` mid-flight:
    /// the buffered prefix has already been emitted as DATA, and
    /// subsequent DATA on the stream is forwarded verbatim.
    /// ``headers`` snapshots the rewritten header block at HEADERS time
    /// so script rules can inspect it via the `ctx` argument; the list
    /// stays small (a few hundred bytes) and is dropped at END_STREAM.
    private struct BodyBuffer {
        var data: Data
        let codec: MITMBodyCodec.Plan
        let headers: [(name: String, value: String)]
        var abandoned: Bool = false
    }
    private var bodyBuffers: [UInt32: BodyBuffer] = [:]

    // MARK: - Init

    init(direction: Direction, rewriter: MITMHTTP2Rewriter) {
        self.direction = direction
        self.rewriter = rewriter
        self.prefaceRemaining = (direction == .inbound) ? 24 : 0
    }

    // MARK: - Public API

    /// Consumes one chunk of decrypted plaintext from the source TLS
    /// record connection and returns the transformed plaintext that
    /// should be encrypted onto the destination TLS record connection.
    /// Streaming-safe: callers may invoke this with arbitrarily small
    /// or large chunks.
    func process(_ data: Data) -> Data {
        var output = Data()
        var input = data

        // Forward the connection preface verbatim. If the chunk
        // happens to span the preface/frame boundary the second half
        // falls through into rxBuffer below.
        if prefaceRemaining > 0, !input.isEmpty {
            let take = min(prefaceRemaining, input.count)
            output.append(input.prefix(take))
            input.removeFirst(take)
            prefaceRemaining -= take
        }

        if !input.isEmpty {
            rxBuffer.append(input)
        }

        while let frame = parseFrame(from: &rxBuffer) {
            output.append(handleFrame(frame))
        }

        return output
    }

    // MARK: - Frame dispatch

    private func handleFrame(_ frame: RawFrame) -> Data {
        // While accumulating a header block, only CONTINUATION on the
        // same stream is legal (§6.10). Anything else here would be a
        // protocol violation by the peer; we still pass it through
        // since detecting + reporting the error is the receiver's job.
        switch frame.typeCode {
        case FrameTypeCode.headers:
            return handleHeaders(frame)
        case FrameTypeCode.continuation:
            return handleContinuation(frame)
        case FrameTypeCode.pushPromise:
            return handlePushPromise(frame)
        case FrameTypeCode.data:
            return handleData(frame)
        default:
            return serializeFrame(frame)
        }
    }

    // MARK: - HEADERS

    private func handleHeaders(_ frame: RawFrame) -> Data {
        guard let body = stripHeadersPadding(frame: frame, hasPriority: frame.flags & 0x20 != 0) else {
            // Malformed padding — drop the frame to avoid feeding
            // garbage into the HPACK decoder. The peer will GOAWAY.
            return Data()
        }

        if frame.flags & 0x4 != 0 { // END_HEADERS
            return finalizeHeaderBlock(
                streamID: frame.streamID,
                fragments: body,
                originalFlags: frame.flags,
                kind: .headers
            )
        }

        pending = PendingHeaders(
            streamID: frame.streamID,
            fragments: body,
            originalFlags: frame.flags,
            kind: .headers
        )
        return Data()
    }

    private func handleContinuation(_ frame: RawFrame) -> Data {
        guard var p = pending, p.streamID == frame.streamID else {
            // Stray CONTINUATION — pass through; the peer's stack will
            // raise the protocol error.
            return serializeFrame(frame)
        }

        p.fragments.append(frame.payload)

        if frame.flags & 0x4 != 0 { // END_HEADERS
            pending = nil
            return finalizeHeaderBlock(
                streamID: p.streamID,
                fragments: p.fragments,
                originalFlags: p.originalFlags,
                kind: p.kind
            )
        }

        pending = p
        return Data()
    }

    private func handlePushPromise(_ frame: RawFrame) -> Data {
        // PUSH_PROMISE payload (§6.6):
        //   [Pad Length? (8)]
        //   R | Promised Stream ID (31)
        //   Header Block Fragment
        //   [Padding]
        guard let (promisedStreamID, body) = stripPushPromisePadding(frame: frame) else {
            return Data()
        }

        if frame.flags & 0x4 != 0 { // END_HEADERS
            return finalizeHeaderBlock(
                streamID: frame.streamID,
                fragments: body,
                originalFlags: frame.flags,
                kind: .pushPromise(promisedStreamID: promisedStreamID)
            )
        }

        pending = PendingHeaders(
            streamID: frame.streamID,
            fragments: body,
            originalFlags: frame.flags,
            kind: .pushPromise(promisedStreamID: promisedStreamID)
        )
        return Data()
    }

    private func finalizeHeaderBlock(
        streamID: UInt32,
        fragments: Data,
        originalFlags: UInt8,
        kind: PendingHeaders.Kind
    ) -> Data {
        guard let decoded = decoder.decodeHeaders(from: fragments) else {
            // Decoder failure desyncs the dynamic table irrecoverably.
            // Pass an empty header block through so the receiver can
            // GOAWAY the connection cleanly.
            return Data()
        }

        // Trailer detection: a HEADERS frame on a stream that already
        // has a buffered body is a trailer. Flush the body as DATA
        // (without END_STREAM — the trailer carries it) so the receiver
        // sees DATA before HEADERS-with-END_STREAM, per RFC 9113 §8.1.
        var output = Data()
        if case .headers = kind, bodyBuffers[streamID] != nil {
            output.append(flushBufferedBody(streamID: streamID, endStream: false))
        }

        var rewritten: [(name: String, value: String)]
        switch kind {
        case .headers:
            // RFC 9113 section 8.1: client-to-server is a request and
            // server-to-client is a response. Pick the matching hook.
            rewritten = (direction == .inbound)
                ? rewriter.transformRequestHeaders(decoded, streamID: streamID)
                : rewriter.transformResponseHeaders(decoded, streamID: streamID)
        case .pushPromise:
            // PUSH_PROMISE carries the synthesized request that goes
            // with the soon-to-be-pushed response. The rewriter has no
            // dedicated hook; just pass the headers through.
            rewritten = decoded
        }

        // Decide body-buffering policy for the upcoming DATA frames on
        // this stream. Buffer when a body-script rule applies, the
        // codec is one we can decode (or identity), and either
        // content-length is within the cap or absent (identity only —
        // we cannot recover wire shape for a compressed body that
        // overflows mid-stream). Skip on END_STREAM HEADERS because
        // there is no body.
        if case .headers = kind,
           originalFlags & 0x1 == 0,
           rewriter.hasBodyRewrite(
               phase: phase,
               contentType: firstHeaderValue(rewritten, name: "content-type")
           ),
           shouldBufferStream(headers: rewritten) {
            let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewritten, name: "content-encoding"))
            bodyBuffers[streamID] = BodyBuffer(data: Data(), codec: codec, headers: rewritten)
            // The rewritten body's length is unknown at header emit
            // time. RFC 9113 §8.2.1 requires the sum of DATA frame
            // payloads to match `content-length` exactly when
            // present, so drop it; END_STREAM is the canonical
            // framing signal in HTTP/2.
            rewritten.removeAll { $0.name.lowercased() == "content-length" }
            if codec.requiresDecompression {
                // We will emit the body decompressed (identity), so
                // drop the codec from the outgoing header block.
                rewritten.removeAll { $0.name.lowercased() == "content-encoding" }
            }
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten)

        // Emit flags: keep END_STREAM and END_HEADERS (always set on
        // re-emit since we collapse fragments into one frame); drop
        // PADDED and PRIORITY.
        var emittedFlags: UInt8 = 0x4 // END_HEADERS
        if originalFlags & 0x1 != 0 { emittedFlags |= 0x1 } // END_STREAM

        switch kind {
        case .headers:
            output.append(serializeFrame(RawFrame(
                typeCode: FrameTypeCode.headers,
                flags: emittedFlags,
                streamID: streamID,
                payload: reencoded
            )))
            return output
        case .pushPromise(let promisedStreamID):
            var payload = Data(capacity: 4 + reencoded.count)
            let p = promisedStreamID & 0x7FFFFFFF
            payload.append(UInt8((p >> 24) & 0xFF))
            payload.append(UInt8((p >> 16) & 0xFF))
            payload.append(UInt8((p >> 8) & 0xFF))
            payload.append(UInt8(p & 0xFF))
            payload.append(reencoded)
            output.append(serializeFrame(RawFrame(
                typeCode: FrameTypeCode.pushPromise,
                flags: emittedFlags,
                streamID: streamID,
                payload: payload
            )))
            return output
        }
    }

    // MARK: - DATA

    private func handleData(_ frame: RawFrame) -> Data {
        guard let body = stripDataPadding(frame: frame) else {
            return Data()
        }

        let endStream = frame.flags & 0x1 != 0
        let streamID = frame.streamID

        // Pass-through path: no body rewrite for this stream. Re-emit the
        // DATA frame with the original body and END_STREAM flag, with
        // PADDED cleared.
        guard var buffer = bodyBuffers[streamID] else {
            var emittedFlags: UInt8 = 0
            if endStream { emittedFlags |= 0x1 }
            return serializeFrame(RawFrame(
                typeCode: FrameTypeCode.data,
                flags: emittedFlags,
                streamID: streamID,
                payload: body
            ))
        }

        // Abandoned path: a previous DATA frame on this stream blew
        // through the buffer cap. The buffered prefix has already been
        // emitted as DATA, so all we need to do is forward this frame
        // verbatim and clean up at END_STREAM.
        if buffer.abandoned {
            if endStream {
                bodyBuffers.removeValue(forKey: streamID)
            } else {
                bodyBuffers[streamID] = buffer
            }
            var emittedFlags: UInt8 = 0
            if endStream { emittedFlags |= 0x1 }
            return serializeFrame(RawFrame(
                typeCode: FrameTypeCode.data,
                flags: emittedFlags,
                streamID: streamID,
                payload: body
            ))
        }

        // Buffering path: accumulate until END_STREAM.
        buffer.data.append(body)

        // Mid-stream cap check. Only reachable for identity bodies
        // (compressed streams are pre-gated when content-length is
        // missing or already over the cap) so flushing the prefix as a
        // plain DATA frame is non-lossy.
        if !endStream, buffer.data.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] HTTP/2 stream \(streamID) exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes); abandoning rewrite")
            let prefix = buffer.data
            buffer.data = Data()
            buffer.abandoned = true
            bodyBuffers[streamID] = buffer
            return serializeFrame(RawFrame(
                typeCode: FrameTypeCode.data,
                flags: 0,
                streamID: streamID,
                payload: prefix
            ))
        }

        bodyBuffers[streamID] = buffer
        if !endStream {
            return Data()
        }
        return flushBufferedBody(streamID: streamID, endStream: true)
    }

    /// Emits the buffered body for ``streamID`` as a DATA frame, after
    /// decompressing per the recorded codec and applying body rules.
    /// Removes the entry from ``bodyBuffers`` so the stream is settled.
    /// Returns empty when there is no buffered body, or when the stream
    /// was already abandoned (its prefix has already been forwarded as
    /// raw DATA — nothing more to flush).
    private func flushBufferedBody(streamID: UInt32, endStream: Bool) -> Data {
        guard let buffer = bodyBuffers.removeValue(forKey: streamID) else {
            return Data()
        }
        if buffer.abandoned {
            return Data()
        }
        let plaintext: Data
        if buffer.codec.requiresDecompression {
            // If decode fails, emit the original (still-compressed) bytes
            // as identity. The peer will see corrupt content but the
            // stream stays usable; this is the same trade-off the HTTP/1
            // path makes.
            plaintext = MITMBodyCodec.decompress(buffer.data, plan: buffer.codec) ?? buffer.data
        } else {
            plaintext = buffer.data
        }
        let context = makeScriptContext(headers: buffer.headers)
        let contentType = firstHeaderValue(buffer.headers, name: "content-type")
        let rewritten = rewriter.rewriteBody(
            plaintext,
            phase: phase,
            contentType: contentType,
            context: context
        )
        var flags: UInt8 = 0
        if endStream { flags |= 0x1 }
        return serializeFrame(RawFrame(
            typeCode: FrameTypeCode.data,
            flags: flags,
            streamID: streamID,
            payload: rewritten
        ))
    }

    // MARK: - Body-buffer policy

    /// Decides whether a stream's DATA frames should be buffered for
    /// rewrite. Combines the codec and content-length gates so the
    /// decision is made once at HEADERS time rather than rediscovered
    /// per-frame. Content-Type filtering happens earlier, on the
    /// rewriter side via ``MITMHTTP2Rewriter/hasBodyRewrite(phase:contentType:)``.
    private func shouldBufferStream(headers: [(name: String, value: String)]) -> Bool {
        let codec = MITMBodyCodec.plan(for: firstHeaderValue(headers, name: "content-encoding"))
        guard codec.supported else { return false }
        if let raw = firstHeaderValue(headers, name: "content-length"),
           let length = Int(raw.trimmingCharacters(in: .whitespaces)) {
            return length <= MITMBodyCodec.maxBufferedBodyBytes
        }
        // No content-length. We can recover from a mid-stream cap
        // overflow only when the body is identity (just flush + pass
        // through). Compressed bodies whose size we cannot bound up
        // front are not safe to buffer optimistically — skip them.
        return !codec.requiresDecompression
    }

    /// Returns the first header value matching ``name`` (case-insensitive),
    /// or nil when absent.
    private func firstHeaderValue(_ headers: [(name: String, value: String)], name: String) -> String? {
        let target = name.lowercased()
        for (n, v) in headers where n.lowercased() == target {
            return v
        }
        return nil
    }

    /// Builds the per-message `ctx` argument for the script's
    /// `process(body, ctx)`. Pseudo-headers `:method`, `:authority`, and
    /// `:path` give us method and URL on requests; responses leave both
    /// nil. The script sees the same header list that was emitted on
    /// the wire (pseudo-headers included).
    private func makeScriptContext(headers: [(name: String, value: String)]) -> MITMScriptEngine.Context {
        var method: String?
        var url: String?
        if phase == .httpRequest {
            method = firstHeaderValue(headers, name: ":method")
            if let path = firstHeaderValue(headers, name: ":path") {
                let authority = firstHeaderValue(headers, name: ":authority") ?? ""
                url = "https://\(authority)\(path)"
            }
        }
        return MITMScriptEngine.Context(
            phase: phase,
            method: method,
            url: url,
            headers: headers,
            ruleSetID: rewriter.ruleSetID
        )
    }

    // MARK: - Padding helpers

    /// Strips PADDED + PRIORITY prefixes from a HEADERS payload,
    /// returning just the HPACK header block. Returns nil when the
    /// padding length is invalid.
    private func stripHeadersPadding(frame: RawFrame, hasPriority: Bool) -> Data? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 { // PADDED
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        if hasPriority {
            // 5-byte priority block: stream dep (4) + weight (1).
            guard payload.count >= 5 else { return nil }
            payload = payload.subdata(in: (payload.startIndex + 5)..<payload.endIndex)
        }
        return payload
    }

    /// Strips PADDED + extracts the Promised Stream ID from a
    /// PUSH_PROMISE payload.
    private func stripPushPromisePadding(frame: RawFrame) -> (UInt32, Data)? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 {
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        guard payload.count >= 4 else { return nil }
        let s = payload.startIndex
        let promised = (UInt32(payload[s]) << 24
                      | UInt32(payload[s + 1]) << 16
                      | UInt32(payload[s + 2]) << 8
                      | UInt32(payload[s + 3])) & 0x7FFFFFFF
        let block = payload.subdata(in: (s + 4)..<payload.endIndex)
        return (promised, block)
    }

    /// Strips PADDED from a DATA payload.
    private func stripDataPadding(frame: RawFrame) -> Data? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 {
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        return payload
    }

    /// Removes the leading pad-length byte and the trailing padding
    /// bytes; returns the inner content.
    private func stripPadding(_ payload: inout Data) -> Data? {
        guard !payload.isEmpty else { return nil }
        let padLen = Int(payload[payload.startIndex])
        guard payload.count >= 1 + padLen else { return nil }
        return payload.subdata(in: (payload.startIndex + 1)..<(payload.endIndex - padLen))
    }

    // MARK: - Frame parser / serializer

    /// Reads one complete frame from `buffer`, removing the consumed
    /// bytes. Returns nil if more bytes are needed.
    private func parseFrame(from buffer: inout Data) -> RawFrame? {
        guard buffer.count >= 9 else { return nil }
        let s = buffer.startIndex
        let length = (Int(buffer[s]) << 16) | (Int(buffer[s + 1]) << 8) | Int(buffer[s + 2])
        let total = 9 + length
        guard buffer.count >= total else { return nil }

        let type = buffer[s + 3]
        let flags = buffer[s + 4]
        let streamID = (UInt32(buffer[s + 5]) << 24
                      | UInt32(buffer[s + 6]) << 16
                      | UInt32(buffer[s + 7]) << 8
                      | UInt32(buffer[s + 8])) & 0x7FFFFFFF

        let payload = buffer.subdata(in: (s + 9)..<(s + total))
        buffer.removeFirst(total)

        return RawFrame(typeCode: type, flags: flags, streamID: streamID, payload: payload)
    }

    private func serializeFrame(_ frame: RawFrame) -> Data {
        var out = Data(capacity: 9 + frame.payload.count)
        let len = frame.payload.count
        out.append(UInt8((len >> 16) & 0xFF))
        out.append(UInt8((len >> 8) & 0xFF))
        out.append(UInt8(len & 0xFF))
        out.append(frame.typeCode)
        out.append(frame.flags)
        let sid = frame.streamID & 0x7FFFFFFF
        out.append(UInt8((sid >> 24) & 0xFF))
        out.append(UInt8((sid >> 16) & 0xFF))
        out.append(UInt8((sid >> 8) & 0xFF))
        out.append(UInt8(sid & 0xFF))
        out.append(frame.payload)
        return out
    }
}
