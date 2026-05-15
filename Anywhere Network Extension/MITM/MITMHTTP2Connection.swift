//
//  MITMHTTP2Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
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
        static let rstStream: UInt8    = 0x3
        static let pushPromise: UInt8  = 0x5
        static let continuation: UInt8 = 0x9
    }

    /// HTTP/2's mandated minimum ``SETTINGS_MAX_FRAME_SIZE`` (RFC 9113 §6.5.2).
    private static let maxFramePayloadSize = 16_384

    /// Cap on cumulative bytes accumulated in
    /// ``PendingHeaders.fragments`` across a HEADERS / PUSH_PROMISE
    /// frame plus its CONTINUATION chain. RFC 9113 has no spec-level
    /// limit, so a peer can chain CONTINUATIONs without bound and
    /// exhaust the Network Extension's ~50 MiB memory budget. 256 KiB
    /// fits the largest real-world request heads (JWT-bearing tokens,
    /// multi-kilobyte cookies) with margin while leaving no
    /// per-stream pressure path open. On overflow the pending state
    /// is dropped and no HEADERS reach the peer's decoder — the same
    /// failure mode as an HPACK decode error, which the connection
    /// recovers from by GOAWAY.
    private static let maxHeaderBlockFragmentBytes: Int = 256 * 1024

    /// Cap on the wire-level payload of a single received frame.
    /// ``SETTINGS_MAX_FRAME_SIZE`` (RFC 9113 §6.5.2) allows up to
    /// 2^24-1 (~16 MiB) via SETTINGS negotiation, but the MITM does
    /// not track either peer's setting and the Network Extension's
    /// ~50 MiB budget cannot sustain a single 16 MiB allocation.
    /// 1 MiB sits well above the 16 KiB default that nginx, Apache,
    /// and Chrome stick to in practice while keeping the worst-case
    /// per-frame allocation bounded. A frame exceeding this cap flips
    /// ``parseError`` and stops further processing — recovering
    /// requires finding the next valid frame boundary in a stream of
    /// arbitrary bytes, which is undecidable, so the peer sees a
    /// stalled half of the connection and eventually GOAWAYs.
    private static let maxReceivedFramePayloadSize: Int = 1 * 1024 * 1024

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

    /// Sticky flag set when ``parseFrame`` rejects a frame whose wire
    /// length exceeds ``maxReceivedFramePayloadSize``. Once set,
    /// ``process(_:)`` returns nothing and ``rxBuffer`` stays cleared
    /// — resuming parse would require finding the next valid frame
    /// boundary in a stream of arbitrary bytes, which is undecidable.
    /// The peer sees a stalled half of the connection and GOAWAYs
    /// after its timeout.
    private var parseError: Bool = false

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

    /// Per-stream pending message used when at least one script rule
    /// applies for the current direction. Missing entry means
    /// pass-through (HEADERS already emitted, DATA forwarded verbatim);
    /// present entry means we deferred HEADERS emission and are
    /// accumulating DATA so the script chain can mutate the whole
    /// message (headers + body + pseudo-headers) before re-encoding.
    ///
    /// ``data`` holds the raw (possibly compressed) body bytes seen so
    /// far. ``headers`` is the rewritten header block from
    /// ``MITMHTTP2Rewriter`` and is what the script ctx is built from.
    /// ``abandoned`` flips when an identity stream overflows the body
    /// cap mid-flight: the deferred HEADERS + buffered DATA prefix are
    /// emitted un-mutated, and subsequent DATA is forwarded verbatim.
    /// ``originatingRequest`` is the request method/url recorded by the
    /// inbound leg, populated only on outbound (response) streams.
    private struct PendingMessage {
        var data: Data
        let codec: MITMBodyCodec.Plan
        var headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        var abandoned: Bool = false
    }
    private var pendingMessages: [UInt32: PendingMessage] = [:]

    /// Per-stream state for streaming-script mode. Set at HEADERS time
    /// when a ``streamScript`` rule matches the message Content-Type;
    /// drives per-DATA-frame script invocation. Mutually exclusive
    /// with ``pendingMessages`` — a stream is either buffered (full
    /// script) or streamed (per-frame script), never both.
    private struct StreamingState {
        let headers: [(name: String, value: String)]
        let contentType: String?
        let originatingRequest: MITMRequestLog.Record?
        var frameIndex: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
        /// Running `emitted - consumed` byte total for the script's
        /// effect on this stream. Tripping ``maxStreamingRewriteGrowthBytes``
        /// flips the cursor to ``bypass`` so subsequent frames pass
        /// through unchanged. See the flow-control note on the
        /// constant for why we cap.
        var cumulativeGrowth: Int = 0
        /// Single-frame lookahead so the script's ``frame.end = true``
        /// call coincides with the body of the actual last DATA
        /// frame. Without it, an h2 stream that terminates via
        /// trailer HEADERS (END_STREAM on trailer, not on the last
        /// DATA) would deliver the last DATA payload with
        /// ``frame.end = false`` and then a separate empty-body call
        /// with ``frame.end = true``, breaking scripts written
        /// against HTTP/1 semantics where the final call always
        /// carries the last chunk's bytes. The held frame is
        /// released as non-final when the next DATA arrives (we know
        /// it wasn't last), and as final on END_STREAM-bearing DATA
        /// or by ``flushStreamingScript`` on trailer arrival.
        var pendingFrame: Data?
    }
    private var streamingScripts: [UInt32: StreamingState] = [:]

    /// Bytes synthesized by request-phase scripts that called
    /// `Anywhere.respond(...)` and need to be written straight back to
    /// the client (i.e. injected onto the inner TLS record). Populated
    /// on the inbound leg only; the outbound leg never touches it.
    /// Drained by the session pump via ``drainPendingClientBytes()``
    /// immediately after each ``process(_:)`` call.
    private var pendingClientBytes = Data()

    /// Stream IDs whose request was synthesized via
    /// `Anywhere.respond(...)` and never reached the upstream. The
    /// outer leg has no record of these stream IDs, so the inner
    /// client's follow-up frames on them (trailers, DATA, WINDOW_UPDATE,
    /// or typically a RST_STREAM after consuming the response) MUST be
    /// swallowed here rather than forwarded. The upstream sees the
    /// stream as idle, so forwarding stream frames can trigger a
    /// connection-level PROTOCOL_ERROR and take down every other
    /// in-flight stream on the same h2 connection. Inbound leg only.
    ///
    /// Eviction: RST_STREAM clears the entry, the swallow path clears
    /// it when it sees an END_STREAM on a DATA / HEADERS frame, and a
    /// FIFO cap (see ``synthRespondedMaxStreams``) evicts the oldest
    /// entry when neither happens. Clients are not required to RST
    /// after consuming a synthesized response — most just stop sending
    /// — so without the cap the set would grow unbounded for the
    /// connection's lifetime on every script that fires
    /// ``Anywhere.respond``.
    private var synthRespondedStreams: Set<UInt32> = []
    /// Insertion order mirror of ``synthRespondedStreams`` so the cap's
    /// eviction picks the oldest streamID without losing the O(1)
    /// membership test on the hot frame-dispatch path.
    private var synthRespondedOrder: [UInt32] = []

    /// Upper bound on ``synthRespondedStreams`` per connection. Sized
    /// well above the spec-default ``SETTINGS_MAX_CONCURRENT_STREAMS``
    /// (100) so a fully-saturated h2 connection doesn't trip eviction
    /// against streams that may still be live. Worst-case memory cost
    /// is ~1 KiB of UInt32s + array overhead.
    private static let synthRespondedMaxStreams = 256

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
        // Once an oversized frame has broken the parse state, stay
        // broken — dropping further bytes on the floor is strictly
        // safer than misparsing them as a new frame's preamble.
        if parseError { return Data() }
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

    /// Drains and returns any client-bound bytes synthesized by
    /// request-phase scripts that called `Anywhere.respond(...)` since
    /// the last call. The session pump writes these directly to the
    /// inner TLS record, bypassing the outbound translator entirely
    /// (the HPACK encoder is stateless, so a fresh header block decodes
    /// cleanly on the client side without disturbing either dynamic
    /// table). The outbound leg never populates this — call sites
    /// guard with ``direction == .inbound``.
    func drainPendingClientBytes() -> Data {
        let bytes = pendingClientBytes
        pendingClientBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    // MARK: - Frame dispatch

    private func handleFrame(_ frame: RawFrame) -> Data {
        // While accumulating a header block, only CONTINUATION on the
        // same stream is legal (§6.10). Anything else here would be a
        // protocol violation by the peer; we still pass it through
        // since detecting + reporting the error is the receiver's job.
        if frame.streamID != 0,
           synthRespondedStreams.contains(frame.streamID),
           frame.typeCode != FrameTypeCode.rstStream {
            // Evict the streamID when the swallowed frame carries
            // END_STREAM (bit 0x1 of DATA or HEADERS flags). The
            // client is done with the stream on its side, so pinning
            // the ID in the set for the connection's lifetime is
            // wasted memory and pressures the FIFO cap.
            let endStream = frame.flags & 0x1 != 0
            let endStreamBearing = frame.typeCode == FrameTypeCode.data
                || frame.typeCode == FrameTypeCode.headers
            if endStream, endStreamBearing {
                clearSynthResponded(frame.streamID)
            }
            return Data()
        }
        switch frame.typeCode {
        case FrameTypeCode.headers:
            return handleHeaders(frame)
        case FrameTypeCode.continuation:
            return handleContinuation(frame)
        case FrameTypeCode.pushPromise:
            return handlePushPromise(frame)
        case FrameTypeCode.data:
            return handleData(frame)
        case FrameTypeCode.rstStream:
            return handleRSTStream(frame)
        default:
            return serializeFrame(frame)
        }
    }

    /// Drops per-stream bookkeeping for an aborted stream and forwards
    /// the RST_STREAM frame verbatim. Without this, a long-lived
    /// connection that frequently RSTs (e.g. background sync apps that
    /// cancel and retry) would accumulate dead entries in
    /// ``pendingMessages`` and ``streamingScripts`` until the
    /// connection closes. The shared ``MITMRequestLog`` entry is also
    /// dropped so the cross-leg method/url map doesn't pin a record
    /// for a stream that will never produce a response. Each leg
    /// clears independently — the other leg's matching clear is a
    /// no-op.
    private func handleRSTStream(_ frame: RawFrame) -> Data {
        pendingMessages.removeValue(forKey: frame.streamID)
        streamingScripts.removeValue(forKey: frame.streamID)
        _ = rewriter.requestLog.popHTTP2(streamID: frame.streamID)
        // Swallow RST_STREAMs for streams the upstream never saw — the
        // request was synthesized on the inner leg via Anywhere.respond
        // and no HEADERS / DATA ever went on the wire upstream.
        // Forwarding the RST in that case is a PROTOCOL_ERROR per RFC
        // 9113 §5.4.1 (RST_STREAM on an idle stream → connection-level
        // error), which the upstream answers with GOAWAY and kills
        // every other stream on the connection.
        if clearSynthResponded(frame.streamID) {
            return Data()
        }
        return serializeFrame(frame)
    }

    // MARK: - HEADERS

    private func handleHeaders(_ frame: RawFrame) -> Data {
        guard let body = stripHeadersPadding(frame: frame, hasPriority: frame.flags & 0x20 != 0) else {
            // Malformed padding — drop the frame to avoid feeding
            // garbage into the HPACK decoder. The peer will GOAWAY.
            return Data()
        }

        // Single-frame HEADERS cap. ``handleContinuation`` enforces
        // the same bound on chained CONTINUATIONs; without this check
        // a peer can put the entire ``maxHeaderBlockFragmentBytes``
        // budget into one frame and bypass the chain-side guard.
        if body.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 stream \(frame.streamID): HEADERS payload \(body.count) B exceeded cap \(Self.maxHeaderBlockFragmentBytes); dropping")
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

        // Project the post-append size and reject *before* allocating.
        // Otherwise a single 16 MiB CONTINUATION blows through the cap
        // on the append itself; the existing variable ``p`` shares
        // ``pending``'s storage by COW until the first mutation.
        if p.fragments.count + frame.payload.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 stream \(frame.streamID): header block fragments would be \(p.fragments.count + frame.payload.count) B, over cap \(Self.maxHeaderBlockFragmentBytes); dropping")
            pending = nil
            return Data()
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

        if body.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 stream \(frame.streamID): PUSH_PROMISE payload \(body.count) B exceeded cap \(Self.maxHeaderBlockFragmentBytes); dropping")
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

        // Classify the HEADERS frame against the raw decoded block,
        // BEFORE user header rules run (those can't fake a fresh
        // response shape onto an actual trailer). A HEADERS without
        // the primary pseudo-header — `:method` for requests,
        // `:status` for responses — is a trailer (RFC 9113 §8.1) and
        // gets emitted verbatim through the pass-through path without
        // popping the request log or entering script mode. An
        // outbound HEADERS with `:status` in the 1xx range (except
        // 101) is an interim informational response (100 Continue,
        // 103 Early Hints, …): more HEADERS follow on the same stream
        // so the request-log record must stay live for the final
        // response.
        var output = Data()
        let isTrailer: Bool
        let isInterimResponse: Bool
        if case .headers = kind {
            switch direction {
            case .inbound:
                isTrailer = firstHeaderValue(decoded, name: ":method") == nil
                isInterimResponse = false
            case .outbound:
                if let raw = firstHeaderValue(decoded, name: ":status"),
                   let status = Int(raw.trimmingCharacters(in: .whitespaces)) {
                    isTrailer = false
                    isInterimResponse = (100..<200).contains(status) && status != 101
                } else {
                    isTrailer = true
                    isInterimResponse = false
                }
            }
        } else {
            isTrailer = false
            isInterimResponse = false
        }

        // Flush deferred script state when a trailer or follow-on
        // HEADERS arrives on a stream that previously entered scripted
        // mode. For buffered mode we run scripts on the accumulated
        // body and emit deferred HEADERS + DATA (without END_STREAM —
        // the trailer carries it). For streaming mode we give the
        // script one final invocation with an empty body and
        // ``frame.end = true`` so it can flush any per-stream state;
        // non-empty output goes on the wire as a final DATA frame
        // before the trailer HEADERS.
        if case .headers = kind {
            if pendingMessages[streamID] != nil {
                output.append(runScriptsAndFlush(streamID: streamID, endStream: false))
                if synthRespondedStreams.contains(streamID) {
                    return output
                }
            } else if streamingScripts[streamID] != nil {
                output.append(flushStreamingScript(streamID: streamID))
            }
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

        let endStreamOnHeaders = originalFlags & 0x1 != 0
        let contentType = firstHeaderValue(rewritten, name: "content-type")

        // Pop or peek the originating request once per outbound
        // response head, before any script-mode dispatch. Doing it
        // here (rather than inside each script branch) ensures the
        // streamID→record map drains for pass-through responses too —
        // without this it leaks until connection close. Interim 1xx
        // responses peek so the record stays live for the matching
        // final response that follows on the same stream.
        let originatingRequest: MITMRequestLog.Record?
        if case .headers = kind, direction == .outbound, !isTrailer {
            if isInterimResponse {
                originatingRequest = rewriter.requestLog.peekHTTP2(streamID: streamID)
            } else {
                originatingRequest = rewriter.requestLog.popHTTP2(streamID: streamID)
            }
        } else {
            originatingRequest = nil
        }

        // Streaming-script mode wins over buffered-script mode when
        // both apply. The trade-off: stream rules see DATA frames
        // one-at-a-time without HTTP-level decompression, so the body
        // never stalls — but they can't touch HEADERS, which we emit
        // immediately below. Trailers and interim responses skip
        // scripting entirely: trailers have no real "head" to mutate,
        // and interim responses precede the actual final headers.
        //
        // ``endStreamOnHeaders`` skips this branch even when a stream
        // script matches: there will be no DATA frame for the script
        // to fire on, so the right behaviour is to fall through to the
        // buffered-script path (which handles an empty body) or to
        // pass-through. Without this gate, a request/response with no
        // body would silently bypass any buffered script that also
        // matched the same Content-Type.
        if case .headers = kind, !isTrailer, !isInterimResponse,
           !endStreamOnHeaders,
           rewriter.hasStreamScriptRule(phase: phase, contentType: contentType) {
            if rewriter.hasScriptRule(phase: phase, contentType: contentType) {
                logger.warning("[MITM] HTTP/2 stream \(streamID): streamScript rule wins over script rule on the same Content-Type")
            }

            // Inbound HEADERS still need to land in the request log so
            // the response-side scripts can read method/url.
            if direction == .inbound {
                logHTTP2Request(streamID: streamID, headers: rewritten)
            }

            // Track per-stream state so DATA frames know to run the
            // script chain. No body buffering, no decompression. The
            // originating request was popped once at the top of this
            // function for outbound streams.
            streamingScripts[streamID] = StreamingState(
                headers: rewritten,
                contentType: contentType,
                originatingRequest: originatingRequest,
                cursor: MITMScriptTransform.FrameCursor()
            )

            let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten)
            output.append(emitHeaderBlock(
                streamID: streamID,
                block: reencoded,
                endStream: false,
                kind: kind
            ))
            return output
        }

        // Buffered-script mode: defer HEADERS emission. The script may
        // mutate any field on the message, including pseudo-headers,
        // so the wire HEADERS frame waits until scripts have run. For
        // bodied streams the deferral also drives body buffering; for
        // END_STREAM-on-HEADERS streams the script runs inline against
        // an empty body. Skipped for trailers and interim responses
        // for the same reasons as streaming-script above.
        if case .headers = kind, !isTrailer, !isInterimResponse,
           rewriter.hasScriptRule(phase: phase, contentType: contentType),
           shouldBufferStream(headers: rewritten, endStream: endStreamOnHeaders) {
            let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewritten, name: "content-encoding"))
            // Drop content-length: the post-script body size is
            // unknown at HEADERS-defer time and HTTP/2 doesn't require
            // it. Keep content-encoding intact for now —
            // ``runScriptsAndFlush`` strips it on a successful
            // decompression and, on decode failure, emits the deferred
            // HEADERS + raw bytes verbatim so the receiver can still
            // try to decode the original payload.
            rewritten.removeAll { $0.name.lowercased() == "content-length" }

            // ``originatingRequest`` was popped once at the top of
            // this function for outbound streams; pass-through and
            // PUSH_PROMISE cases see nil and ignore it.
            pendingMessages[streamID] = PendingMessage(
                data: Data(),
                codec: codec,
                headers: rewritten,
                originatingRequest: originatingRequest
            )

            if endStreamOnHeaders {
                // No DATA will follow — run scripts immediately on an
                // empty body. ``runScriptsAndFlush`` emits the deferred
                // HEADERS plus any body the script populated.
                output.append(runScriptsAndFlush(streamID: streamID, endStream: true))
            }
            return output
        }

        // Pass-through path: no script applies, this is a trailer or
        // interim response, or this is a PUSH_PROMISE. Inbound request
        // HEADERS get logged so the response side can populate
        // ctx.method/ctx.url even when no script touched the request —
        // but trailer HEADERS, which carry no pseudo-headers, must be
        // skipped here. Without this gate a request trailer would
        // overwrite the streamID→record map with nils and the
        // matching response-side script would lose its originating
        // request context.
        if case .headers = kind, direction == .inbound, !isTrailer {
            logHTTP2Request(streamID: streamID, headers: rewritten)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten)

        // Encoded block emission drops PADDED and PRIORITY but preserves
        // END_STREAM. END_HEADERS lands on the final emitted frame, which
        // ``emitHeaderBlock`` picks based on whether splitting is required.
        output.append(emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: endStreamOnHeaders,
            kind: kind
        ))
        return output
    }

    // MARK: - DATA

    private func handleData(_ frame: RawFrame) -> Data {
        guard let body = stripDataPadding(frame: frame) else {
            return Data()
        }

        let endStream = frame.flags & 0x1 != 0
        let streamID = frame.streamID

        // Streaming-script path: run the script chain on this single
        // DATA frame and emit immediately. No buffering, no
        // decompression — gRPC and other framed-stream payloads stay
        // streaming.
        if var streaming = streamingScripts[streamID] {
            return handleStreamingData(
                streamID: streamID,
                streaming: &streaming,
                body: body,
                endStream: endStream
            )
        }

        // Pass-through path: no script for this stream. Re-emit the
        // DATA frame with the original body and END_STREAM flag, with
        // PADDED cleared.
        guard var pending = pendingMessages[streamID] else {
            return emitDataFrames(streamID: streamID, payload: body, endStream: endStream)
        }

        // Abandoned path: a previous DATA frame on this stream blew
        // through the buffer cap. HEADERS + buffered prefix were
        // already emitted by the abandon transition; forward this frame
        // verbatim and clean up at END_STREAM.
        if pending.abandoned {
            if endStream {
                pendingMessages.removeValue(forKey: streamID)
            } else {
                pendingMessages[streamID] = pending
            }
            return emitDataFrames(streamID: streamID, payload: body, endStream: endStream)
        }

        // Buffering path: accumulate until END_STREAM.
        pending.data.append(body)

        // Mid-stream cap check. Only reachable for identity bodies
        // (compressed streams are pre-gated when content-length is
        // missing or already over the cap). We've withheld the HEADERS
        // frame so far, so the abandon transition emits the deferred
        // HEADERS (without script mutations) plus the buffered prefix
        // as DATA, then continues to forward subsequent DATA verbatim.
        if !endStream, pending.data.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] HTTP/2 stream \(streamID) exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes); abandoning rewrite")
            return abandonPending(streamID: streamID, pending: &pending)
        }

        pendingMessages[streamID] = pending
        if !endStream {
            return Data()
        }
        return runScriptsAndFlush(streamID: streamID, endStream: true)
    }

    /// Closes out a streaming-script stream when END_STREAM lands on
    /// a trailer HEADERS frame rather than on a DATA frame. Emits
    /// the held-back final DATA frame (if any) with
    /// ``frame.end = true`` so the script's last invocation carries
    /// the actual last frame's bytes — matching HTTP/1's chunked
    /// streaming contract. When no frame was held (no DATA on the
    /// stream at all), the script still gets one empty-body
    /// ``isLast=true`` call as a flush opportunity. The wire
    /// END_STREAM bit lives on the upcoming trailer HEADERS, so the
    /// DATA frame we emit here carries ``endStream=false``.
    private func flushStreamingScript(streamID: UInt32) -> Data {
        guard var streaming = streamingScripts.removeValue(forKey: streamID) else {
            return Data()
        }
        let body = streaming.pendingFrame ?? Data()
        streaming.pendingFrame = nil
        return processStreamingFrame(
            streamID: streamID,
            streaming: &streaming,
            body: body,
            isLast: true,
            wireEndStream: false
        )
    }

    /// Streaming-script path. ``Anywhere.done`` / ``Anywhere.exit``
    /// flip the cursor's ``bypass`` flag so subsequent frames on the
    /// stream pass through unchanged. The streaming entry is cleared
    /// on END_STREAM regardless of bypass state so a follow-up
    /// message on the same stream ID (rare under HTTP/2 stream-ID
    /// rules but possible with PUSH_PROMISE) gets a fresh cursor.
    ///
    /// Lookahead: each DATA frame is held for one event so the script
    /// call with ``frame.end = true`` always carries the last frame's
    /// actual bytes (rather than firing on an empty body after the
    /// last DATA already went out — the old behaviour, which
    /// diverged from HTTP/1 chunked semantics). When the next DATA
    /// arrives, the held one is released as non-final; when this
    /// frame's END_STREAM bit is set, the held one is released as
    /// non-final and the current one is processed as final.
    private func handleStreamingData(
        streamID: UInt32,
        streaming: inout StreamingState,
        body: Data,
        endStream: Bool
    ) -> Data {
        var output = Data()

        // Release the previously held frame, if any. Its mere
        // presence here means the stream did not end on it (a
        // subsequent DATA frame has arrived), so the script's
        // ``frame.end`` is false. Bypass is honoured inside
        // ``processStreamingFrame``: held frames are still emitted,
        // just verbatim.
        if let held = streaming.pendingFrame {
            streaming.pendingFrame = nil
            output.append(processStreamingFrame(
                streamID: streamID,
                streaming: &streaming,
                body: held,
                isLast: false,
                wireEndStream: false
            ))
        }

        if endStream {
            // END_STREAM on this DATA frame: this IS the last frame
            // on the stream, no trailers can follow. Process inline
            // with ``isLast=true`` so the script sees the actual
            // last-frame bytes (HTTP/1 chunked parity).
            output.append(processStreamingFrame(
                streamID: streamID,
                streaming: &streaming,
                body: body,
                isLast: true,
                wireEndStream: true
            ))
            streamingScripts.removeValue(forKey: streamID)
        } else {
            // Defer: we don't yet know whether this is the last DATA
            // (a trailer HEADERS could follow). Stash it; the next
            // event — another DATA frame or trailer — will release
            // it with the correct ``frame.end`` value.
            streaming.pendingFrame = body
            streamingScripts[streamID] = streaming
        }

        return output
    }

    /// Runs one buffered frame through the streaming-script chain and
    /// serializes the (possibly mutated) bytes as DATA frames.
    /// ``isLast`` is what the script sees on ``ctx.frame.end``;
    /// ``wireEndStream`` is the END_STREAM bit on the emitted DATA
    /// frame — the two diverge for the held frame released on
    /// trailer flush (``isLast=true`` so the script knows it's the
    /// last call, ``wireEndStream=false`` because the trailer
    /// HEADERS will carry END_STREAM on the wire).
    private func processStreamingFrame(
        streamID: UInt32,
        streaming: inout StreamingState,
        body: Data,
        isLast: Bool,
        wireEndStream: Bool
    ) -> Data {
        let emitted: Data
        if streaming.cursor.bypass {
            emitted = body
        } else {
            let ctx = MITMScriptEngine.FrameContext(
                phase: phase,
                method: streaming.originatingRequest?.method
                    ?? firstHeaderValue(streaming.headers, name: ":method"),
                url: streamingURL(streaming),
                status: parseStatus(streaming.headers),
                headers: streaming.headers.filter { !$0.name.hasPrefix(":") },
                frameIndex: streaming.frameIndex,
                isLast: isLast,
                ruleSetID: rewriter.ruleSetID
            )
            let result = MITMScriptTransform.applyFrame(
                body,
                rules: rewriter.rules(phase: phase),
                contentType: streaming.contentType,
                frameContext: ctx,
                cursor: streaming.cursor,
                engineProvider: rewriter.scriptEngineProvider
            )
            // Track cumulative wire-byte growth across the stream's
            // frames. The receiver's flow-control window was budgeted
            // for the original sender's bytes; any growth we add eats
            // unaccounted into that window. Once the *projected*
            // total would exceed the cap, both this frame and every
            // subsequent one fall back to the original payload — we
            // never emit a frame that would push us past the budget,
            // even partially.
            let growth = result.body.count - body.count
            let projected = streaming.cumulativeGrowth + growth
            if projected > Self.maxStreamingRewriteGrowthBytes {
                logger.warning("[MITM] HTTP/2 stream \(streamID): streamScript projected growth \(projected) B exceeded cap \(Self.maxStreamingRewriteGrowthBytes) B; bypassing this frame and remaining frames to avoid FLOW_CONTROL_ERROR")
                streaming.cursor.bypass = true
                emitted = body
            } else {
                streaming.cumulativeGrowth = projected
                emitted = result.body
            }
        }
        streaming.frameIndex += 1
        // Skip emitting an empty mid-stream DATA frame so that a script
        // returning `Data()` for a frame "swallows" it cleanly — same
        // semantics as the HTTP/1 chunked path, which simply doesn't
        // append a chunk on empty output. END_STREAM still has to land
        // somewhere though, so empty + endStream collapses to one
        // zero-length DATA frame carrying the flag.
        if emitted.isEmpty, !wireEndStream {
            return Data()
        }
        return emitDataFrames(streamID: streamID, payload: emitted, endStream: wireEndStream)
    }

    /// URL for the streaming script's ctx. On response phase the
    /// originating request's URL (from the request log) wins; on
    /// request phase we synthesize the URL using the connection's
    /// destination host so the script sees what the client requested,
    /// not the rewritten ``:authority`` an authority-rewrite rule may
    /// have substituted. Matches HTTP/1's behaviour (which uses the
    /// connection's ``host`` rather than the rewritten ``Host`` header)
    /// so a script written against ``ctx.url`` behaves the same on
    /// both protocols.
    private func streamingURL(_ streaming: StreamingState) -> String? {
        if phase == .httpResponse {
            return streaming.originatingRequest?.url
        }
        guard let path = firstHeaderValue(streaming.headers, name: ":path") else {
            return nil
        }
        return "https://\(rewriter.host)\(path)"
    }

    private func parseStatus(_ headers: [(name: String, value: String)]) -> Int? {
        guard phase == .httpResponse,
              let raw = firstHeaderValue(headers, name: ":status"),
              let code = Int(raw.trimmingCharacters(in: .whitespaces))
        else { return nil }
        return code
    }

    /// Emits the deferred HEADERS and the buffered body prefix without
    /// running scripts, then flips the pending message to ``abandoned``
    /// so subsequent DATA frames forward verbatim. Used when the body
    /// overflows the buffer cap mid-stream.
    private func abandonPending(streamID: UInt32, pending: inout PendingMessage) -> Data {
        // Inbound HEADERS need to be logged for the response side to
        // populate ctx.method/url even though scripts won't run.
        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: pending.headers)
        }
        let prefix = pending.data
        pending.data = Data()
        pending.abandoned = true
        let reencoded = HPACKEncoder.encodeHeaderBlock(pending.headers)
        var out = emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: false,
            kind: .headers
        )
        out.append(emitDataFrames(streamID: streamID, payload: prefix, endStream: false))
        pendingMessages[streamID] = pending
        return out
    }

    /// Emits the deferred HEADERS + buffered raw body without running
    /// scripts. Used by ``runScriptsAndFlush`` when decompression fails
    /// — the original ``content-encoding`` is still present on
    /// ``pending.headers`` so the receiver can decode the original
    /// payload itself. Inbound request HEADERS still need to land in
    /// the request log so the response-side ctx is populated.
    private func emitPassthroughDeferred(
        streamID: UInt32,
        pending: PendingMessage,
        endStream: Bool
    ) -> Data {
        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: pending.headers)
        }
        let reencoded = HPACKEncoder.encodeHeaderBlock(pending.headers)
        let body = pending.data
        let headersHaveEndStream = endStream && body.isEmpty
        var out = emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: headersHaveEndStream,
            kind: .headers
        )
        if !body.isEmpty {
            out.append(emitDataFrames(streamID: streamID, payload: body, endStream: endStream))
        }
        return out
    }

    /// Runs the script chain on the buffered message and emits the
    /// final HEADERS (with script mutations) plus the rewritten body
    /// as DATA frame(s). Removes the entry from ``pendingMessages`` so
    /// the stream is settled. Returns empty when no pending message
    /// exists, or when it was already abandoned.
    private func runScriptsAndFlush(streamID: UInt32, endStream: Bool) -> Data {
        guard let pending = pendingMessages.removeValue(forKey: streamID) else {
            return Data()
        }
        if pending.abandoned {
            return Data()
        }
        let plaintext: Data
        if pending.codec.requiresDecompression {
            // Decompression failure: skip scripts and emit the
            // deferred HEADERS + raw bytes verbatim so the receiver
            // can still decode the original payload. ``pending.headers``
            // still carries `content-encoding` because we no longer
            // strip it at deferral time. HTTP/1 takes the same
            // approach in ``applyScriptsAndEmit``.
            guard let decoded = MITMBodyCodec.decompress(pending.data, plan: pending.codec) else {
                return emitPassthroughDeferred(streamID: streamID, pending: pending, endStream: endStream)
            }
            plaintext = decoded
        } else {
            plaintext = pending.data
        }
        // On a successful decompression we're emitting identity, so
        // hide ``content-encoding`` from the script and from the
        // re-encoded header block. When the body wasn't compressed
        // there's nothing to hide.
        let scriptedHeaders: [(name: String, value: String)]
        if pending.codec.requiresDecompression {
            scriptedHeaders = pending.headers.filter { $0.name.lowercased() != "content-encoding" }
        } else {
            scriptedHeaders = pending.headers
        }
        let inputMessage = buildMessage(
            headers: scriptedHeaders,
            body: plaintext,
            originatingRequest: pending.originatingRequest
        )
        let outcome = rewriter.applyScripts(inputMessage, phase: phase)
        let result: MITMScriptEngine.Message
        switch outcome {
        case .message(let updated):
            result = updated
        case .synthesizedResponse(let response):
            // Request-phase short-circuit. Suppress upstream emission
            // for this stream entirely and queue the synthesized
            // HEADERS + DATA on the inbound leg's client-bound buffer.
            // The outer leg never saw a HEADERS for this stream so
            // there's nothing to RST.
            queueSynthesizedResponse(streamID: streamID, response: response)
            return Data()
        }

        // Flow-control safeguard. The wire-level body bytes the
        // original sender put on this stream were already budgeted by
        // its flow-control accounting; we can pass those through
        // safely. Any script-introduced *growth* is unaccounted: the
        // receiver decrements its window by what we send, not by what
        // the original sender intended, so a script that grows the
        // body past the default initial window risks a
        // FLOW_CONTROL_ERROR + connection-wide GOAWAY.
        //
        // The comparison baseline is the *decompressed* plaintext, not
        // the compressed wire bytes — decompression itself is not
        // "growth" from the script's perspective, and using
        // ``pending.data.count`` (compressed) as the baseline would
        // make every script with a non-trivial compression ratio
        // (typical gzip JSON is ~5×) trip the cap as a no-op and fall
        // back to passthrough. ``plaintext.count`` is what the script
        // saw on input; ``result.body.count`` is what it produced.
        // Their delta is the user-introduced wire-level growth, which
        // is the value the receiver's flow-control window cares about.
        let originalIdentityBytes = plaintext.count
        let rewrittenWireBytes = result.body.count
        if rewrittenWireBytes > originalIdentityBytes,
           rewrittenWireBytes - originalIdentityBytes > Self.maxBufferedRewriteGrowthBytes {
            logger.warning("[MITM] HTTP/2 stream \(streamID): script grew body by \(rewrittenWireBytes - originalIdentityBytes) B (cap \(Self.maxBufferedRewriteGrowthBytes) B = default initial window); emitting original payload to avoid FLOW_CONTROL_ERROR")
            return emitPassthroughDeferred(streamID: streamID, pending: pending, endStream: endStream)
        }

        // Re-build the HTTP/2 header block: pseudo-headers from the
        // (possibly script-mutated) method/url/status, regular headers
        // from result.headers (with any stale pseudo-headers stripped
        // in case the script touched them directly).
        let finalHeaders = rebuildHeaders(from: result, fallback: pending.headers)

        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: finalHeaders)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(finalHeaders)
        // RFC 9110 §15.2: a response to HEAD never carries a body even
        // when the same resource fetched with GET would. A script that
        // wrote into ctx.body would otherwise have us emit DATA frames
        // the client didn't expect — strict h2 clients ignore them, but
        // emitting them is still spec-violating and can confuse stream
        // accounting on the receiver. Drop the bytes here, matching
        // HTTP/1's emitScriptedHead carve-out.
        let isHeadResponse = phase == .httpResponse
            && pending.originatingRequest?.method.uppercased() == "HEAD"
        let body = isHeadResponse ? Data() : result.body
        // END_STREAM lands on either HEADERS (no body case) or the last
        // DATA frame (body case). HTTP/2 requires DATA to follow HEADERS
        // when there's a body; an empty body is fine on HEADERS alone.
        let headersHaveEndStream = endStream && body.isEmpty
        var out = emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: headersHaveEndStream,
            kind: .headers
        )
        if !body.isEmpty {
            out.append(emitDataFrames(streamID: streamID, payload: body, endStream: endStream))
        }
        return out
    }

    // MARK: - Deferral policy

    /// Decides whether a stream's HEADERS (and DATA, if any) should be
    /// deferred so the script chain can mutate the full message. The
    /// codec and content-length gates make the decision once at HEADERS
    /// time rather than rediscovered per-frame. Content-Type filtering
    /// happens earlier, on the rewriter side via
    /// ``MITMHTTP2Rewriter/hasScriptRule(phase:contentType:)``.
    ///
    /// An END_STREAM-on-HEADERS message has no DATA to buffer, so the
    /// content-length / codec gates don't apply — defer unconditionally
    /// so the script can still mutate head fields.
    private func shouldBufferStream(
        headers: [(name: String, value: String)],
        endStream: Bool
    ) -> Bool {
        if endStream { return true }
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

    /// HTTP/2's default initial flow-control window (RFC 9113 §6.9.2).
    /// A synthesized response body larger than this would overflow the
    /// client's window before any WINDOW_UPDATE could arrive — we don't
    /// track windows on the MITM path, so the conservative move is to
    /// cap the body. 64 KiB comfortably covers the common
    /// ``Anywhere.respond`` use cases (mocked JSON, redirect bodies,
    /// canned error pages) and matches the cap an unconfigured peer
    /// would enforce anyway.
    private static let maxSynthesizedResponseBodyBytes: Int = 65_535

    /// Per-stream cap on how many bytes a buffered ``.script`` rewrite
    /// may add to the original body before the rewrite is abandoned in
    /// favour of emitting the unmodified payload. Original bytes are
    /// already budgeted by the original sender's flow-control accounting
    /// — those can't trip ``FLOW_CONTROL_ERROR``. Extra bytes can, since
    /// the receiver's window decrements by what *we* send, not by what
    /// the original sender intended. Without per-stream window tracking
    /// in the MITM the safest cap is the spec-default initial window
    /// (RFC 9113 §6.9.2 = 65,535 B), so a single rewrite emission stays
    /// within one worst-case window's worth of unaccounted growth. A
    /// script that grows further falls back to the original payload via
    /// ``emitPassthroughDeferred`` rather than risking a GOAWAY that
    /// would tear down every other stream on the connection.
    private static let maxBufferedRewriteGrowthBytes: Int = 65_535

    /// Cumulative per-stream cap on the wire-byte growth a
    /// ``.streamScript`` may introduce before subsequent frames are
    /// bypassed. Same rationale as ``maxBufferedRewriteGrowthBytes``:
    /// the receiver's flow-control window only budgeted the original
    /// sender's wire bytes, so introduced growth eats into the window
    /// without any matching WINDOW_UPDATE we can observe. The cap is
    /// cumulative across frames on the same stream — a script that
    /// grows each of a hundred frames by 1 KB exhausts the budget just
    /// as surely as one that grows a single frame by 100 KB. When the
    /// cap trips, we flip ``FrameCursor.bypass`` so the rest of the
    /// stream forwards verbatim instead of risking a connection-level
    /// GOAWAY.
    private static let maxStreamingRewriteGrowthBytes: Int = 65_535

    /// Serializes a request-phase `Anywhere.respond(...)` payload as an
    /// HTTP/2 HEADERS (+ optional DATA) frame sequence ending with
    /// END_STREAM, and appends it to ``pendingClientBytes`` for the
    /// session pump to inject onto the inner TLS record. Inbound leg
    /// only — the outbound leg never reaches this path. ``:status`` is
    /// taken from ``response.status``; any pseudo-headers the script
    /// accidentally populated under ``headers`` are dropped so the
    /// HPACK encoder never emits duplicates. ``content-length`` is
    /// likewise dropped since END_STREAM is the source of truth in
    /// HTTP/2 and a user-supplied value would risk disagreeing with
    /// the actual body size.
    ///
    /// Header names are checked against RFC 9110 §5.6.2 (token chars
    /// only) and values against RFC 9113 §8.2.1 (no CR/LF/NUL). Entries
    /// that violate either are dropped with a warning so a malicious
    /// or accidental script can't desynchronise the HPACK decoder or
    /// inject extra header lines.
    private func queueSynthesizedResponse(
        streamID: UInt32,
        response: MITMScriptEngine.SynthesizedResponse
    ) {
        var headers: [(name: String, value: String)] = [
            (name: ":status", value: String(response.status))
        ]
        for entry in response.headers {
            let n = entry.name.lowercased()
            if n.hasPrefix(":") { continue }
            if n == "content-length" || n == "transfer-encoding" { continue }
            guard Self.isValidHeaderName(n),
                  Self.isValidHTTP2HeaderValue(entry.value)
            else {
                logger.warning("[MITM][JS] Anywhere.respond dropping invalid header: \(entry.name)")
                continue
            }
            // HTTP/2 forbids uppercase header names (RFC 9113 §8.2.1);
            // normalize defensively so a careless script can't blow up
            // the client's decoder.
            headers.append((name: n, value: entry.value))
        }
        let block = HPACKEncoder.encodeHeaderBlock(headers)

        let body: Data
        if response.body.count > Self.maxSynthesizedResponseBodyBytes {
            logger.warning("[MITM][JS] Anywhere.respond body \(response.body.count) B exceeds initial flow-control window; truncating to \(Self.maxSynthesizedResponseBodyBytes) B")
            let end = response.body.startIndex + Self.maxSynthesizedResponseBodyBytes
            body = response.body.subdata(in: response.body.startIndex..<end)
        } else {
            body = response.body
        }

        let endStreamOnHeaders = body.isEmpty
        var out = emitHeaderBlock(
            streamID: streamID,
            block: block,
            endStream: endStreamOnHeaders,
            kind: .headers
        )
        if !body.isEmpty {
            out.append(emitDataFrames(streamID: streamID, payload: body, endStream: true))
        }
        pendingClientBytes.append(out)
        // Record so follow-up frames from the client (trailers, DATA, or
        // the RST some clients send after consuming a response they
        // didn't expect to get on their own initiative) aren't forwarded
        // upstream on an idle stream. See ``handleFrame`` /
        // ``handleRSTStream``.
        markSynthResponded(streamID)
    }

    /// Inserts ``streamID`` into ``synthRespondedStreams`` and the
    /// matching FIFO. Evicts the oldest entry when the FIFO is at the
    /// cap so a long-lived connection that repeatedly synthesizes
    /// responses can't grow the set without bound. The eviction is
    /// best-effort — if a client happens to send a late RST_STREAM for
    /// the evicted ID it'll be forwarded to upstream as if from an
    /// idle stream and may trigger GOAWAY, but that risk is bounded by
    /// the cap and unlikely in practice (clients RST promptly or not
    /// at all).
    private func markSynthResponded(_ streamID: UInt32) {
        guard synthRespondedStreams.insert(streamID).inserted else { return }
        synthRespondedOrder.append(streamID)
        if synthRespondedOrder.count > Self.synthRespondedMaxStreams {
            let evicted = synthRespondedOrder.removeFirst()
            synthRespondedStreams.remove(evicted)
        }
    }

    /// Removes ``streamID`` from both ``synthRespondedStreams`` and the
    /// FIFO. Returns true iff the streamID was present — callers use
    /// the return value to gate frame swallowing (the set membership
    /// and the swallow decision are the same predicate).
    @discardableResult
    private func clearSynthResponded(_ streamID: UInt32) -> Bool {
        guard synthRespondedStreams.remove(streamID) != nil else { return false }
        if let idx = synthRespondedOrder.firstIndex(of: streamID) {
            synthRespondedOrder.remove(at: idx)
        }
        return true
    }

    /// RFC 9110 §5.6.2: header field-name is a `token` — one or more of
    /// `tchar` (alphanumerics plus a fixed punctuation set). Empty
    /// names are rejected. Used to gate user-supplied headers from
    /// ``Anywhere.respond`` before they reach the HPACK encoder.
    private static func isValidHeaderName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        for byte in name.utf8 {
            switch byte {
            case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x2A, 0x2B, 0x2D, 0x2E,
                 0x5E, 0x5F, 0x60, 0x7C, 0x7E:
                continue
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
                continue
            default:
                return false
            }
        }
        return true
    }

    /// HTTP/2 disallows CR, LF, and NUL in header field values (RFC
    /// 9113 §8.2.1). A scriptable inject path would otherwise let a
    /// careless or malicious script slip extra header lines into the
    /// re-encoded block via the decoder's string handling.
    private static func isValidHTTP2HeaderValue(_ value: String) -> Bool {
        for byte in value.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return false
            }
        }
        return true
    }

    // MARK: - Message build / header rebuild

    /// Builds the ``MITMScriptEngine/Message`` the script chain
    /// receives. HTTP/2 pseudo-headers (`:method`, `:authority`,
    /// `:path`, `:scheme`, `:status`) are stripped here and projected
    /// into the scalar `method` / `url` / `status` fields so the script
    /// sees only regular headers in `ctx.headers`. On response phase
    /// the originating request's method/url are looked up via
    /// ``MITMRequestLog``.
    private func buildMessage(
        headers: [(name: String, value: String)],
        body: Data,
        originatingRequest: MITMRequestLog.Record?
    ) -> MITMScriptEngine.Message {
        var method: String?
        var url: String?
        var status: Int?
        switch phase {
        case .httpRequest:
            method = firstHeaderValue(headers, name: ":method")
            if let path = firstHeaderValue(headers, name: ":path") {
                // Use the connection's destination host (the SNI/host
                // the client opened the leg with) rather than the
                // possibly-rewritten ``:authority``, so ``ctx.url``
                // mirrors what the client requested. HTTP/1 does the
                // same with its session-level ``host`` field, keeping
                // the two protocols' script semantics aligned.
                url = "https://\(rewriter.host)\(path)"
            }
        case .httpResponse:
            if let raw = firstHeaderValue(headers, name: ":status"),
               let code = Int(raw.trimmingCharacters(in: .whitespaces)) {
                status = code
            }
            method = originatingRequest?.method
            url = originatingRequest?.url
        }
        let regularHeaders = headers.filter { !$0.name.hasPrefix(":") }
        return MITMScriptEngine.Message(
            phase: phase,
            method: method,
            url: url,
            status: status,
            headers: regularHeaders,
            body: body,
            ruleSetID: rewriter.ruleSetID
        )
    }

    /// Re-assembles the wire header block from a (possibly mutated)
    /// message. Pseudo-headers are rebuilt from ``message`` fields; any
    /// pseudo-headers the script accidentally added to
    /// ``message.headers`` are dropped here so the HPACK encoder never
    /// emits duplicates. ``fallback`` supplies pseudo-header values
    /// the message lacks (e.g. ``:scheme`` on requests, original
    /// authority when the script cleared the URL).
    private func rebuildHeaders(
        from message: MITMScriptEngine.Message,
        fallback: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        var pseudos: [(name: String, value: String)] = []
        switch phase {
        case .httpRequest:
            let method = message.method ?? firstHeaderValue(fallback, name: ":method") ?? "GET"
            pseudos.append((name: ":method", value: method))
            let scheme = firstHeaderValue(fallback, name: ":scheme") ?? "https"
            pseudos.append((name: ":scheme", value: scheme))
            let authority: String
            let path: String
            if let url = message.url, let components = URLComponents(string: url) {
                authority = components.host.map { host in
                    if let port = components.port { return "\(host):\(port)" }
                    return host
                } ?? firstHeaderValue(fallback, name: ":authority") ?? rewriter.host
                // RFC 9113 §8.3.1: ``:path`` MUST start with ``/`` for
                // non-CONNECT, non-OPTIONS-asterisk requests. A script
                // that wrote a relative URL like ``api/foo`` would
                // otherwise produce ``:path: api/foo``, which strict
                // h2 stacks reject with PROTOCOL_ERROR + GOAWAY.
                var rawPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
                if !rawPath.hasPrefix("/") { rawPath = "/" + rawPath }
                path = components.percentEncodedQuery.map { "\(rawPath)?\($0)" } ?? rawPath
            } else {
                authority = firstHeaderValue(fallback, name: ":authority") ?? rewriter.host
                path = firstHeaderValue(fallback, name: ":path") ?? "/"
            }
            pseudos.append((name: ":authority", value: authority))
            pseudos.append((name: ":path", value: path))
        case .httpResponse:
            let status = message.status.map(String.init)
                ?? firstHeaderValue(fallback, name: ":status")
                ?? "200"
            pseudos.append((name: ":status", value: status))
        }
        let regular = message.headers.filter { !$0.name.hasPrefix(":") }
        return pseudos + regular
    }

    /// Records the in-flight request's method and absolute URL onto the
    /// shared request log so the outbound (response) leg can populate
    /// ctx.method / ctx.url. Inbound HEADERS only.
    private func logHTTP2Request(streamID: UInt32, headers: [(name: String, value: String)]) {
        guard direction == .inbound else { return }
        let method = firstHeaderValue(headers, name: ":method")
        var url: String?
        if let path = firstHeaderValue(headers, name: ":path") {
            // Use the connection's destination host so the recorded
            // URL — surfaced as ``ctx.url`` on response-phase scripts —
            // matches what request-phase scripts saw and what HTTP/1
            // records. Authority-rewrite rules change ``:authority``
            // on the wire, but the script-facing URL should remain the
            // client's original target for consistency across protocols.
            url = "https://\(rewriter.host)\(path)"
        }
        rewriter.requestLog.recordHTTP2(streamID: streamID, method: method, url: url)
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
        if length > Self.maxReceivedFramePayloadSize {
            logger.warning("[MITM] HTTP/2: frame length \(length) B exceeded receive cap \(Self.maxReceivedFramePayloadSize); breaking connection state")
            parseError = true
            buffer.removeAll(keepingCapacity: false)
            return nil
        }
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

    /// Emits one or more DATA frames whose payloads each fit within
    /// ``maxFramePayloadSize``. END_STREAM lands on the last frame only.
    /// An empty input still emits a single empty DATA frame so any
    /// END_STREAM signal survives.
    private func emitDataFrames(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        if payload.isEmpty {
            var flags: UInt8 = 0
            if endStream { flags |= 0x1 }
            return serializeFrame(RawFrame(
                typeCode: FrameTypeCode.data,
                flags: flags,
                streamID: streamID,
                payload: Data()
            ))
        }
        var output = Data()
        var offset = payload.startIndex
        while offset < payload.endIndex {
            let end = min(payload.endIndex, offset + Self.maxFramePayloadSize)
            let isLast = end == payload.endIndex
            var flags: UInt8 = 0
            if isLast && endStream { flags |= 0x1 }
            output.append(serializeFrame(RawFrame(
                typeCode: FrameTypeCode.data,
                flags: flags,
                streamID: streamID,
                payload: payload.subdata(in: offset..<end)
            )))
            offset = end
        }
        return output
    }

    /// Emits a HEADERS or PUSH_PROMISE frame, followed by CONTINUATION
    /// frames when the encoded block does not fit in a single frame
    /// (RFC 9113 §6.2 / §6.10). PUSH_PROMISE's 4-byte Promised Stream ID
    /// prefix counts towards the first frame's payload, so the initial
    /// chunk is sized accordingly. END_HEADERS lands on the final emitted
    /// frame; END_STREAM stays on the initial frame.
    private func emitHeaderBlock(
        streamID: UInt32,
        block: Data,
        endStream: Bool,
        kind: PendingHeaders.Kind
    ) -> Data {
        let firstType: UInt8
        var firstPayload: Data
        switch kind {
        case .headers:
            firstType = FrameTypeCode.headers
            firstPayload = Data()
        case .pushPromise(let promisedStreamID):
            firstType = FrameTypeCode.pushPromise
            let p = promisedStreamID & 0x7FFFFFFF
            firstPayload = Data(capacity: 4)
            firstPayload.append(UInt8((p >> 24) & 0xFF))
            firstPayload.append(UInt8((p >> 16) & 0xFF))
            firstPayload.append(UInt8((p >> 8) & 0xFF))
            firstPayload.append(UInt8(p & 0xFF))
        }

        let firstChunkSize = min(block.count, Self.maxFramePayloadSize - firstPayload.count)
        let firstChunkEnd = block.startIndex + firstChunkSize
        firstPayload.append(block.subdata(in: block.startIndex..<firstChunkEnd))
        let needsContinuation = firstChunkEnd < block.endIndex

        var firstFlags: UInt8 = 0
        if !needsContinuation { firstFlags |= 0x4 }  // END_HEADERS
        if endStream { firstFlags |= 0x1 }           // END_STREAM

        var output = Data()
        output.append(serializeFrame(RawFrame(
            typeCode: firstType,
            flags: firstFlags,
            streamID: streamID,
            payload: firstPayload
        )))

        var offset = firstChunkEnd
        while offset < block.endIndex {
            let end = min(block.endIndex, offset + Self.maxFramePayloadSize)
            let isLast = end == block.endIndex
            let flags: UInt8 = isLast ? 0x4 : 0
            output.append(serializeFrame(RawFrame(
                typeCode: FrameTypeCode.continuation,
                flags: flags,
                streamID: streamID,
                payload: block.subdata(in: offset..<end)
            )))
            offset = end
        }
        return output
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
