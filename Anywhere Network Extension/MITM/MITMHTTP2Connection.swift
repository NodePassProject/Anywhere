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

    /// HTTP/2's mandated minimum ``SETTINGS_MAX_FRAME_SIZE`` (RFC 9113 §6.5.2).
    private static let maxFramePayloadSize = 16_384

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
    }
    private var streamingScripts: [UInt32: StreamingState] = [:]

    /// Bytes synthesized by request-phase scripts that called
    /// `Anywhere.respond(...)` and need to be written straight back to
    /// the client (i.e. injected onto the inner TLS record). Populated
    /// on the inbound leg only; the outbound leg never touches it.
    /// Drained by the session pump via ``drainPendingClientBytes()``
    /// immediately after each ``process(_:)`` call.
    private var pendingClientBytes = Data()

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
        if case .headers = kind, !isTrailer, !isInterimResponse,
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
            if !endStreamOnHeaders {
                streamingScripts[streamID] = StreamingState(
                    headers: rewritten,
                    contentType: contentType,
                    originatingRequest: originatingRequest,
                    cursor: MITMScriptTransform.FrameCursor()
                )
            }

            let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten)
            output.append(emitHeaderBlock(
                streamID: streamID,
                block: reencoded,
                endStream: endStreamOnHeaders,
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
    /// a trailer HEADERS frame rather than on a DATA frame. Calls the
    /// script chain one last time with an empty body and
    /// ``frame.end = true`` so the script can flush whatever
    /// per-stream state it has accumulated, then drops the entry from
    /// ``streamingScripts``. Non-empty script output is emitted as a
    /// DATA frame without END_STREAM (the trailer carries it).
    private func flushStreamingScript(streamID: UInt32) -> Data {
        guard let streaming = streamingScripts.removeValue(forKey: streamID) else {
            return Data()
        }
        if streaming.cursor.bypass {
            return Data()
        }
        var working = streaming
        let ctx = MITMScriptEngine.FrameContext(
            phase: phase,
            method: working.originatingRequest?.method
                ?? firstHeaderValue(working.headers, name: ":method"),
            url: streamingURL(working),
            status: parseStatus(working.headers),
            headers: working.headers.filter { !$0.name.hasPrefix(":") },
            frameIndex: working.frameIndex,
            isLast: true,
            ruleSetID: rewriter.ruleSetID
        )
        let result = MITMScriptTransform.applyFrame(
            Data(),
            rules: rewriter.rules(phase: phase),
            contentType: working.contentType,
            frameContext: ctx,
            cursor: working.cursor,
            engineProvider: rewriter.scriptEngineProvider
        )
        working.frameIndex += 1
        if result.body.isEmpty {
            return Data()
        }
        return emitDataFrames(streamID: streamID, payload: result.body, endStream: false)
    }

    /// Streaming-script path. Runs the script chain on one DATA
    /// frame's payload and emits the (possibly mutated) bytes as a
    /// single DATA frame. ``Anywhere.done`` / ``Anywhere.exit`` flip
    /// the cursor's ``bypass`` flag so subsequent frames on the stream
    /// pass through unchanged. The streaming entry is cleared on
    /// END_STREAM regardless of bypass state so a follow-up message
    /// on the same stream ID (rare under HTTP/2 stream-ID rules but
    /// possible with PUSH_PROMISE) gets a fresh cursor.
    private func handleStreamingData(
        streamID: UInt32,
        streaming: inout StreamingState,
        body: Data,
        endStream: Bool
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
                isLast: endStream,
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
            emitted = result.body
        }
        streaming.frameIndex += 1
        if endStream {
            streamingScripts.removeValue(forKey: streamID)
        } else {
            streamingScripts[streamID] = streaming
        }
        return emitDataFrames(streamID: streamID, payload: emitted, endStream: endStream)
    }

    /// URL for the streaming script's ctx. On response phase the
    /// originating request's URL (from the request log) wins; on
    /// request phase we synthesize from the pseudo-headers the
    /// rewriter already emitted.
    private func streamingURL(_ streaming: StreamingState) -> String? {
        if phase == .httpResponse {
            return streaming.originatingRequest?.url
        }
        guard let path = firstHeaderValue(streaming.headers, name: ":path") else {
            return nil
        }
        let authority = firstHeaderValue(streaming.headers, name: ":authority") ?? rewriter.host
        return "https://\(authority)\(path)"
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

        // Re-build the HTTP/2 header block: pseudo-headers from the
        // (possibly script-mutated) method/url/status, regular headers
        // from result.headers (with any stale pseudo-headers stripped
        // in case the script touched them directly).
        let finalHeaders = rebuildHeaders(from: result, fallback: pending.headers)

        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: finalHeaders)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(finalHeaders)
        let body = result.body
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
            // HTTP/2 forbids uppercase header names (RFC 9113 §8.2.1);
            // normalize defensively so a careless script can't blow up
            // the client's decoder.
            headers.append((name: n, value: entry.value))
        }
        let block = HPACKEncoder.encodeHeaderBlock(headers)
        let body = response.body
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
                let authority = firstHeaderValue(headers, name: ":authority") ?? rewriter.host
                url = "https://\(authority)\(path)"
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
                let rawPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
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
            let authority = firstHeaderValue(headers, name: ":authority") ?? rewriter.host
            url = "https://\(authority)\(path)"
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
