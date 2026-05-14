//
//  MITMHTTP1Stream.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// One direction of an HTTP/1.x byte stream traversing the MITM. Owns
/// the message-framing state machine (parse head -> forward or rewrite
/// body -> next message) and the chunked-encoding decoder. The caller
/// passes raw plaintext bytes via ``transform(_:)`` and receives the
/// rewritten plaintext for the opposite TLS leg.
///
/// One instance per direction. ``MITMSession`` constructs two of them
/// (request, response). They share ``policy`` but never share state.
///
/// If the stream cannot be parsed safely, it permanently downgrades to
/// passthrough so the underlying connection stays usable even when MITM
/// rewrites cannot apply.
final class MITMHTTP1Stream {

    private let host: String
    private let phase: MITMPhase
    private let policy: MITMRewritePolicy
    /// When set, every request's `Host:` header is rewritten to this value
    /// so the upstream sees a consistent authority. Driven by the rule set's
    /// ``rewriteTarget``; nil means "leave Host alone". Used only on request
    /// streams; response streams pass nil.
    private let effectiveAuthority: String?
    /// Lazy JS runtime, shared across both directions of the same MITM
    /// session. Touched only when a script rule fires.
    private let scriptEngineProvider: MITMScriptEngine.Provider
    /// Cross-direction request bookkeeping. The request stream records
    /// the (post-rewrite) method/URL as each request goes upstream; the
    /// response stream pops it to populate the script ctx's
    /// `method`/`url` fields on response phase.
    private let requestLog: MITMRequestLog

    init(
        host: String,
        phase: MITMPhase,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?,
        scriptEngineProvider: MITMScriptEngine.Provider,
        requestLog: MITMRequestLog
    ) {
        self.host = host
        self.phase = phase
        self.policy = policy
        self.effectiveAuthority = effectiveAuthority
        self.scriptEngineProvider = scriptEngineProvider
        self.requestLog = requestLog
    }

    // MARK: - State

    /// Snapshot of the rewritten head (start line + headers) plus the
    /// originating request context (looked up from ``MITMRequestLog`` on
    /// response phase). Saved when we decide to defer head emission so
    /// the body-completion path can rebuild the final head from script
    /// mutations.
    private struct PendingHead {
        let startLine: String
        let headers: [Header]
        /// Pre-decompression `Content-Encoding` plan. We emit identity
        /// after decompressing, so the outbound head also drops
        /// `Content-Encoding`.
        let codec: MITMBodyCodec.Plan
        /// Originating request's method/url for response-phase ctx.
        /// Nil on request phase (the request stream itself sources these
        /// from the start line).
        let originatingRequest: MITMRequestLog.Record?
    }

    /// Streaming-script state for HTTP/1 chunked bodies. Set once at
    /// head time when a ``streamScript`` rule matches; threaded through
    /// the chunked-streaming mode along with a one-chunk lookahead so
    /// the last chunk before the terminator can be marked
    /// ``frame.end = true``.
    private struct StreamingState {
        let headers: [Header]
        let contentType: String?
        let originatingRequest: MITMRequestLog.Record?
        let startLine: String
        var frameIndex: Int = 0
        /// Holds the most recently completed chunk's bytes; we don't
        /// emit it until we know whether the next chunk exists (and
        /// thus whether the held chunk was the last one). nil before
        /// any chunk has completed.
        var pendingChunk: Data? = nil
        let cursor: MITMScriptTransform.FrameCursor
    }

    private enum StreamingChunkedInner {
        case sizeLine
        case chunkData(remaining: Int, accumulator: Data)
        case dataCRLF
        /// After the zero-size size line. Drain any trailer-section
        /// lines from ``rxBuffer`` until the empty-line terminator so
        /// the connection returns to a clean head-parsing state on
        /// keep-alive.
        case trailerOrEnd
    }

    private enum Mode {
        /// Buffering the next message's head. The accumulator lives in
        /// ``rxBuffer`` until CRLF CRLF is seen.
        case awaitingHead

        /// Header rewrite already emitted; pass body bytes through
        /// unchanged. Used when no script rule applies, or when the
        /// body is opaque-encoded.
        case forwardingLength(remaining: Int)
        case forwardingChunked(reader: ChunkedReader)

        /// Buffering the body to rewrite it. The head is withheld
        /// (saved in ``pending``) until the body completes so the
        /// script chain can mutate it before we serialize.
        case rewritingLength(pending: PendingHead, expected: Int, accumulator: Data)
        case rewritingChunked(pending: PendingHead, accumulator: Data, reader: ChunkedReader)

        /// Reached when a chunked body has overflowed
        /// ``MITMBodyCodec/maxBufferedBodyBytes`` mid-rewrite. The
        /// head + truncated rewritten body have already been emitted;
        /// the remaining wire chunks are parsed and discarded so the
        /// connection returns to ``awaitingHead`` cleanly.
        case discardingChunked(reader: ChunkedReader)

        /// Per-chunk streaming-script mode. The head is already
        /// emitted; chunks flow through the script chain one at a
        /// time. A one-chunk lookahead in ``streaming.pendingChunk``
        /// lets us mark the final chunk before the terminator with
        /// ``frame.end = true``.
        case streamingChunked(streaming: StreamingState, inner: StreamingChunkedInner)

        /// Permanent: forward bytes verbatim. Reached on protocol
        /// upgrades (101), CONNECT-style tunnels, or any framing error.
        case passthrough
    }

    private var mode: Mode = .awaitingHead
    private var rxBuffer = Data()

    /// Bytes the request stream has synthesized in response to a
    /// `Anywhere.respond(...)` call and wants written straight back to
    /// the client (i.e. injected onto the inner TLS record). Request
    /// phase only; response streams never populate this. Drained by the
    /// session pump via ``drainPendingClientBytes()`` immediately after
    /// each ``transform(_:)`` call.
    private var pendingClientBytes = Data()

    // MARK: - Public API

    func transform(_ data: Data) -> Data {
        if case .passthrough = mode {
            return data
        }
        rxBuffer.append(data)
        var output = Data()
        // Each iteration consumes from rxBuffer or returns when more
        // bytes are needed.
        while drive(into: &output) { }
        return output
    }

    /// Drains and returns any client-bound bytes synthesized by
    /// request-phase scripts that called `Anywhere.respond(...)` since
    /// the last call. The session pump writes these directly to the
    /// inner TLS record, bypassing the upstream leg entirely.
    func drainPendingClientBytes() -> Data {
        let bytes = pendingClientBytes
        pendingClientBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    // MARK: - Driver

    /// Returns true when state advanced and the loop should run again.
    private func drive(into output: inout Data) -> Bool {
        // Modes with mutable associated state are written back before inout
        // calls to avoid overlapping access to ``mode``.
        switch mode {
        case .passthrough:
            output.append(rxBuffer)
            rxBuffer.removeAll(keepingCapacity: false)
            return false

        case .awaitingHead:
            return consumeHead(into: &output)

        case .forwardingLength(let remaining):
            return forwardLength(remaining: remaining, into: &output)

        case .forwardingChunked(var reader):
            mode = .forwardingChunked(reader: reader)
            return forwardChunked(reader: &reader, into: &output)

        case .rewritingLength(let pending, let expected, var accumulator):
            mode = .rewritingLength(pending: pending, expected: expected, accumulator: accumulator)
            return rewriteLength(pending: pending, expected: expected, accumulator: &accumulator, into: &output)

        case .rewritingChunked(let pending, var accumulator, var reader):
            mode = .rewritingChunked(pending: pending, accumulator: accumulator, reader: reader)
            return rewriteChunked(pending: pending, accumulator: &accumulator, reader: &reader, into: &output)

        case .discardingChunked(var reader):
            mode = .discardingChunked(reader: reader)
            return discardChunked(reader: &reader)

        case .streamingChunked(var streaming, let inner):
            mode = .streamingChunked(streaming: streaming, inner: inner)
            return driveStreamingChunked(streaming: &streaming, inner: inner, into: &output)
        }
    }

    // MARK: - Head consumption

    /// Finds CRLF CRLF in ``rxBuffer``. When found, parses the head,
    /// applies header rewrites, decides on body framing, and either:
    ///   - emits the rewritten head and switches to forwarding mode, or
    ///   - withholds the head (saved in mode) and switches to rewrite
    ///     mode so script mutations can be applied after the body is
    ///     buffered, or
    ///   - for no-body framings with scripts, runs scripts on an empty
    ///     body and emits the (possibly mutated) head inline.
    private func consumeHead(into output: inout Data) -> Bool {
        guard let terminator = rxBuffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) else {
            return false
        }
        let headEnd = terminator.upperBound
        let headData = rxBuffer.subdata(in: rxBuffer.startIndex..<headEnd)
        rxBuffer.removeSubrange(rxBuffer.startIndex..<headEnd)

        guard let parsed = parseHead(headData) else {
            // If the head is not HTTP/1.x, stop rewriting and forward the
            // remaining bytes verbatim.
            mode = .passthrough
            output.append(headData)
            return true
        }

        // Apply rewrite rules. URL rules touch the request-target on the
        // start line (request phase only); header rules touch the
        // header block. Content-Length is recomputed below if scripts
        // run.
        //
        // Auto Host rewrite runs first so configured headerReplace rules
        // see the canonical post-redirect Host and can still override
        // it.
        let rewrittenStartLine = applyURLRules(parsed.startLine)
        let withAuthority = applyAuthorityRewrite(parsed.headers)
        let rewrittenHeaders = applyHeaderRules(withAuthority)
        let framing = bodyFraming(startLine: rewrittenStartLine, headers: rewrittenHeaders)

        // On the response side, every well-formed final message
        // corresponds to one request previously pushed by the request
        // stream. Pop the matching record here — once per final
        // response head, before any framing dispatch — so the FIFO
        // never drifts even when the response is passthrough or no
        // scripts fire.
        //
        // Interim responses (1xx other than 101) are not the final
        // response: more headers follow on the same request. They
        // peek instead of pop so the matching record stays available
        // for the final response.
        let originatingRequest: MITMRequestLog.Record?
        if phase == .httpResponse {
            if isInterimResponseStartLine(rewrittenStartLine) {
                originatingRequest = requestLog.peekHTTP1()
            } else {
                originatingRequest = requestLog.popHTTP1()
            }
        } else {
            originatingRequest = nil
        }

        // Protocol upgrades and "read until close" responses can't be
        // safely re-framed, so emit the rewritten head and downgrade.
        switch framing {
        case .switchingProtocols, .readUntilClose:
            // Request side records the outgoing request even though
            // scripts can't run, so the response leg can still look up
            // method/url on subsequent messages.
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            mode = .passthrough
            return true
        case .none, .contentLength, .chunked:
            break
        }

        let contentType = firstHeaderValue(rewrittenHeaders, name: "content-type")
        let rules = policy.rules(for: host, phase: phase)
        let scriptsApply = MITMScriptTransform.hasScriptRule(in: rules, contentType: contentType)

        switch framing {
        case .none:
            // Interim 1xx responses (100 Continue, 103 Early Hints, …)
            // MUST NOT carry a body or framing headers (RFC 9110 §15.2);
            // running scripts on them would let a no-op default-filter
            // script fabricate `Content-Length: 0` and break the
            // exchange. The matching final response will pop the
            // request log and run scripts itself. HTTP/2 takes the
            // same stance.
            let runScripts = scriptsApply && !isInterimResponseStartLine(rewrittenStartLine)
            if runScripts {
                let message = buildMessage(
                    startLine: rewrittenStartLine,
                    headers: rewrittenHeaders,
                    body: Data(),
                    originatingRequest: originatingRequest
                )
                let outcome = MITMScriptTransform.apply(
                    message,
                    rules: rules,
                    engineProvider: scriptEngineProvider
                )
                switch outcome {
                case .message(let result):
                    emitScriptedHead(
                        fallbackStartLine: rewrittenStartLine,
                        result: result,
                        codecRequiresDecompression: false,
                        into: &output
                    )
                case .synthesizedResponse(let response):
                    queueSynthesizedResponse(response)
                }
            } else {
                if phase == .httpRequest {
                    logRequest(startLine: rewrittenStartLine)
                }
                output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            }
            mode = .awaitingHead
            return true
        case .contentLength(let length):
            return enterContentLength(
                rewrittenStartLine: rewrittenStartLine,
                rewrittenHeaders: rewrittenHeaders,
                length: length,
                scriptsApply: scriptsApply,
                rules: rules,
                originatingRequest: originatingRequest,
                into: &output
            )
        case .chunked:
            return enterChunked(
                rewrittenStartLine: rewrittenStartLine,
                rewrittenHeaders: rewrittenHeaders,
                scriptsApply: scriptsApply,
                rules: rules,
                originatingRequest: originatingRequest,
                into: &output
            )
        case .readUntilClose, .switchingProtocols:
            preconditionFailure("handled above")
        }
    }

    private func enterContentLength(
        rewrittenStartLine: String,
        rewrittenHeaders: [Header],
        length: Int,
        scriptsApply: Bool,
        rules: [CompiledMITMRule],
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        // Stream scripts can't safely modify a length-prefixed body —
        // the head has already committed to a byte count we can't
        // change. Warn and fall through to either buffered-script or
        // passthrough.
        let contentType = firstHeaderValue(rewrittenHeaders, name: "content-type")
        if MITMScriptTransform.hasStreamScriptRule(in: rules, contentType: contentType) {
            logger.warning("[MITM] HTTP/1 \(host): streamScript skipped for Content-Length body (chunked encoding required)")
        }

        // The length is known up front, so we can opt out of buffering
        // before consuming a single body byte when the response would
        // exceed the cap. This keeps huge downloads (videos, archives)
        // from ever reaching the accumulator.
        let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewrittenHeaders, name: "content-encoding"))
        let canRewrite = scriptsApply && codec.supported && length <= MITMBodyCodec.maxBufferedBodyBytes

        if canRewrite {
            mode = .rewritingLength(
                pending: PendingHead(
                    startLine: rewrittenStartLine,
                    headers: rewrittenHeaders,
                    codec: codec,
                    originatingRequest: originatingRequest
                ),
                expected: length,
                accumulator: Data()
            )
            return true
        }
        if scriptsApply, length > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] Skipping script rewrite for \(host): Content-Length \(length) exceeds cap \(MITMBodyCodec.maxBufferedBodyBytes)")
        }
        if phase == .httpRequest {
            logRequest(startLine: rewrittenStartLine)
        }
        output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
        mode = .forwardingLength(remaining: length)
        return true
    }

    private func enterChunked(
        rewrittenStartLine: String,
        rewrittenHeaders: [Header],
        scriptsApply: Bool,
        rules: [CompiledMITMRule],
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        let contentType = firstHeaderValue(rewrittenHeaders, name: "content-type")

        // Streaming-script wins over buffered-script. Emit head
        // immediately and switch to per-chunk script mode. Stream
        // scripts can't mutate head fields, so head emission is
        // straightforward here.
        if MITMScriptTransform.hasStreamScriptRule(in: rules, contentType: contentType) {
            if scriptsApply {
                logger.warning("[MITM] HTTP/1 \(host): streamScript wins over script on the same Content-Type")
            }
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            let streaming = StreamingState(
                headers: rewrittenHeaders,
                contentType: contentType,
                originatingRequest: originatingRequest,
                startLine: rewrittenStartLine,
                cursor: MITMScriptTransform.FrameCursor()
            )
            mode = .streamingChunked(streaming: streaming, inner: .sizeLine)
            return true
        }

        let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewrittenHeaders, name: "content-encoding"))
        if scriptsApply, codec.supported {
            mode = .rewritingChunked(
                pending: PendingHead(
                    startLine: rewrittenStartLine,
                    headers: rewrittenHeaders,
                    codec: codec,
                    originatingRequest: originatingRequest
                ),
                accumulator: Data(),
                reader: ChunkedReader()
            )
            return true
        }
        if phase == .httpRequest {
            logRequest(startLine: rewrittenStartLine)
        }
        output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
        mode = .forwardingChunked(reader: ChunkedReader())
        return true
    }

    // MARK: - Body forwarding (no rewrite)

    private func forwardLength(remaining: Int, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let take = min(remaining, rxBuffer.count)
        let slice = rxBuffer.prefix(take)
        output.append(slice)
        rxBuffer.removeFirst(take)
        let left = remaining - take
        if left == 0 {
            mode = .awaitingHead
        } else {
            mode = .forwardingLength(remaining: left)
        }
        return true
    }

    private func forwardChunked(reader: inout ChunkedReader, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let result = reader.consumeForward(&rxBuffer, into: &output)
        switch result {
        case .needMore:
            mode = .forwardingChunked(reader: reader)
            return false
        case .complete:
            mode = .awaitingHead
            return true
        case .malformed:
            // Forward remaining bytes verbatim; the peer will detect the
            // framing error.
            mode = .passthrough
            return true
        }
    }

    // MARK: - Body rewriting

    private func rewriteLength(
        pending: PendingHead,
        expected: Int,
        accumulator: inout Data,
        into output: inout Data
    ) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let needed = expected - accumulator.count
        let take = min(needed, rxBuffer.count)
        accumulator.append(rxBuffer.prefix(take))
        rxBuffer.removeFirst(take)
        if accumulator.count == expected {
            applyScriptsAndEmit(pending: pending, rawBody: accumulator, originalSizes: nil, into: &output)
            mode = .awaitingHead
            return true
        }
        mode = .rewritingLength(pending: pending, expected: expected, accumulator: accumulator)
        return false
    }

    private func rewriteChunked(
        pending: PendingHead,
        accumulator: inout Data,
        reader: inout ChunkedReader,
        into output: inout Data
    ) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let result = reader.consumeBuffered(&rxBuffer, into: &accumulator)
        switch result {
        case .needMore:
            // Chunked bodies have no up-front length, so the cap can
            // only be enforced as bytes flow in. On overflow we apply
            // rules to the partial buffer, emit it, and drain the rest.
            // Lossy, but the alternative — refusing to rewrite chunked
            // bodies entirely — would silently break common APIs whose
            // bodies are well under the cap.
            if accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                logger.warning("[MITM] Chunked body for \(host) exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes); truncating")
                applyScriptsAndEmit(pending: pending, rawBody: accumulator, originalSizes: [accumulator.count], into: &output)
                mode = .discardingChunked(reader: reader)
                return true
            }
            mode = .rewritingChunked(pending: pending, accumulator: accumulator, reader: reader)
            return false
        case .complete(let originalSizes):
            applyScriptsAndEmit(pending: pending, rawBody: accumulator, originalSizes: originalSizes, into: &output)
            mode = .awaitingHead
            return true
        case .malformed:
            mode = .passthrough
            return true
        }
    }

    /// Parses chunked-transfer encoding with a one-chunk lookahead so
    /// each chunk can be handed to the streaming-script chain before
    /// emission. The head was already emitted at ``enterChunked``
    /// time; this loop pulls one chunk at a time off ``rxBuffer``,
    /// holds it in ``streaming.pendingChunk`` until the next size line
    /// tells us whether it was the final chunk, and emits each chunk
    /// as its own chunked-transfer chunk on the way out. When the
    /// zero-size terminator arrives, the held chunk is emitted with
    /// ``frame.end = true`` (or, for an empty body, the script gets a
    /// single isLast=true call against an empty body for cleanup).
    private func driveStreamingChunked(
        streaming: inout StreamingState,
        inner startInner: StreamingChunkedInner,
        into output: inout Data
    ) -> Bool {
        var currentInner = startInner
        while true {
            switch currentInner {
            case .sizeLine:
                guard let lineEnd = Self.findCRLF(in: rxBuffer) else {
                    mode = .streamingChunked(streaming: streaming, inner: .sizeLine)
                    return false
                }
                let line = rxBuffer.subdata(in: rxBuffer.startIndex..<lineEnd)
                rxBuffer.removeSubrange(rxBuffer.startIndex..<(lineEnd + 2))
                guard let size = Self.parseHexSize(line) else {
                    mode = .passthrough
                    return true
                }
                if size == 0 {
                    // End of body. Emit the held chunk (or a single
                    // empty-body flush call) with isLast=true, then
                    // emit the zero-size size line on the wire. The
                    // trailer-section bytes (zero or more field-lines
                    // plus the empty CRLF terminator) still live in
                    // ``rxBuffer`` and are drained in ``.trailerOrEnd``
                    // — we must consume them, otherwise a keep-alive
                    // connection's next message starts mid-trailer and
                    // fails to parse.
                    let finalChunk = streaming.pendingChunk ?? Data()
                    streaming.pendingChunk = nil
                    emitStreamingChunk(
                        streaming: &streaming,
                        chunk: finalChunk,
                        isLast: true,
                        into: &output
                    )
                    output.append(contentsOf: "0\r\n".utf8)
                    currentInner = .trailerOrEnd
                } else {
                    currentInner = .chunkData(remaining: size, accumulator: Data())
                }
            case .chunkData(let remaining, var accumulator):
                guard !rxBuffer.isEmpty else {
                    mode = .streamingChunked(
                        streaming: streaming,
                        inner: .chunkData(remaining: remaining, accumulator: accumulator)
                    )
                    return false
                }
                let take = min(remaining, rxBuffer.count)
                accumulator.append(rxBuffer.prefix(take))
                rxBuffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    // Chunk is complete. Flush the previous held chunk
                    // (with isLast=false now that we know more chunks
                    // follow), then hold this one.
                    if let held = streaming.pendingChunk {
                        emitStreamingChunk(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            into: &output
                        )
                    }
                    streaming.pendingChunk = accumulator
                    currentInner = .dataCRLF
                } else {
                    mode = .streamingChunked(
                        streaming: streaming,
                        inner: .chunkData(remaining: left, accumulator: accumulator)
                    )
                    return false
                }
            case .dataCRLF:
                guard rxBuffer.count >= 2 else {
                    mode = .streamingChunked(streaming: streaming, inner: .dataCRLF)
                    return false
                }
                guard rxBuffer[rxBuffer.startIndex] == 0x0D,
                      rxBuffer[rxBuffer.startIndex + 1] == 0x0A
                else {
                    mode = .passthrough
                    return true
                }
                rxBuffer.removeFirst(2)
                currentInner = .sizeLine
            case .trailerOrEnd:
                // RFC 9112 §7.1.2: trailer-section is zero or more
                // field-lines terminated by an empty line. Forward each
                // line verbatim (we don't rewrite trailers) and stop
                // once we hit the empty terminator.
                guard let lineEnd = Self.findCRLF(in: rxBuffer) else {
                    mode = .streamingChunked(streaming: streaming, inner: .trailerOrEnd)
                    return false
                }
                let line = rxBuffer.subdata(in: rxBuffer.startIndex..<lineEnd)
                rxBuffer.removeSubrange(rxBuffer.startIndex..<(lineEnd + 2))
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                if line.isEmpty {
                    mode = .awaitingHead
                    return true
                }
            }
        }
    }

    /// Runs the streaming-script chain on ``chunk`` and appends the
    /// result as a chunked-transfer chunk to ``output``. Empty results
    /// are dropped (no zero-size chunk emitted mid-stream — the
    /// terminator reserves that). ``cursor.bypass`` short-circuits the
    /// script chain so subsequent chunks pass through unchanged.
    private func emitStreamingChunk(
        streaming: inout StreamingState,
        chunk: Data,
        isLast: Bool,
        into output: inout Data
    ) {
        let body: Data
        if streaming.cursor.bypass {
            body = chunk
        } else {
            let frameCtx = MITMScriptEngine.FrameContext(
                phase: phase,
                method: streamingMethod(streaming),
                url: streamingURL(streaming),
                status: streamingStatus(streaming),
                headers: streaming.headers,
                frameIndex: streaming.frameIndex,
                isLast: isLast,
                ruleSetID: policy.set(for: host)?.id
            )
            let result = MITMScriptTransform.applyFrame(
                chunk,
                rules: policy.rules(for: host, phase: phase),
                contentType: streaming.contentType,
                frameContext: frameCtx,
                cursor: streaming.cursor,
                engineProvider: scriptEngineProvider
            )
            body = result.body
        }
        streaming.frameIndex += 1
        if !body.isEmpty {
            appendChunk(body, into: &output)
        }
    }

    private func streamingMethod(_ streaming: StreamingState) -> String? {
        switch phase {
        case .httpRequest:
            let parts = streaming.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            return parts.first.map(String.init)
        case .httpResponse:
            return streaming.originatingRequest?.method
        }
    }

    private func streamingURL(_ streaming: StreamingState) -> String? {
        switch phase {
        case .httpRequest:
            let parts = streaming.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 2 else { return nil }
            return "https://\(host)\(String(parts[1]))"
        case .httpResponse:
            return streaming.originatingRequest?.url
        }
    }

    private func streamingStatus(_ streaming: StreamingState) -> Int? {
        guard phase == .httpResponse else { return nil }
        let parts = streaming.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        return Int(parts[1])
    }

    /// Finds the first CRLF in ``buffer`` and returns the index of the
    /// CR. nil when no CRLF is present.
    fileprivate static func findCRLF(in buffer: Data) -> Int? {
        guard buffer.count >= 2 else { return nil }
        var i = buffer.startIndex
        while i < buffer.endIndex - 1 {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A {
                return i
            }
            i += 1
        }
        return nil
    }

    /// Parses the hex size from a chunked size line (ignoring any
    /// chunk extensions after `;`).
    fileprivate static func parseHexSize(_ data: Data) -> Int? {
        guard let raw = String(data: data, encoding: .ascii) else { return nil }
        let head = raw.split(separator: ";", maxSplits: 1).first.map(String.init) ?? raw
        let trimmed = head.trimmingCharacters(in: CharacterSet.whitespaces)
        return Int(trimmed, radix: 16)
    }

    /// Drains the remaining wire chunks of an over-cap rewriting body.
    /// The truncated rewritten body has already been emitted, so all we
    /// need to do is keep the stream parser advancing until the
    /// terminator/trailers and then return to ``awaitingHead`` so the
    /// next message on this connection is parsed normally.
    private func discardChunked(reader: inout ChunkedReader) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        var sink = Data()
        let result = reader.consumeBuffered(&rxBuffer, into: &sink)
        switch result {
        case .needMore:
            mode = .discardingChunked(reader: reader)
            return false
        case .complete:
            mode = .awaitingHead
            return true
        case .malformed:
            mode = .passthrough
            return true
        }
    }

    // MARK: - Script application + head rebuild

    /// Decompresses the buffered body, runs the script chain, and emits
    /// the rebuilt head plus the (re-encoded if originally chunked)
    /// body. If decompression fails, the original bytes are passed
    /// through unmodified — better to leak the upstream's payload than
    /// break the connection.
    private func applyScriptsAndEmit(
        pending: PendingHead,
        rawBody: Data,
        originalSizes: [Int]?,
        into output: inout Data
    ) {
        let body: Data
        if pending.codec.requiresDecompression {
            guard let decoded = MITMBodyCodec.decompress(rawBody, plan: pending.codec) else {
                // Decompression failed; treat as identity passthrough.
                if phase == .httpRequest {
                    logRequest(startLine: pending.startLine)
                }
                output.append(serializeHead(startLine: pending.startLine, headers: pending.headers))
                if let originalSizes {
                    output.append(rechunk(body: rawBody, originalSizes: originalSizes))
                } else {
                    output.append(rawBody)
                }
                return
            }
            body = decoded
        } else {
            body = rawBody
        }

        let rules = policy.rules(for: host, phase: phase)
        let message = buildMessage(
            startLine: pending.startLine,
            headers: pending.headers,
            body: body,
            originatingRequest: pending.originatingRequest
        )
        let outcome = MITMScriptTransform.apply(
            message,
            rules: rules,
            engineProvider: scriptEngineProvider
        )
        let result: MITMScriptEngine.Message
        switch outcome {
        case .message(let updated):
            result = updated
        case .synthesizedResponse(let response):
            // Request-phase short-circuit. Drop the request bytes
            // we'd otherwise emit to upstream and queue the
            // synthesized HTTP/1.1 response for the inner leg.
            queueSynthesizedResponse(response)
            return
        }

        let finalStartLine = rebuildStartLine(from: result, fallback: pending.startLine)
        var finalHeaders = strippedFramingHeaders(result.headers, dropContentEncoding: pending.codec.requiresDecompression)
        // Always set an explicit Content-Length matching the post-script
        // body size. The original message may have been chunked, but we
        // emit the rewritten body as a single length-prefixed unit since
        // we've already buffered all of it.
        finalHeaders.append((name: "Content-Length", value: String(result.body.count)))

        if phase == .httpRequest {
            logRequest(startLine: finalStartLine)
        }
        output.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
        if !result.body.isEmpty {
            output.append(result.body)
        }
        _ = originalSizes // chunked re-encoding is unused once we collapse to Content-Length
    }

    /// Handles the no-body framing variant: scripts already ran, no
    /// body to buffer or decompress. Emits the rebuilt head with any
    /// script-supplied body inline.
    ///
    /// Framing-headers policy: when the post-script status semantically
    /// forbids a body (1xx other than 101, 204, 205, 304) and the
    /// script left the body empty, no `Content-Length` is emitted —
    /// the status alone signals "no body" and adding the header would
    /// violate RFC 9110 §15.2/§15.3. Everything else (regular response
    /// statuses, requests, scripts that populated a body) gets an
    /// explicit `Content-Length` matching the post-script body size so
    /// the receiver can frame the message without ambiguity.
    private func emitScriptedHead(
        fallbackStartLine: String,
        result: MITMScriptEngine.Message,
        codecRequiresDecompression: Bool,
        into output: inout Data
    ) {
        let finalStartLine = rebuildStartLine(from: result, fallback: fallbackStartLine)
        var finalHeaders = strippedFramingHeaders(result.headers, dropContentEncoding: codecRequiresDecompression)

        let preserveNoBody = phase == .httpResponse
            && result.body.isEmpty
            && isNoBodyStatus(responseStatusCode(from: finalStartLine))
        if !preserveNoBody {
            finalHeaders.append((name: "Content-Length", value: String(result.body.count)))
        }

        if phase == .httpRequest {
            logRequest(startLine: finalStartLine)
        }
        output.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
        if !result.body.isEmpty {
            output.append(result.body)
        }
    }

    /// True for HTTP/1 response statuses that forbid a body per RFC
    /// 9110 §15: 1xx informational (other than 101 Switching Protocols),
    /// 204 No Content, 205 Reset Content, 304 Not Modified.
    private func isNoBodyStatus(_ status: Int?) -> Bool {
        guard let status else { return false }
        switch status {
        case 204, 205, 304:
            return true
        default:
            return (100..<200).contains(status) && status != 101
        }
    }

    /// Extracts the numeric status code from an HTTP/1 response start
    /// line. Returns nil for request start lines or malformed input.
    private func responseStatusCode(from startLine: String) -> Int? {
        guard startLine.hasPrefix("HTTP/") else { return nil }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        return Int(parts[1])
    }

    /// Strips framing-related headers that we re-emit ourselves
    /// (`Transfer-Encoding`, `Content-Length`) and, when we just
    /// decompressed the body, `Content-Encoding`.
    private func strippedFramingHeaders(
        _ headers: [Header],
        dropContentEncoding: Bool
    ) -> [Header] {
        headers.filter { entry in
            let n = entry.name.lowercased()
            if n == "content-length" || n == "transfer-encoding" { return false }
            if dropContentEncoding, n == "content-encoding" { return false }
            return true
        }
    }

    // MARK: - Re-chunking (legacy; kept for the chunked passthrough
    // path where we want to preserve chunk shape rather than collapse
    // to a single Content-Length unit).

    /// Re-emits ``body`` as chunked-transfer-encoding using
    /// ``originalSizes`` as chunk-size targets. All but the last emitted
    /// chunk keep their original sizes; the last chunk absorbs any size
    /// delta. If the rewritten body is shorter than the prefix, emit fewer
    /// chunks. Always terminates with a zero-size chunk and empty trailers.
    private func rechunk(body: Data, originalSizes: [Int]) -> Data {
        var out = Data()
        var emitted = 0
        let total = body.count

        if originalSizes.count > 1 {
            for size in originalSizes.dropLast() {
                guard emitted < total else { break }
                let take = min(size, total - emitted)
                appendChunk(body.subdata(in: (body.startIndex + emitted)..<(body.startIndex + emitted + take)), into: &out)
                emitted += take
            }
        }
        if emitted < total || originalSizes.count == 1 {
            let remaining = total - emitted
            if remaining > 0 {
                appendChunk(body.subdata(in: (body.startIndex + emitted)..<body.endIndex), into: &out)
            }
        }
        // Final zero-size chunk and empty trailers.
        out.append(contentsOf: "0\r\n\r\n".utf8)
        return out
    }

    private func appendChunk(_ data: Data, into out: inout Data) {
        out.append(contentsOf: String(data.count, radix: 16).utf8)
        out.append(0x0D); out.append(0x0A)
        out.append(data)
        out.append(0x0D); out.append(0x0A)
    }

    // MARK: - Head parsing

    private typealias Header = (name: String, value: String)

    private struct ParsedHead {
        let startLine: String
        let headers: [Header]
    }

    private func parseHead(_ data: Data) -> ParsedHead? {
        guard let raw = String(data: data, encoding: .ascii) else { return nil }
        let lines = raw.components(separatedBy: "\r\n")
        guard let startLine = lines.first, !startLine.isEmpty else { return nil }
        guard isHTTPStartLine(startLine) else { return nil }
        var headers: [Header] = []
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon])
            let value = String(line[line.index(after: colon)...])
                .trimmingCharacters(in: CharacterSet.whitespaces)
            headers.append((name: name, value: value))
        }
        return ParsedHead(startLine: startLine, headers: headers)
    }

    private func isHTTPStartLine(_ line: String) -> Bool {
        // Request: METHOD SP path SP HTTP/1.x
        // Response: HTTP/1.x SP status SP reason
        if line.hasPrefix("HTTP/1.") { return true }
        return line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0")
    }

    /// True when ``startLine`` is a response start line with a 1xx
    /// status that isn't 101 — i.e. an informational interim response
    /// (100 Continue, 102 Processing, 103 Early Hints) that will be
    /// followed by additional headers on the same request. 101 is a
    /// final response (protocol upgrade) and pops normally.
    private func isInterimResponseStartLine(_ startLine: String) -> Bool {
        guard startLine.hasPrefix("HTTP/1.") else { return false }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, let status = Int(parts[1]) else { return false }
        return (100..<200).contains(status) && status != 101
    }

    private func serializeHead(startLine: String, headers: [Header]) -> Data {
        var out = Data()
        out.append(contentsOf: startLine.utf8)
        out.append(0x0D); out.append(0x0A)
        for (name, value) in headers {
            out.append(contentsOf: name.utf8)
            out.append(0x3A); out.append(0x20) // ": "
            out.append(contentsOf: value.utf8)
            out.append(0x0D); out.append(0x0A)
        }
        out.append(0x0D); out.append(0x0A)
        return out
    }

    /// Serializes a request-phase `Anywhere.respond(...)` payload as an
    /// HTTP/1.1 response and queues it on ``pendingClientBytes`` for
    /// the session pump to inject onto the inner TLS record. Strips
    /// user-supplied framing headers (``Content-Length`` /
    /// ``Transfer-Encoding``) and re-emits a single ``Content-Length``
    /// matching the body so the wire framing always agrees with the
    /// payload. The reason phrase is the canonical one (``""`` for
    /// unrecognised codes — clients ignore it per RFC 9112 §4).
    private func queueSynthesizedResponse(_ response: MITMScriptEngine.SynthesizedResponse) {
        let reason = canonicalReasonPhrase(for: response.status)
        let startLine = "HTTP/1.1 \(response.status) \(reason)"
        var headers = response.headers.filter { entry in
            let n = entry.name.lowercased()
            return n != "content-length" && n != "transfer-encoding"
        }
        headers.append((name: "Content-Length", value: String(response.body.count)))
        pendingClientBytes.append(serializeHead(startLine: startLine, headers: headers))
        if !response.body.isEmpty {
            pendingClientBytes.append(response.body)
        }
    }

    // MARK: - Framing decision

    private enum Framing {
        case none
        case contentLength(Int)
        case chunked
        case readUntilClose
        case switchingProtocols
    }

    private func bodyFraming(startLine: String, headers: [Header]) -> Framing {
        if phase == .httpResponse {
            // Status line: "HTTP/1.x SSS Reason"
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let status = Int(parts[1]) {
                if status == 101 { return .switchingProtocols }
                if status == 204 || status == 304 { return .none }
                if status >= 100 && status < 200 { return .none }
            }
        }
        for (name, value) in headers where name.lowercased() == "transfer-encoding" {
            if value.lowercased().contains("chunked") {
                return .chunked
            }
        }
        for (name, value) in headers where name.lowercased() == "content-length" {
            let trimmed = value.trimmingCharacters(in: CharacterSet.whitespaces)
            if let length = Int(trimmed), length >= 0 {
                return length == 0 ? .none : .contentLength(length)
            }
        }
        return phase == .httpRequest ? .none : .readUntilClose
    }

    private func firstHeaderValue(_ headers: [Header], name: String) -> String? {
        let target = name.lowercased()
        for (n, v) in headers where n.lowercased() == target {
            return v
        }
        return nil
    }

    // MARK: - Rule application (head-time)

    /// When the rule set declares a ``rewriteTarget``, the request's Host
    /// header is forced to the target authority so redirected requests use
    /// an authority the upstream can route.
    private func applyAuthorityRewrite(_ headers: [Header]) -> [Header] {
        guard phase == .httpRequest, let authority = effectiveAuthority else {
            return headers
        }
        var result = headers.filter { $0.name.lowercased() != "host" }
        result.append((name: "Host", value: authority))
        return result
    }

    /// Rewrites the request-target on the start line via any
    /// ``urlReplace`` rules. Request phase only; no-op on responses,
    /// asterisk-form (`OPTIONS *`), or unparseable lines. The regex applies
    /// to the path-and-query, not the method or HTTP-version.
    private func applyURLRules(_ startLine: String) -> String {
        guard phase == .httpRequest else { return startLine }
        let rules = policy.rules(for: host, phase: phase)
        guard rules.contains(where: {
            if case .urlReplace = $0.operation { return true }
            return false
        }) else { return startLine }

        // Request-line shape: METHOD SP request-target SP HTTP-version.
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return startLine }
        let method = String(parts[0])
        var target = String(parts[1])
        let version = String(parts[2])

        // Asterisk-form (RFC 9112 section 3.2.4) is reserved for
        // OPTIONS * and is not a meaningful target for URL rewrites.
        if target == "*" { return startLine }

        var changed = false
        for rule in rules {
            guard case .urlReplace(let regex, let replacement) = rule.operation else {
                continue
            }
            let range = NSRange(target.startIndex..., in: target)
            let mutated = regex.stringByReplacingMatches(
                in: target,
                options: [],
                range: range,
                withTemplate: replacement
            )
            if mutated != target {
                target = mutated
                changed = true
            }
        }
        return changed ? "\(method) \(target) \(version)" : startLine
    }

    private func applyHeaderRules(_ headers: [Header]) -> [Header] {
        let rules = policy.rules(for: host, phase: phase)
        guard !rules.isEmpty else { return headers }
        var current = headers
        for rule in rules {
            switch rule.operation {
            case .headerAdd(let name, let value):
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                current.removeAll { $0.name.lowercased() == nameLower }
            case .headerReplace(let regex, let name, let value):
                current = current.map { entry in
                    let literal = "\(entry.name): \(entry.value)"
                    let range = NSRange(literal.startIndex..., in: literal)
                    guard regex.firstMatch(in: literal, options: [], range: range) != nil else {
                        return entry
                    }
                    _ = regex.stringByReplacingMatches(
                        in: literal,
                        options: [],
                        range: range,
                        withTemplate: "\(name): \(value)"
                    )
                    return (name: name, value: value)
                }
            case .urlReplace, .script, .streamScript:
                continue
            }
        }
        return current
    }

    // MARK: - Message build / head rebuild

    /// Builds a ``MITMScriptEngine/Message`` from the in-flight head
    /// state. On response phase, fills in `method`/`url` from the
    /// originating request (looked up via ``MITMRequestLog`` by the
    /// caller).
    private func buildMessage(
        startLine: String,
        headers: [Header],
        body: Data,
        originatingRequest: MITMRequestLog.Record?
    ) -> MITMScriptEngine.Message {
        var method: String?
        var url: String?
        var status: Int?
        switch phase {
        case .httpRequest:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2 {
                method = String(parts[0])
                url = "https://\(host)\(String(parts[1]))"
            }
        case .httpResponse:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let code = Int(parts[1]) {
                status = code
            }
            method = originatingRequest?.method
            url = originatingRequest?.url
        }
        return MITMScriptEngine.Message(
            phase: phase,
            method: method,
            url: url,
            status: status,
            headers: headers,
            body: body,
            ruleSetID: policy.set(for: host)?.id
        )
    }

    /// Rebuilds the start/status line from a (possibly script-mutated)
    /// message. For requests, the URL's path-and-query becomes the
    /// request-target; the host portion is ignored since the upstream
    /// is fixed at session creation. For responses, the status code
    /// flows into the status line with a canonical reason phrase.
    /// Falls back to the original line when the message lacks the
    /// fields needed to rebuild.
    private func rebuildStartLine(
        from message: MITMScriptEngine.Message,
        fallback: String
    ) -> String {
        switch message.phase {
        case .httpRequest:
            guard let method = message.method, let url = message.url else {
                return fallback
            }
            let target = pathAndQuery(fromURL: url) ?? url
            return "\(method) \(target) HTTP/1.1"
        case .httpResponse:
            guard let status = message.status else { return fallback }
            let parts = fallback.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            let version = parts.count >= 1 ? String(parts[0]) : "HTTP/1.1"
            let reason = canonicalReasonPhrase(for: status)
            return "\(version) \(status) \(reason)"
        }
    }

    /// Extracts path-and-query from an absolute URL string, or returns
    /// nil if the input looks like a relative reference (no scheme) —
    /// in which case the caller treats the whole string as the target.
    private func pathAndQuery(fromURL url: String) -> String? {
        guard let components = URLComponents(string: url) else { return nil }
        // Relative URL? Use as-is.
        if components.scheme == nil && components.host == nil {
            return nil
        }
        var target = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        if let query = components.percentEncodedQuery {
            target += "?\(query)"
        }
        return target
    }

    /// Minimal canonical reason phrase lookup for HTTP/1.1 status
    /// codes. Returns an empty string for unrecognised codes so the
    /// status line stays well-formed (clients ignore the reason
    /// phrase per RFC 9112 §4).
    private func canonicalReasonPhrase(for status: Int) -> String {
        switch status {
        case 100: return "Continue"
        case 101: return "Switching Protocols"
        case 200: return "OK"
        case 201: return "Created"
        case 202: return "Accepted"
        case 204: return "No Content"
        case 206: return "Partial Content"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 303: return "See Other"
        case 304: return "Not Modified"
        case 307: return "Temporary Redirect"
        case 308: return "Permanent Redirect"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 408: return "Request Timeout"
        case 409: return "Conflict"
        case 410: return "Gone"
        case 418: return "I'm a teapot"
        case 429: return "Too Many Requests"
        case 500: return "Internal Server Error"
        case 501: return "Not Implemented"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default:  return ""
        }
    }

    // MARK: - Request log helpers

    /// Push the in-flight request's method and absolute URL onto the
    /// request log so the response stream can populate its script
    /// `ctx.method` / `ctx.url`. Request phase only.
    private func logRequest(startLine: String) {
        guard phase == .httpRequest else { return }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else {
            requestLog.recordHTTP1(method: nil, url: nil)
            return
        }
        let method = String(parts[0])
        let target = String(parts[1])
        let url = "https://\(host)\(target)"
        requestLog.recordHTTP1(method: method, url: url)
    }
}

// MARK: - ChunkedReader

/// Streaming chunked-transfer decoder. Used in two modes:
///
///   - ``consumeForward(_:into:)``: pass-through. Bytes consumed from
///     ``buffer`` are appended verbatim to ``output``; framing is tracked
///     to know when the message ends.
///   - ``consumeBuffered(_:into:)``: rewrite. Decoded chunk data is
///     appended to ``output`` (the body accumulator); on
///     completion the original chunk sizes are returned for re-chunking.
///
/// Either method drains ``buffer`` from the front. They do not mix on
/// the same instance; ``MITMHTTP1Stream`` chooses one mode per body.
private final class ChunkedReader {
    private enum State {
        case sizeLine
        case chunkData(remaining: Int, originalSize: Int)
        case dataCRLF(originalSize: Int)
        case trailerOrEnd
    }

    private var state: State = .sizeLine
    private var sizes: [Int] = []

    enum ForwardResult {
        case needMore
        case complete
        case malformed
    }

    enum BufferedResult {
        case needMore
        case complete(sizes: [Int])
        case malformed
    }

    func consumeForward(_ buffer: inout Data, into output: inout Data) -> ForwardResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                guard let size = parseHexSize(line) else { return .malformed }
                if size == 0 {
                    state = .trailerOrEnd
                } else {
                    state = .chunkData(remaining: size, originalSize: size)
                }
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                output.append(buffer.prefix(take))
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF(let originalSize):
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[buffer.startIndex] == 0x0D, buffer[buffer.startIndex + 1] == 0x0A else {
                    return .malformed
                }
                output.append(0x0D); output.append(0x0A)
                buffer.removeFirst(2)
                sizes.append(originalSize)
                state = .sizeLine
            case .trailerOrEnd:
                // Forward the trailer block (zero or more lines + CRLF)
                // verbatim until the empty-line terminator.
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                if line.isEmpty {
                    return .complete
                }
            }
        }
        return .needMore
    }

    func consumeBuffered(_ buffer: inout Data, into output: inout Data) -> BufferedResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                guard let size = parseHexSize(line) else { return .malformed }
                if size == 0 {
                    state = .trailerOrEnd
                } else {
                    state = .chunkData(remaining: size, originalSize: size)
                }
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                output.append(buffer.prefix(take))
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF(let originalSize):
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[buffer.startIndex] == 0x0D, buffer[buffer.startIndex + 1] == 0x0A else {
                    return .malformed
                }
                buffer.removeFirst(2)
                sizes.append(originalSize)
                state = .sizeLine
            case .trailerOrEnd:
                // Rewritten bodies are re-chunked with empty trailers, so
                // consume and discard any original trailers here.
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                if line.isEmpty {
                    return .complete(sizes: sizes)
                }
            }
        }
        return .needMore
    }

    private func findCRLF(in buffer: Data) -> Int? {
        guard buffer.count >= 2 else { return nil }
        var i = buffer.startIndex
        while i < buffer.endIndex - 1 {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A {
                return i
            }
            i += 1
        }
        return nil
    }

    private func parseHexSize(_ data: Data) -> Int? {
        guard let raw = String(data: data, encoding: .ascii) else { return nil }
        // "size" or "size;ext..."; only the leading hex is needed.
        let head = raw.split(separator: ";", maxSplits: 1).first.map(String.init) ?? raw
        let trimmed = head.trimmingCharacters(in: CharacterSet.whitespaces)
        return Int(trimmed, radix: 16)
    }
}
