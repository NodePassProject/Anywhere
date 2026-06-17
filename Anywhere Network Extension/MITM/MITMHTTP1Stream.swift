//
//  MITMHTTP1Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMHTTP1Stream")

/// Structured response delivery for the h2→h1 bridge. When a `MITMHTTP1Stream` (response phase) is
/// given a sink, it delivers the rewritten response as IR — head / body / reset — instead of
/// serializing HTTP/1.1 bytes the bridge would only re-parse. Chunked response trailers are not
/// surfaced (dropped). lwIP-queue-confined.
protocol MITMHTTP1ResponseIRSink: AnyObject {
    /// `endStream` true ⇒ no body follows (the IR consumer ends the stream on the head).
    func http1ResponseHead(status: Int, headers: [(name: String, value: String)], endStream: Bool)
    /// An interim 1xx informational response (e.g. 103 Early Hints) ahead of the final response:
    /// forwarded to the client without a body and without ending the stream (RFC 9113 §8.1).
    func http1ResponseInterim(status: Int, headers: [(name: String, value: String)])
    func http1ResponseBody(_ data: Data, endStream: Bool)
    /// Malformed, oversized, or unbridgeable (101 / CONNECT-2xx) upstream response: reset the stream.
    func http1ResponseReset()
}

/// One direction of an HTTP/1.x byte stream through the MITM: framing state
/// machine plus chunked decoder, emitting rewritten plaintext for the opposite
/// TLS leg. Unparseable input permanently downgrades to passthrough.
final class MITMHTTP1Stream {

    /// Cap on bytes buffered awaiting the CRLF CRLF head terminator (Apache's
    /// 64 KiB default); on exceed the stream downgrades to passthrough.
    private static let maxHeadBytes: Int = 64 * 1024

    /// Cap on a chunk-size or trailer line awaiting its CRLF — an unterminated
    /// line is a remote memory DoS; on exceed the framing is treated as malformed.
    fileprivate static let maxChunkLineBytes: Int = 16 * 1024

    /// Memory cap on `Anywhere.respond` bodies; oversized bodies are truncated
    /// rather than rejected — a partial mock beats a dropped one.
    private static let maxSynthesizedResponseBodyBytes: Int = MITMBodyCodec.maxBufferedBodyBytes

    private let host: String
    private let phase: MITMPhase
    /// Phase-filtered rules for this host, resolved once at init (one trie walk).
    private let rules: [CompiledMITMRule]
    /// Rule-set ID for the matched host (`Anywhere.store` scope key); nil when no set matches.
    private let ruleSetID: UUID?
    /// Forced `Host:` once a transparent rewrite commits to a replacement
    /// authority. Sticky: the connection has one upstream leg, so later requests
    /// route there too. Request phase only.
    private var effectiveAuthority: String?

    /// Replacement upstream from a transparent rewrite; read by the session's
    /// deferred-dial pump. Request phase only.
    private(set) var resolvedUpstream: (host: String, port: UInt16?)?

    /// Fired once on 101 / CONNECT-2xx so the session can flip the opposite
    /// leg to passthrough. Response phase only.
    var onProtocolUpgrade: (() -> Void)?
    /// Fired when a head is rejected as a request-smuggling / header-injection framing violation,
    /// or a chunked body overruns the buffer cap. The stream stops forwarding (`.draining`) and
    /// asks the session to close the connection — fail closed rather than relay malformed bytes or
    /// deliver a truncated body framed as complete. Mirrors mitmproxy's `400/502 + CloseConnection`.
    /// Used only *before* a head is committed to the wire, so the response leg can still answer 502.
    var onFatalClose: (() -> Void)?
    /// Fired when chunked framing breaks *mid-body*, after the head is already on the wire. The
    /// session must tear down both legs (a plain TCP close) — it cannot answer a 502, and
    /// synthesizing a `0\r\n\r\n` terminator + passthrough would frame a truncated body as complete
    /// and then desync the peer onto the next message. Mirrors mitmproxy's `CloseConnection` on a
    /// body `ProtocolError`.
    var onHardClose: (() -> Void)?
    /// Lazy JS runtime, shared across both directions.
    private let scriptEngineProvider: MITMScriptEngine.Provider
    /// Request stream records method/URL; response stream pops them for script ctx.
    private let requestLog: MITMRequestLog

    /// Serial lwIP queue all stream state is confined to; script hops resume here.
    private let lwipQueue: DispatchQueue

    init(
        host: String,
        phase: MITMPhase,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?,
        scriptEngineProvider: MITMScriptEngine.Provider,
        requestLog: MITMRequestLog,
        lwipQueue: DispatchQueue
    ) {
        self.host = host
        self.phase = phase
        let matchedSet = policy.set(for: host)
        self.rules = matchedSet?.rules.filter { $0.phase == phase } ?? []
        self.ruleSetID = matchedSet?.id
        self.effectiveAuthority = effectiveAuthority
        self.scriptEngineProvider = scriptEngineProvider
        self.requestLog = requestLog
        self.lwipQueue = lwipQueue
    }

    // MARK: - State

    /// Head withheld until the body completes so the final Content-Length /
    /// Content-Encoding can be computed.
    private struct PendingHead {
        let startLine: String
        let headers: [Header]
        /// Decompression plan; identity after decompressing, so `Content-Encoding` is dropped on emit.
        let codec: MITMBodyCodec.Plan
        /// Originating request for response-phase ctx. Nil on request phase.
        let originatingRequest: MITMRequestLog.Record?
    }

    /// Per-body streaming-script state; one-chunk lookahead so the final chunk
    /// can be marked `frame.end = true`.
    private struct StreamingState {
        let headers: [Header]
        let originatingRequest: MITMRequestLog.Record?
        let startLine: String
        var frameIndex: Int = 0
        /// Held until we know whether a next chunk exists (sets `isLast`).
        var pendingChunk: Data? = nil
        /// CRLF scan resume offset (avoids O(n²) re-scanning); reset after each line.
        var lineScanCursor: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
    }

    /// Continuation captured before a script hop, applied when the hop resumes.
    private enum StreamingPostFrame {
        /// Normal mid-stream boundary: hold `nextPending` and continue at `inner`.
        case hold(nextPending: Data?, inner: StreamingChunkedInner)
        /// Final chunk emitted: emit `0\r\n` and drain trailers.
        case finalThenTrailer
        /// Per-chunk cap overflow: bypass the script and forward the remaining
        /// `left` bytes of this chunk verbatim.
        case bypassRemainder(left: Int, accumulator: Data)
    }

    private enum StreamingChunkedInner {
        case sizeLine
        case chunkData(remaining: Int, accumulator: Data)
        case dataCRLF
        /// After the zero-size line: drain trailer lines until the empty-line terminator.
        case trailerOrEnd
    }

    private enum Mode {
        /// Accumulating the next head in `rxBuffer` until CRLF CRLF.
        case awaitingHead

        /// Head emitted; forwarding body bytes verbatim.
        case forwardingLength(remaining: Int)
        case forwardingChunked(reader: ChunkedReader)

        /// Bridge (IR) only: forward a read-until-close response body as IR data until EOF — there's
        /// no h1 framing to emit, and the consumer frames it as HTTP/2 DATA.
        case bridgeForwardUntilClose

        /// Buffering body for rewrite; head withheld until body completes.
        case rewritingLength(pending: PendingHead, expected: Int, accumulator: Data)
        case rewritingChunked(pending: PendingHead, accumulator: Data, reader: ChunkedReader)

        /// Buffering a read-until-close body (identity-coded only); `finish()`
        /// runs the script chain at EOF. On cap overflow falls back to passthrough.
        case rewritingUntilClose(pending: PendingHead, accumulator: Data)

        /// Draining a chunked body without forwarding it: `afterSynth` for a
        /// locally answered request, else an over-cap rewrite tail.
        case discardingChunked(reader: ChunkedReader, afterSynth: Bool)

        /// Discarding a Content-Length request body after a synthesized 302 / reject.
        case discardingLength(remaining: Int)

        /// Terminal blackhole when `.discardingChunked` loses the message boundary;
        /// `.passthrough` would leak bytes upstream or desync the next response.
        case draining

        /// Per-chunk streaming-script mode; head already emitted.
        case streamingChunked(streaming: StreamingState, inner: StreamingChunkedInner)

        /// Permanent passthrough: protocol upgrades, CONNECT tunnels, or framing errors.
        case passthrough

        /// Script hop outstanding; drive loop halted until the engine result
        /// resumes on the lwIP queue.
        case awaitingScript
    }

    private var mode: Mode = .awaitingHead

    /// When set (the h2→h1 bridge's per-stream response stream), the response path delivers IR to
    /// this sink instead of producing HTTP/1.1 bytes. nil ⇒ byte output (the main h1↔h1 path),
    /// byte-for-byte unchanged. Response phase only; set once before the first `transform`.
    weak var responseIRSink: MITMHTTP1ResponseIRSink?

    /// In-flight completion, retained while a script hop is outstanding.
    private var parkedCompletion: ((Data) -> Void)?

    /// Bytes emitted before the script hop; the resume prepends them so output
    /// stays in wire order.
    private var pendingPreParkOutput = Data()

    /// Set on teardown; resumes that fire after this bail immediately.
    private var torn = false

    /// Set when `forcePassthrough()` arrives while a script hop is parked; honored at resume.
    private var forcePassthroughPending = false
    private var rxBuffer = MITMByteBuffer()

    /// Prefix of `rxBuffer` already scanned for CRLF CRLF (O(n) total, not O(n²)).
    private var headScanned: Int = 0

    /// Client-bound synth bytes from `Anywhere.respond(...)`; drained by the
    /// session pump. Request phase only.
    private var pendingClientBytes = Data()

    /// Synth bytes held until the current response finishes streaming. Response phase only.
    private var pendingSynthAfterCurrentResponse = Data()

    /// True when the stream is between messages — awaiting a head, with nothing buffered, parked, or
    /// pending. The session checks this on the *response* stream to know an h1 upstream leg is fully
    /// idle (no response in flight) and so can be safely closed to reconnect to a different
    /// transparent-rewrite target. Conservative by construction: any in-progress state reads false.
    var isBetweenMessages: Bool {
        guard case .awaitingHead = mode else { return false }
        return rxBuffer.isEmpty
            && parkedCompletion == nil
            && !forcePassthroughPending
            && pendingSynthAfterCurrentResponse.isEmpty
    }

    // MARK: - Public API

    /// Feeds `data` through the rewrite pipeline. `completion` fires exactly once —
    /// synchronously, or later on the lwIP queue when a script parks the stream.
    func transform(_ data: Data, completion: @escaping (Data) -> Void) {
        guard parkedCompletion == nil else { return failClosedReentry(completion) }
        if case .passthrough = mode {
            completion(data)
            return
        }
        rxBuffer.append(data)
        parkedCompletion = completion
        var output = Data()
        while drive(into: &output) { }
        finishDrivePass(output)
    }

    /// Fires the stashed completion, or holds `output` while a script hop is outstanding.
    private func finishDrivePass(_ output: Data) {
        if case .awaitingScript = mode {
            pendingPreParkOutput = output
            return
        }
        let completion = parkedCompletion
        parkedCompletion = nil
        completion?(output)
    }

    /// Marks the stream torn down; later script resumes bail immediately. Idempotent.
    func markTorn() {
        torn = true
        parkedCompletion = nil
        pendingPreParkOutput = Data()
        // Release buffers eagerly rather than pinning them until the session lets go.
        mode = .passthrough
        rxBuffer = MITMByteBuffer()
    }

    /// Forces permanent passthrough and returns buffered bytes for forwarding;
    /// defers via `forcePassthroughPending` (returning empty) if a script hop is parked.
    func forcePassthrough() -> Data {
        guard parkedCompletion == nil else {
            forcePassthroughPending = true
            return Data()
        }
        if case .passthrough = mode { return Data() }
        let buffered = rxBuffer.prefix(rxBuffer.count)
        rxBuffer.removeAll(keepingCapacity: false)
        headScanned = 0
        mode = .passthrough
        return buffered
    }

    /// Honors a deferred `forcePassthrough` at resume time; returns true when
    /// fired, in which case the resume must do nothing further.
    private func resumeIntoForcedPassthroughIfNeeded() -> Bool {
        guard forcePassthroughPending else { return false }
        forcePassthroughPending = false
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        resumed.append(rxBuffer.prefix(rxBuffer.count))
        rxBuffer.removeAll(keepingCapacity: false)
        headScanned = 0
        mode = .passthrough
        finishDrivePass(resumed)
        return true
    }

    /// Re-entry while parked would stomp the stashed completion and hang the
    /// connection; fire the new completion empty and keep the stashed one.
    private func failClosedReentry(_ completion: (Data) -> Void) {
        logger.error("HTTP/1 \(host): transform/finish re-entered while a script hop is outstanding; dropping this chunk to preserve the parked completion (one-read-in-flight invariant violated)")
        completion(Data())
    }

    /// Drains client-bound bytes queued by `Anywhere.respond(...)`.
    func drainPendingClientBytes() -> Data {
        let bytes = pendingClientBytes
        pendingClientBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    /// Called on upstream EOF: flushes a `.rewritingUntilClose` body through the
    /// script chain; fires `completion` inline in all other modes.
    func finish(completion: @escaping (Data) -> Void) {
        guard parkedCompletion == nil else { return failClosedReentry(completion) }
        // Bridge (IR) EOF handling, by current mode:
        if responseIRSink != nil {
            switch mode {
            case .bridgeForwardUntilClose:
                // read-until-close: EOF ends the body cleanly.
                _ = emitBridgeBody(Data(), endStream: true)
                mode = .draining
                completion(Data())
                return
            case .forwardingLength, .forwardingChunked, .rewritingLength, .rewritingChunked:
                // EOF arrived mid-body (a truncated upstream response) → reset the bridged stream
                // rather than leave the client waiting for a body that won't finish.
                responseIRSink?.http1ResponseReset()
                mode = .draining
                completion(Data())
                return
            case .rewritingUntilClose:
                break // fall through: run the buffered script chain at EOF; the resume delivers IR.
            default:
                completion(Data())
                return
            }
        }
        guard case .rewritingUntilClose(let pending, let accumulator) = mode else {
            completion(Data())
            return
        }
        parkedCompletion = completion
        var output = Data()
        let parked = applyScriptsAndEmit(
            pending: pending,
            rawBody: accumulator,
            originalSizes: nil,
            resumeMode: .passthrough,
            into: &output
        )
        if parked {
            pendingPreParkOutput = output
            return
        }
        finishDrivePass(output)
    }

    /// Emits synth-after bytes exactly at the response body boundary — early
    /// corrupts framing, late races the next upstream head.
    private func flushSynthAfterResponse(into output: inout Data) {
        if !pendingSynthAfterCurrentResponse.isEmpty {
            output.append(pendingSynthAfterCurrentResponse)
            pendingSynthAfterCurrentResponse.removeAll(keepingCapacity: false)
        }
    }

    // MARK: - Driver

    /// Returns true when state advanced and the loop should run again.
    private func drive(into output: inout Data) -> Bool {
        switch mode {
        case .passthrough:
            // Bridge: a passthrough downgrade (malformed framing, upgrade, non-HTTP, oversize head)
            // can't map onto one HTTP/2 stream — reset it instead of leaking raw bytes the IR
            // consumer can't frame. The main path forwards verbatim.
            if bridgeResetIfNeeded() { return false }
            output.append(rxBuffer.prefix(rxBuffer.count))
            rxBuffer.removeAll(keepingCapacity: false)
            return false

        case .bridgeForwardUntilClose:
            guard !rxBuffer.isEmpty else { return false }
            _ = emitBridgeBody(Data(rxBuffer.prefix(rxBuffer.count)), endStream: false)
            rxBuffer.removeAll(keepingCapacity: false)
            return false

        case .awaitingScript:
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

        case .rewritingUntilClose(let pending, var accumulator):
            mode = .rewritingUntilClose(pending: pending, accumulator: accumulator)
            return rewriteUntilClose(pending: pending, accumulator: &accumulator, into: &output)

        case .discardingChunked(var reader, let afterSynth):
            mode = .discardingChunked(reader: reader, afterSynth: afterSynth)
            return discardChunked(reader: &reader, afterSynth: afterSynth, into: &output)

        case .discardingLength(let remaining):
            return discardLength(remaining: remaining)

        case .draining:
            rxBuffer.removeAll(keepingCapacity: false)
            return false

        case .streamingChunked(var streaming, let inner):
            mode = .streamingChunked(streaming: streaming, inner: inner)
            return driveStreamingChunked(streaming: &streaming, inner: inner, into: &output)
        }
    }

    // MARK: - Head consumption

    /// Scans for CRLF CRLF, parses the head, applies rewrites, and enters the
    /// appropriate body mode.
    private func consumeHead(into output: inout Data) -> Bool {
        let crlfcrlf = Data([0x0D, 0x0A, 0x0D, 0x0A])
        // Overlap the scanned prefix by 3 bytes so a straddling CRLF CRLF is found.
        let searchFrom = max(0, headScanned - (crlfcrlf.count - 1))
        guard let terminator = rxBuffer.range(of: crlfcrlf, from: searchFrom) else {
            if rxBuffer.count > Self.maxHeadBytes {
                // An over-cap head with no CRLF CRLF (giant headers, or bare-LF framing we never
                // terminate) used to downgrade to verbatim passthrough — relaying bytes that skip
                // every parseHead smuggling check, a trivially-triggered inspection bypass. Fail
                // closed instead, like the `.smuggling` path: never relay an unparseable head
                // (mitmproxy answers 400/502 + close). onFatalClose closes the connection on the
                // request leg, or answers the client 502 on the response leg.
                logger.warning("HTTP/1 \(host): head exceeded \(Self.maxHeadBytes) B without CRLF CRLF; closing the connection without forwarding")
                rxBuffer.removeAll(keepingCapacity: false)
                headScanned = 0
                mode = .draining
                onFatalClose?()
                return false
            }
            headScanned = rxBuffer.count
            return false
        }
        headScanned = 0
        let headEnd = terminator.upperBound
        let headData = rxBuffer.subdata(in: 0..<headEnd)
        rxBuffer.removeFirst(headEnd)

        let parsed: ParsedHead
        switch parseHead(headData) {
        case .ok(let p):
            parsed = p
        case .forward:
            // Not HTTP/1.x, or a tolerable deviation: stop rewriting, forward verbatim.
            mode = .passthrough
            output.append(headData)
            return true
        case .smuggling:
            // A request-smuggling / header-injection framing violation (RFC 9112 §6). Fail closed:
            // do not relay the offending bytes (mitmproxy answers 400 + CloseConnection). The session
            // closes the connection; `.draining` drops anything already buffered behind this head.
            logger.warning("HTTP/1 \(host): rejecting message with a framing/smuggling violation; closing the connection without forwarding")
            mode = .draining
            onFatalClose?()
            return false
        }

        let rewrittenStartLine: String
        switch applyRewrite(parsed.startLine) {
        case .rewritten(let line):
            rewrittenStartLine = line
        case .synthesize(let response):
            return synthesizeRequestResponse(
                response,
                requestHeaders: parsed.headers,
                into: &output
            )
        }

        // Pop the request record once per *final* response head so the FIFO never
        // drifts; 1xx interims peek. Must precede header rules and `bodyFraming`.
        let originatingRequest: MITMRequestLog.Record?
        if phase == .httpResponse {
            if isInterimResponseStartLine(rewrittenStartLine) {
                originatingRequest = requestLog.peekHTTP1()
            } else {
                let popped = requestLog.popHTTP1()
                originatingRequest = popped
                // Pipelined synth bytes emit only after this response finishes streaming.
                if let popped, !popped.synthAfter.isEmpty {
                    pendingSynthAfterCurrentResponse.append(popped.synthAfter)
                }
            }
        } else {
            originatingRequest = nil
        }

        let gateURL = requestURLForGating(
            startLine: rewrittenStartLine,
            originatingRequest: originatingRequest
        )

        // Authority rewrite first so a headerReplace on Host can still override it.
        let withAuthority = applyAuthorityRewrite(parsed.headers)
        var rewrittenHeaders = applyHeaderRules(withAuthority, requestURL: gateURL)
        // Clamp the request's Accept-Encoding to codings we can decode (mitmproxy `constrain_encoding`)
        // so a buffered body rule isn't silently defeated by an undecodable Content-Encoding (e.g. zstd).
        if phase == .httpRequest {
            rewrittenHeaders = rewrittenHeaders.map { entry in
                entry.name.equalsIgnoringASCIICase("accept-encoding")
                    ? (name: entry.name, value: MITMBodyCodec.constrainedAcceptEncoding(entry.value))
                    : entry
            }
        }

        let framing = bodyFraming(
            startLine: rewrittenStartLine,
            headers: rewrittenHeaders,
            originatingMethod: originatingRequest?.method
        )

        let scriptsApply = MITMScriptTransform.hasScriptRule(in: rules, requestURL: gateURL)
        // Any rule needing the full decompressed body drives buffered mode.
        let buffersBody = scriptsApply
            || MITMScriptTransform.hasBodyReplaceRule(in: rules, requestURL: gateURL)
            || MITMScriptTransform.hasBodyJSONRule(in: rules, requestURL: gateURL)

        switch framing {
        case .switchingProtocols, .readUntilClose:
            // Buffer a read-until-close body to EOF and re-emit with Content-Length
            // when a buffered script applies and the body is identity-coded; else passthrough.
            if case .readUntilClose = framing, buffersBody,
               !MITMScriptTransform.hasStreamScriptRule(in: rules, requestURL: gateURL) {
                let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
                if codec.supported, !codec.requiresDecompression {
                    warnIfBufferedScriptDeStreams(rewrittenHeaders)
                    // Force Connection: close so success and overflow paths both frame correctly.
                    var headers = rewrittenHeaders.filter {
                        !$0.name.equalsIgnoringASCIICase("connection")
                    }
                    headers.append((name: "Connection", value: "close"))
                    mode = .rewritingUntilClose(
                        pending: PendingHead(
                            startLine: rewrittenStartLine,
                            headers: headers,
                            codec: codec,
                            originatingRequest: originatingRequest
                        ),
                        accumulator: Data()
                    )
                    return true
                }
            }
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            // RFC 9112 §6.3 case 7: read-until-close. Force Connection: close so
            // the receiver doesn't parse body bytes as the next response head.
            let finalHeaders: [Header]
            if case .readUntilClose = framing {
                var headers = rewrittenHeaders.filter {
                    !$0.name.equalsIgnoringASCIICase("connection")
                }
                headers.append((name: "Connection", value: "close"))
                finalHeaders = headers
            } else {
                finalHeaders = rewrittenHeaders
            }
            if responseIRSink != nil {
                if case .switchingProtocols = framing {
                    // 101 / CONNECT-2xx can't bridge onto a single HTTP/2 stream — reset (the client
                    // retries over HTTP/1.1, where the tunnel path applies).
                    _ = bridgeResetIfNeeded()
                    return false
                }
                // read-until-close: deliver the head, then stream the body as IR until EOF.
                emitResponseHead(startLine: rewrittenStartLine, headers: finalHeaders, bodyFollows: true, into: &output)
                mode = .bridgeForwardUntilClose
                return true
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: finalHeaders))
            // Best-effort: synth bytes can't be cleanly framed once passthrough.
            flushSynthAfterResponse(into: &output)
            mode = .passthrough
            // 101 / CONNECT-2xx: flip the request leg too, or WebSocket frames
            // stall in the head parser.
            if case .switchingProtocols = framing {
                onProtocolUpgrade?()
            }
            return true
        case .none, .contentLength, .chunked:
            break
        }

        switch framing {
        case .none:
            // Skip scripts on 1xx interim responses (RFC 9110 §15.2); the
            // matching final response runs them itself.
            let runScripts = scriptsApply && !isInterimResponseStartLine(rewrittenStartLine)
            if runScripts {
                let message = buildMessage(
                    startLine: rewrittenStartLine,
                    headers: rewrittenHeaders,
                    body: Data(),
                    originatingRequest: originatingRequest
                )
                let fallback = rewrittenStartLine
                let originatingMethod = originatingRequest?.method
                mode = .awaitingScript
                MITMScriptTransform.apply(
                    message,
                    rules: rules,
                    engineProvider: scriptEngineProvider,
                    resumeOn: lwipQueue
                ) { [weak self] outcome in
                    self?.resumeHeadNoBody(
                        outcome: outcome,
                        fallbackStartLine: fallback,
                        originatingMethod: originatingMethod
                    )
                }
                return false // parked
            }
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            // Interim 1xx (e.g. 103 Early Hints): forward it to the client leg as its own interim
            // head — no body, doesn't end the stream (RFC 9113 §8.1) — then await the final response
            // (the request-log record was peeked, so it stays queued for that pop).
            if let sink = responseIRSink, isInterimResponseStartLine(rewrittenStartLine) {
                sink.http1ResponseInterim(
                    status: responseStatusCode(from: rewrittenStartLine) ?? 0,
                    headers: rewrittenHeaders
                )
                mode = .awaitingHead
                return true
            }
            emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: false, into: &output)
            // Head-only response: this is the synth-after boundary.
            flushSynthAfterResponse(into: &output)
            mode = .awaitingHead
            return true
        case .contentLength(let length):
            return enterContentLength(
                rewrittenStartLine: rewrittenStartLine,
                rewrittenHeaders: rewrittenHeaders,
                length: length,
                buffersBody: buffersBody,
                rules: rules,
                requestURL: gateURL,
                originatingRequest: originatingRequest,
                into: &output
            )
        case .chunked:
            return enterChunked(
                rewrittenStartLine: rewrittenStartLine,
                rewrittenHeaders: rewrittenHeaders,
                buffersBody: buffersBody,
                rules: rules,
                requestURL: gateURL,
                originatingRequest: originatingRequest,
                into: &output
            )
        case .readUntilClose, .switchingProtocols:
            return true
        }
    }

    private func enterContentLength(
        rewrittenStartLine: String,
        rewrittenHeaders: [Header],
        length: Int,
        buffersBody: Bool,
        rules: [CompiledMITMRule],
        requestURL: String?,
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        // Stream scripts can't modify a length-prefixed body; warn and fall through.
        if MITMScriptTransform.hasStreamScriptRule(in: rules, requestURL: requestURL) {
            logger.warning("HTTP/1 \(host): Stream Script skipped for Content-Length body (chunked encoding required)")
        }

        // Opt out of buffering up front when length exceeds the cap — keeps
        // large downloads out of the accumulator.
        let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
        let canRewrite = buffersBody && codec.supported && length <= MITMBodyCodec.maxBufferedBodyBytes

        if canRewrite {
            let headers = handleExpectContinue(startLine: rewrittenStartLine, headers: rewrittenHeaders)
            mode = .rewritingLength(
                pending: PendingHead(
                    startLine: rewrittenStartLine,
                    headers: headers,
                    codec: codec,
                    originatingRequest: originatingRequest
                ),
                expected: length,
                accumulator: Data()
            )
            return true
        }
        if buffersBody, length > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("HTTP/1 \(host): Content-Length \(length) exceeds cap \(MITMBodyCodec.maxBufferedBodyBytes)")
        }
        if phase == .httpRequest {
            logRequest(startLine: rewrittenStartLine)
        }
        emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: true, into: &output)
        mode = .forwardingLength(remaining: length)
        return true
    }

    private func enterChunked(
        rewrittenStartLine: String,
        rewrittenHeaders: [Header],
        buffersBody: Bool,
        rules: [CompiledMITMRule],
        requestURL: String?,
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        // Streaming script wins over buffered script; emit head immediately
        // (stream scripts can't mutate head fields).
        if MITMScriptTransform.hasStreamScriptRule(in: rules, requestURL: requestURL) {
            if responseIRSink != nil {
                // The bridge can't run a streaming response script across the h2→h1 boundary
                // (mirrors the request side); forward the body unscripted as IR rather than stall.
                logger.warning("HTTP/1 \(host): response stream-script unsupported on the bridge; forwarding unscripted")
                emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: true, into: &output)
                mode = .forwardingChunked(reader: ChunkedReader())
                return true
            }
            if buffersBody {
                logger.warning("HTTP/1 \(host): Stream Script wins over buffered body rule")
            }
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            let streaming = StreamingState(
                headers: rewrittenHeaders,
                originatingRequest: originatingRequest,
                startLine: rewrittenStartLine,
                cursor: MITMScriptTransform.FrameCursor()
            )
            mode = .streamingChunked(streaming: streaming, inner: .sizeLine)
            return true
        }

        let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
        if buffersBody, codec.supported {
            warnIfBufferedScriptDeStreams(rewrittenHeaders)
            let headers = handleExpectContinue(startLine: rewrittenStartLine, headers: rewrittenHeaders)
            mode = .rewritingChunked(
                pending: PendingHead(
                    startLine: rewrittenStartLine,
                    headers: headers,
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
        emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: true, into: &output)
        mode = .forwardingChunked(reader: ChunkedReader())
        return true
    }

    /// `Expect: 100-continue` while the head is withheld: the upstream can't send
    /// the 100 yet, so synthesize it and strip `Expect` to avoid a duplicate.
    private func handleExpectContinue(startLine: String, headers: [Header]) -> [Header] {
        guard phase == .httpRequest, startLine.hasSuffix(" HTTP/1.1") else { return headers }
        let expectsContinue = headers.contains { entry in
            entry.name.equalsIgnoringASCIICase("expect")
                && entry.value
                    .trimmingCharacters(in: CharacterSet.whitespaces)
                    .equalsIgnoringASCIICase("100-continue")
        }
        guard expectsContinue else { return headers }
        pendingClientBytes.append(serializeHead(startLine: "HTTP/1.1 100 Continue", headers: []))
        return headers.filter { !$0.name.equalsIgnoringASCIICase("expect") }
    }

    // MARK: - Body forwarding (no rewrite)

    private func forwardLength(remaining: Int, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let take = min(remaining, rxBuffer.count)
        let slice = Data(rxBuffer.prefix(take))
        rxBuffer.removeFirst(take)
        let left = remaining - take
        if !emitBridgeBody(slice, endStream: left == 0) {
            output.append(slice)
        }
        if left == 0 {
            flushSynthAfterResponse(into: &output)
            mode = .awaitingHead
        } else {
            mode = .forwardingLength(remaining: left)
        }
        return true
    }

    private func forwardChunked(reader: inout ChunkedReader, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let result: ChunkedReader.ForwardResult
        if let sink = responseIRSink {
            // Bridge: deliver decoded chunk payloads as IR — no h1 re-framing.
            result = reader.consumeForwardIR(&rxBuffer) { sink.http1ResponseBody($0, endStream: false) }
        } else {
            result = reader.consumeForward(&rxBuffer, into: &output)
        }
        switch result {
        case .needMore:
            mode = .forwardingChunked(reader: reader)
            return false
        case .complete:
            if emitBridgeBody(Data(), endStream: true) {
                mode = .awaitingHead
                return true
            }
            flushSynthAfterResponse(into: &output)
            mode = .awaitingHead
            return true
        case .malformed:
            // Chunked framing broke mid-body. Bridge: reset the stream. Main path: the head is
            // already on the wire, so we can't answer an error — synthesizing a `0\r\n\r\n`
            // terminator + passthrough would frame a truncated body as complete and then desync the
            // peer onto the next message. Fail closed (close both legs), matching mitmproxy.
            if bridgeResetIfNeeded() { return false }
            logger.warning("HTTP/1 \(host): chunked framing broke mid-body; closing the connection rather than truncating + desyncing")
            rxBuffer.removeAll(keepingCapacity: false)
            mode = .draining
            onHardClose?()
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
            // Parked: the resume finishes; a decompression-fail passthrough doesn't park.
            let parked = applyScriptsAndEmit(
                pending: pending,
                rawBody: accumulator,
                originalSizes: nil,
                resumeMode: .awaitingHead,
                into: &output
            )
            return !parked
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
            // No up-front length. On cap overflow we can neither buffer the whole body nor cleanly
            // stream the remainder un-rewritten (the head is withheld and decode-while-buffering has
            // already consumed the original chunk framing). Emitting the partial buffer with an
            // *exact* Content-Length would frame a silently-truncated body as complete — which a
            // client trusts (corrupt JSON / file). Fail honestly instead: answer a 502 on the
            // response phase (output is client-bound there; mirrors mitmproxy's RESPONSE_TOO_LARGE)
            // and close, never presenting a truncated body as whole.
            if accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                logger.warning("HTTP/1 \(host): chunked body exceeded \(MITMBodyCodec.maxBufferedBodyBytes) B buffer cap; failing closed rather than truncating to a fake-complete length")
                mode = .draining
                onFatalClose?()
                return false
            }
            mode = .rewritingChunked(pending: pending, accumulator: accumulator, reader: reader)
            return false
        case .complete(let originalSizes):
            let parked = applyScriptsAndEmit(
                pending: pending,
                rawBody: accumulator,
                originalSizes: originalSizes,
                resumeMode: .awaitingHead,
                into: &output
            )
            return !parked
        case .malformed:
            // Bridge: no head emitted yet (buffered rewrite), so reset the client stream rather
            // than strand it. Main path: the head is still withheld (we were buffering to rewrite),
            // so fail closed — answer 502 / close — instead of going passthrough, which would emit
            // raw body bytes with no response head and desync the peer.
            if bridgeResetIfNeeded() { return false }
            logger.warning("HTTP/1 \(host): chunked framing broke while buffering for a rewrite; failing closed")
            mode = .draining
            onFatalClose?()
            return true
        }
    }

    /// Accumulates a read-until-close body; `finish()` runs the script chain at EOF.
    /// On cap overflow emits the unmodified head + buffered bytes and goes passthrough.
    private func rewriteUntilClose(
        pending: PendingHead,
        accumulator: inout Data,
        into output: inout Data
    ) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        accumulator.append(rxBuffer.prefix(rxBuffer.count))
        rxBuffer.removeAll(keepingCapacity: false)
        if accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("HTTP/1 \(host): read-until-close body exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes) B; bypassing Script and forwarding verbatim")
            if bridgeResetIfNeeded() { return false }
            output.append(serializeHead(startLine: pending.startLine, headers: pending.headers))
            output.append(accumulator)
            flushSynthAfterResponse(into: &output)
            mode = .passthrough
            return true
        }
        mode = .rewritingUntilClose(pending: pending, accumulator: accumulator)
        return false
    }

    /// Drives the per-chunk streaming-script loop with a one-chunk lookahead for `isLast`.
    private func driveStreamingChunked(
        streaming: inout StreamingState,
        inner startInner: StreamingChunkedInner,
        into output: inout Data
    ) -> Bool {
        var currentInner = startInner
        while true {
            switch currentInner {
            case .sizeLine:
                guard let lineEnd = rxBuffer.firstCRLF(from: streaming.lineScanCursor) else {
                    if rxBuffer.count > Self.maxChunkLineBytes {
                        // Unterminated size line: malformed, or the buffer grows unbounded. The head
                        // is already on the wire, so fail closed (close both legs) rather than
                        // synthesize a terminator that frames the body as complete and desyncs.
                        logger.warning("HTTP/1 \(host): chunk-size line exceeded \(Self.maxChunkLineBytes) B without CRLF; closing the connection")
                        rxBuffer.removeAll(keepingCapacity: false)
                        mode = .draining
                        onHardClose?()
                        return true
                    }
                    streaming.lineScanCursor = max(0, rxBuffer.count - 1)
                    mode = .streamingChunked(streaming: streaming, inner: .sizeLine)
                    return false
                }
                let line = rxBuffer.subdata(in: 0..<lineEnd)
                rxBuffer.removeFirst(lineEnd + 2)
                streaming.lineScanCursor = 0
                guard let size = Self.parseHexSize(line) else {
                    // Malformed chunk-size line: the head already went out as chunked, so fail closed
                    // (close both legs) rather than synthesize a terminator that frames a truncated
                    // body as complete and then feeds garbage as the next response.
                    logger.warning("HTTP/1 \(host): malformed chunk-size line; closing the connection")
                    rxBuffer.removeAll(keepingCapacity: false)
                    mode = .draining
                    onHardClose?()
                    return true
                }
                if size == 0 {
                    // End of body: emit the held chunk with isLast=true, then drain trailers.
                    let finalChunk = streaming.pendingChunk ?? Data()
                    streaming.pendingChunk = nil
                    if emitOrParkStreamingFrame(
                        streaming: &streaming,
                        chunk: finalChunk,
                        isLast: true,
                        postFrame: .finalThenTrailer,
                        into: &output
                    ) {
                        return false // parked
                    }
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
                // A declared chunk size can be Int.max; on overflow flush the held
                // chunk, bypass the script, and emit the remainder verbatim.
                if left != 0, accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                    logger.warning("HTTP/1 \(host): streaming chunk exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes) B; bypassing Script and forwarding remainder verbatim")
                    if let held = streaming.pendingChunk {
                        streaming.pendingChunk = nil
                        if emitOrParkStreamingFrame(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            postFrame: .bypassRemainder(left: left, accumulator: accumulator),
                            into: &output
                        ) {
                            return false // parked
                        }
                    }
                    streaming.cursor.bypass = true
                    appendChunk(accumulator, into: &output)
                    mode = .streamingChunked(
                        streaming: streaming,
                        inner: .chunkData(remaining: left, accumulator: Data())
                    )
                    return false
                }
                if left == 0 {
                    // Chunk complete: flush the held chunk (isLast=false) and hold this one.
                    if let held = streaming.pendingChunk {
                        if emitOrParkStreamingFrame(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            postFrame: .hold(nextPending: accumulator, inner: .dataCRLF),
                            into: &output
                        ) {
                            return false // parked
                        }
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
                guard rxBuffer[0] == 0x0D,
                      rxBuffer[1] == 0x0A
                else {
                    // Missing inter-chunk CRLF: framing is broken and the head is on the wire.
                    // Fail closed (close both legs) rather than truncate-and-desync.
                    logger.warning("HTTP/1 \(host): missing CRLF after chunk data; closing the connection")
                    rxBuffer.removeAll(keepingCapacity: false)
                    mode = .draining
                    onHardClose?()
                    return true
                }
                rxBuffer.removeFirst(2)
                currentInner = .sizeLine
            case .trailerOrEnd:
                // RFC 9112 §7.1.2: forward trailer lines verbatim until the empty-line terminator.
                guard let lineEnd = rxBuffer.firstCRLF(from: streaming.lineScanCursor) else {
                    if rxBuffer.count > Self.maxChunkLineBytes {
                        // Oversized/garbage trailer with the final CRLF still unseen: the upstream
                        // framing is broken. We already emitted `0\r\n` but not the closing `\r\n`,
                        // so the peer sees an unterminated body — close both legs (the honest signal)
                        // rather than paper over it and desync onto trailer garbage.
                        logger.warning("HTTP/1 \(host): chunk trailer line exceeded \(Self.maxChunkLineBytes) B without CRLF; closing the connection")
                        rxBuffer.removeAll(keepingCapacity: false)
                        mode = .draining
                        onHardClose?()
                        return true
                    }
                    streaming.lineScanCursor = max(0, rxBuffer.count - 1)
                    mode = .streamingChunked(streaming: streaming, inner: .trailerOrEnd)
                    return false
                }
                let line = rxBuffer.subdata(in: 0..<lineEnd)
                rxBuffer.removeFirst(lineEnd + 2)
                streaming.lineScanCursor = 0
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                if line.isEmpty {
                    flushSynthAfterResponse(into: &output)
                    mode = .awaitingHead
                    return true
                }
            }
        }
    }

    /// Runs the streaming-script chain on `chunk`; returns true when parked.
    /// Empty results are dropped (the zero-size line is reserved for the terminator).
    private func emitOrParkStreamingFrame(
        streaming: inout StreamingState,
        chunk: Data,
        isLast: Bool,
        postFrame: StreamingPostFrame,
        into output: inout Data
    ) -> Bool {
        if streaming.cursor.bypass {
            streaming.frameIndex += 1
            if !chunk.isEmpty {
                appendChunk(chunk, into: &output)
            }
            return false
        }
        let frameCtx = MITMScriptEngine.FrameContext(
            phase: phase,
            method: streamingMethod(streaming),
            url: streamingURL(streaming),
            status: streamingStatus(streaming),
            headers: streaming.headers,
            frameIndex: streaming.frameIndex,
            isLast: isLast,
            ruleSetID: ruleSetID
        )
        // cursor is shared by reference so engine mutations are visible on resume.
        let captured = streaming
        mode = .awaitingScript
        MITMScriptTransform.applyFrame(
            chunk,
            rules: rules,
            frameContext: frameCtx,
            cursor: streaming.cursor,
            engineProvider: scriptEngineProvider,
            resumeOn: lwipQueue
        ) { [weak self] result in
            self?.resumeStreamingFrame(result: result, streaming: captured, postFrame: postFrame)
        }
        return true
    }

    /// Resume for a parked streaming frame: appends the result and applies the
    /// captured continuation.
    private func resumeStreamingFrame(
        result: MITMScriptTransform.StreamFrameResult,
        streaming: StreamingState,
        postFrame: StreamingPostFrame
    ) {
        guard !torn else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        var streaming = streaming
        streaming.frameIndex += 1
        if !result.body.isEmpty {
            appendChunk(result.body, into: &resumed)
        }
        switch postFrame {
        case .hold(let nextPending, let inner):
            streaming.pendingChunk = nextPending
            mode = .streamingChunked(streaming: streaming, inner: inner)
        case .finalThenTrailer:
            resumed.append(contentsOf: "0\r\n".utf8)
            mode = .streamingChunked(streaming: streaming, inner: .trailerOrEnd)
        case .bypassRemainder(let left, let accumulator):
            streaming.cursor.bypass = true
            appendChunk(accumulator, into: &resumed)
            mode = .streamingChunked(
                streaming: streaming,
                inner: .chunkData(remaining: left, accumulator: Data())
            )
        }
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
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
        return parseHTTPStatusCode(parts[1])
    }

    /// Parses the hex chunk-size, ignoring any extensions after `;`.
    fileprivate static func parseHexSize(_ data: Data) -> Int? {
        // latin-1 never fails (a non-ASCII byte in a chunk extension shouldn't kill an otherwise-valid
        // body); the hex chunk-size itself is still validated as ASCII hex digits below.
        guard let raw = String(data: data, encoding: .isoLatin1) else { return nil }
        let head = raw.split(separator: ";", maxSplits: 1).first.map(String.init) ?? raw
        let trimmed = head.trimmingCharacters(in: CharacterSet.whitespaces)
        // RFC 9112 §7.1: unsigned hex only. `Int(_:radix:)` accepts `-`/`+`,
        // and a hostile `-1` would trap in MITMByteBuffer's range math.
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isHexDigit && $0.isASCII }),
              let size = Int(trimmed, radix: 16), size >= 0 else { return nil }
        return size
    }

    /// Drops a Content-Length body, keeping the connection framed for keep-alive.
    private func discardLength(remaining: Int) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let take = min(remaining, rxBuffer.count)
        rxBuffer.removeFirst(take)
        let left = remaining - take
        mode = left == 0 ? .awaitingHead : .discardingLength(remaining: left)
        return true
    }

    private func discardChunked(reader: inout ChunkedReader, afterSynth: Bool, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        var sink = Data()
        let result = reader.consumeBuffered(&rxBuffer, into: &sink)
        switch result {
        case .needMore:
            mode = .discardingChunked(reader: reader, afterSynth: afterSynth)
            return false
        case .complete:
            // Synth-after boundary; flush only for over-cap rewrite tails
            // (post-synth discards are request streams).
            if !afterSynth {
                flushSynthAfterResponse(into: &output)
            }
            mode = .awaitingHead
            return true
        case .malformed:
            // Boundary lost; passthrough would leak post-synth bytes upstream
            // or desync the receiver, so blackhole instead.
            mode = .draining
            return true
        }
    }

    // MARK: - Script application + head rebuild

    /// Decompresses the body and dispatches the script chain. Returns true when
    /// parked; false on decompression failure (emits verbatim, sets `resumeMode`).
    @discardableResult
    private func applyScriptsAndEmit(
        pending: PendingHead,
        rawBody: Data,
        originalSizes: [Int]?,
        resumeMode: Mode,
        into output: inout Data
    ) -> Bool {
        let body: Data
        if pending.codec.requiresDecompression {
            guard let decoded = MITMBodyCodec.decompress(rawBody, plan: pending.codec, host: host) else {
                if responseIRSink != nil {
                    // Couldn't decompress to run the rule — deliver the head with its Content-Encoding
                    // intact plus the original (still-encoded) body; the client decodes it (rule skipped).
                    emitResponseHead(startLine: pending.startLine, headers: pending.headers, bodyFollows: !rawBody.isEmpty, into: &output)
                    if !rawBody.isEmpty { _ = emitBridgeBody(rawBody, endStream: true) }
                    mode = resumeMode
                    return false
                }
                if phase == .httpRequest {
                    logRequest(startLine: pending.startLine)
                }
                output.append(serializeHead(startLine: pending.startLine, headers: pending.headers))
                if let originalSizes {
                    output.append(rechunk(body: rawBody, originalSizes: originalSizes))
                } else {
                    output.append(rawBody)
                }
                flushSynthAfterResponse(into: &output)
                mode = resumeMode
                return false
            }
            body = decoded
        } else {
            body = rawBody
        }

        let message = buildMessage(
            startLine: pending.startLine,
            headers: pending.headers,
            body: body,
            originatingRequest: pending.originatingRequest
        )
        _ = originalSizes // chunked re-encoding is unused once we collapse to Content-Length
        mode = .awaitingScript
        MITMScriptTransform.apply(
            message,
            rules: rules,
            engineProvider: scriptEngineProvider,
            resumeOn: lwipQueue
        ) { [weak self] outcome in
            self?.resumeBufferedBody(outcome: outcome, pending: pending, resumeMode: resumeMode)
        }
        return true
    }

    /// Resume for the buffered script path: emits the rebuilt head + body
    /// (or queues a synth response) and resumes the pass.
    private func resumeBufferedBody(
        outcome: MITMScriptTransform.Outcome,
        pending: PendingHead,
        resumeMode: Mode
    ) {
        guard !torn else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        switch outcome {
        case .message(let result):
            let finalStartLine = rebuildStartLine(from: result, fallback: pending.startLine)
            var finalHeaders = strippedFramingHeaders(result.headers, dropContentEncoding: pending.codec.requiresDecompression)
            // Collapse to a single Content-Length unit (original may have been chunked).
            finalHeaders.append((name: "Content-Length", value: String(result.body.count)))
            if phase == .httpRequest {
                logRequest(startLine: finalStartLine)
            }
            if responseIRSink != nil {
                emitResponseHead(startLine: finalStartLine, headers: finalHeaders, bodyFollows: !result.body.isEmpty, into: &resumed)
                if !result.body.isEmpty { _ = emitBridgeBody(result.body, endStream: true) }
            } else {
                resumed.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
                if !result.body.isEmpty {
                    resumed.append(result.body)
                }
            }
        case .synthesizedResponse(let response):
            if responseIRSink != nil {
                // Response-phase Anywhere.respond shouldn't occur on the bridge; reset, don't mis-frame.
                _ = bridgeResetIfNeeded()
                finishDrivePass(resumed)
                return
            }
            queueSynthesizedResponse(response)
        }
        flushSynthAfterResponse(into: &resumed)
        mode = resumeMode
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    /// Resume for the no-body script path: emits the scripted head (or queues
    /// a synth response) and resumes from `.awaitingHead`.
    private func resumeHeadNoBody(
        outcome: MITMScriptTransform.Outcome,
        fallbackStartLine: String,
        originatingMethod: String?
    ) {
        guard !torn else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        switch outcome {
        case .message(let result):
            emitScriptedHead(
                fallbackStartLine: fallbackStartLine,
                result: result,
                codecRequiresDecompression: false,
                originatingMethod: originatingMethod,
                into: &resumed
            )
        case .synthesizedResponse(let response):
            if responseIRSink != nil {
                _ = bridgeResetIfNeeded()
                finishDrivePass(resumed)
                return
            }
            queueSynthesizedResponse(response)
        }
        flushSynthAfterResponse(into: &resumed)
        mode = .awaitingHead
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    /// Emits the rebuilt head after scripts ran with no body. No-body statuses
    /// omit Content-Length (RFC 9110 §15.2/§15.3); HEAD responses keep the
    /// server's framing headers verbatim.
    private func emitScriptedHead(
        fallbackStartLine: String,
        result: HTTPMessage,
        codecRequiresDecompression: Bool,
        originatingMethod: String?,
        into output: inout Data
    ) {
        let finalStartLine = rebuildStartLine(from: result, fallback: fallbackStartLine)
        let isHeadResponse = phase == .httpResponse
            && originatingMethod?.uppercased() == "HEAD"

        let finalHeaders: [Header]
        if isHeadResponse {
            // Preserve server framing headers; the receiver knows not to read a body.
            finalHeaders = codecRequiresDecompression
                ? result.headers.filter { !$0.name.equalsIgnoringASCIICase("content-encoding") }
                : result.headers
        } else {
            var stripped = strippedFramingHeaders(result.headers, dropContentEncoding: codecRequiresDecompression)
            let preserveNoBody = result.body.isEmpty
                && isNoBodyStatus(responseStatusCode(from: finalStartLine))
            if !preserveNoBody {
                stripped.append((name: "Content-Length", value: String(result.body.count)))
            }
            finalHeaders = stripped
        }

        if phase == .httpRequest {
            logRequest(startLine: finalStartLine)
        }
        let hasBody = !result.body.isEmpty && !isHeadResponse
        if responseIRSink != nil {
            emitResponseHead(startLine: finalStartLine, headers: finalHeaders, bodyFollows: hasBody, into: &output)
            if hasBody { _ = emitBridgeBody(result.body, endStream: true) }
        } else {
            output.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
            // RFC 9110 §15.2: HEAD responses must not carry a body.
            if hasBody {
                output.append(result.body)
            }
        }
    }

    /// Statuses that forbid a body (RFC 9110 §15): 1xx except 101, 204, 205, 304.
    private func isNoBodyStatus(_ status: Int?) -> Bool {
        guard let status else { return false }
        switch status {
        case 204, 304:
            // RFC 9112 §6.3's framing no-body set is 1xx/204/304 (plus HEAD and CONNECT-2xx). 205 is
            // *not* in it — though it carries no content (RFC 9110 §15.3.6), `bodyFraming` honors an
            // explicit Content-Length/Transfer-Encoding on a 205 and only then defaults it to empty.
            return true
        default:
            return (100..<200).contains(status) && status != 101
        }
    }

    private func responseStatusCode(from startLine: String) -> Int? {
        guard startLine.hasPrefix("HTTP/") else { return nil }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        return parseHTTPStatusCode(parts[1])
    }

    /// Strips the framing headers we re-emit ourselves.
    private func strippedFramingHeaders(
        _ headers: [Header],
        dropContentEncoding: Bool
    ) -> [Header] {
        headers.filter { entry in
            if entry.name.equalsIgnoringASCIICase("content-length")
                || entry.name.equalsIgnoringASCIICase("transfer-encoding") {
                return false
            }
            if dropContentEncoding, entry.name.equalsIgnoringASCIICase("content-encoding") {
                return false
            }
            return true
        }
    }

    // MARK: - Re-chunking (chunked decompression-failure passthrough only)

    /// Re-emits `body` as chunked with the original sizes; the last chunk absorbs any delta.
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

    /// Outcome of `parseHead`, distinguishing the two reasons it can decline a head so the caller
    /// can act differently: a non-HTTP / tolerable head is forwarded verbatim (`.forward`), while an
    /// HTTP head carrying a request-smuggling / injection framing violation fails closed
    /// (`.smuggling`) instead of being relayed.
    private enum ParsedHeadResult {
        case ok(ParsedHead)
        case forward
        case smuggling
    }

    private func parseHead(_ data: Data) -> ParsedHeadResult {
        // ISO-8859-1, not ASCII: HTTP/1 header octets are a byte string (RFC 9110 §5.5 obs-text), and
        // latin-1 maps every byte 1:1 so it never fails. An ASCII decode returned nil on any byte > 0x7F
        // (common in real Set-Cookie / Content-Disposition / Server fields), which dropped the whole
        // connection to verbatim passthrough and silently disabled all rewriting. `serializeHead`
        // re-emits these via `appendHeaderFieldBytes`, so the original octets round-trip exactly.
        guard let raw = String(data: data, encoding: .isoLatin1) else { return .forward }
        let lines = raw.components(separatedBy: "\r\n")
        guard let startLine = lines.first, !startLine.isEmpty else { return .forward }
        guard isHTTPStartLine(startLine) else { return .forward }
        // A lone CR/LF survives the exact-CRLF split and could smuggle a header
        // on re-emission; NUL is forbidden too (RFC 9112 §2.2).
        if Self.containsControlChars(startLine) { return .smuggling }
        // RFC 9112 §3: a request-line is exactly `method SP request-target SP HTTP-version`. The
        // incoming target is otherwise re-emitted verbatim, so validate it here — an embedded
        // SP/TAB/DEL/CTL is a target-confusion / request-smuggling primitive, and would also desync
        // the URL gate (which splits on SP). Responses skip this: the reason phrase may contain SP.
        if phase == .httpRequest {
            let parts = startLine.split(separator: " ", omittingEmptySubsequences: false)
            guard parts.count == 3, Self.isValidRequestTarget(String(parts[1])) else {
                return .smuggling
            }
        }
        // RFC 9112 §5.2 / RFC 7230 §3.2.4: obs-fold is deprecated. Rather than forward a folded head
        // verbatim — which would let a field value split across a fold skip the CL/TE smuggling
        // checks below — unfold it (append each continuation to the prior field value with a single
        // SP) and validate the unfolded result.
        var headerLines: [String] = []
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            if let first = line.utf8.first, first == 0x20 || first == 0x09 {
                guard !headerLines.isEmpty else { return .smuggling } // continuation with no field
                let continuation = line.drop { $0 == " " || $0 == "\t" }
                headerLines[headerLines.count - 1] += " " + String(continuation)
                continue
            }
            headerLines.append(line)
        }
        var headers: [Header] = []
        var contentLengthValues: [String] = []
        var transferEncodingValues: [String] = []
        for line in headerLines {
            // RFC 9112 §5.1: no colon is a syntax error; forward verbatim (it isn't itself a
            // CL/TE framing manipulation) and let the upstream reject it.
            guard let colon = line.firstIndex(of: ":") else { return .forward }
            let name = String(line[..<colon])
            let value = String(line[line.index(after: colon)...])
                .trimmingCharacters(in: CharacterSet.whitespaces)
            // RFC 9110 §5.6.2: SP/CTL in a field-name is the classic obfuscated-TE smuggle.
            guard isValidHTTPHeaderName(name) else { return .smuggling }
            // CR/LF/NUL in a field-value would split the line on re-emission.
            if Self.containsControlChars(value) { return .smuggling }
            if name.equalsIgnoringASCIICase("content-length") {
                contentLengthValues.append(
                    value.trimmingCharacters(in: CharacterSet.whitespaces)
                )
            } else if name.equalsIgnoringASCIICase("transfer-encoding") {
                transferEncodingValues.append(value)
            }
            headers.append((name: name, value: value))
        }
        // Reject any Content-Length that `bodyFraming` wouldn't honor — a
        // forward/frame divergence is a request-smuggling vector.
        if contentLengthValues.contains(where: { !Self.isCleanContentLength($0) }) {
            return .smuggling
        }
        // RFC 9112 §6.1: a request's Transfer-Encoding must end in `chunked` — a non-chunked final
        // coding is unframable and a smuggling vector. A *response* may carry a non-chunked
        // transfer-coding (e.g. `gzip`), framed by connection close (RFC 9112 §6.3); `bodyFraming`
        // resolves that to `.readUntilClose`. Multiple TE field lines are always a smuggling vector.
        if !transferEncodingValues.isEmpty {
            if transferEncodingValues.count > 1 { return .smuggling }
            // RFC 9112 §6.1 / RFC 9110: Transfer-Encoding is an HTTP/1.1-only feature. A TE on an
            // HTTP/1.0 message is a smuggling vector — HTTP/1.0 hops ignore TE and frame by close, so
            // two hops disagree on the body boundary (mitmproxy rejects this in validate.py).
            guard startLineIsHTTP11(startLine) else { return .smuggling }
            // RFC 9112 §6.1: `chunked` must be applied at most once and only as the final coding.
            // `chunked, chunked` (or chunked in a non-final position) means two hops can disagree on
            // the body length — reject it on both phases, matching mitmproxy's TE allow-list.
            let teTokens = transferEncodingValues[0]
                .split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: CharacterSet.whitespaces) }
            let chunkedCount = teTokens.filter { $0.equalsIgnoringASCIICase("chunked") }.count
            if chunkedCount > 1 { return .smuggling }
            if chunkedCount == 1, teTokens.last?.equalsIgnoringASCIICase("chunked") != true {
                return .smuggling
            }
            if !Self.transferEncodingIsChunked(transferEncodingValues[0]), phase == .httpRequest {
                return .smuggling
            }
        }
        // RFC 9112 §6.3.5: differing Content-Length values are a primary smuggling vector.
        let uniqueLengths = Set(contentLengthValues)
        if uniqueLengths.count > 1 {
            return .smuggling
        }
        // RFC 9112 §6.3: Transfer-Encoding overrides Content-Length. When both are present, strip
        // Content-Length so the two framing sources can't disagree (the classic TE+CL smuggle).
        if !transferEncodingValues.isEmpty && !contentLengthValues.isEmpty {
            headers = headers.filter {
                !$0.name.equalsIgnoringASCIICase("content-length")
            }
        } else if contentLengthValues.count > 1 {
            // Duplicate identical Content-Length values: collapse to one.
            var filtered = headers.filter {
                !$0.name.equalsIgnoringASCIICase("content-length")
            }
            filtered.append((name: "Content-Length", value: contentLengthValues[0]))
            headers = filtered
        }
        return .ok(ParsedHead(startLine: startLine, headers: headers))
    }

    /// Pure non-negative integer Content-Length; rejects `+5`, `5 5`, overflow
    /// (RFC 9112 §6.3). Shared by `parseHead` and `bodyFraming` so they can't drift.
    static func isCleanContentLength(_ trimmed: String) -> Bool {
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isASCII && $0.isNumber }) else { return false }
        guard let length = Int(trimmed), length >= 0 else { return false }
        return true
    }

    /// True when the start line declares HTTP/1.1 — a request line ends with the version, a status
    /// line begins with it. Transfer-Encoding is valid only for HTTP/1.1 (RFC 9112 §6.1).
    private func startLineIsHTTP11(_ startLine: String) -> Bool {
        phase == .httpRequest ? startLine.hasSuffix(" HTTP/1.1") : startLine.hasPrefix("HTTP/1.1")
    }

    /// True when `chunked` is the final Transfer-Encoding coding (RFC 9112 §6.1).
    /// Shared by `parseHead` and `bodyFraming` so their decisions can't diverge.
    static func transferEncodingIsChunked(_ value: String) -> Bool {
        let last = value
            .split(separator: ",", omittingEmptySubsequences: false)
            .last?
            .trimmingCharacters(in: CharacterSet.whitespaces)
        return last?.equalsIgnoringASCIICase("chunked") == true
    }

    /// True when `s` contains CR, LF, or NUL — bytes that would split a line on re-emission.
    private static func containsControlChars(_ s: String) -> Bool {
        for byte in s.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return true
            }
        }
        return false
    }

    private func isHTTPStartLine(_ line: String) -> Bool {
        if line.hasPrefix("HTTP/1.") { return true }
        // Method must be a valid RFC 9110 §9.1 token — the version suffix alone
        // would accept "AB/CD / HTTP/1.1".
        guard line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0") else {
            return false
        }
        guard let firstSpace = line.firstIndex(of: " ") else { return false }
        let method = String(line[..<firstSpace])
        return Self.isValidMethodToken(method)
    }

    /// 1xx interim response (not 101): the log record is peeked, not popped.
    private func isInterimResponseStartLine(_ startLine: String) -> Bool {
        guard startLine.hasPrefix("HTTP/1.") else { return false }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, let status = parseHTTPStatusCode(parts[1]) else { return false }
        return (100..<200).contains(status) && status != 101
    }

    /// Emits the (rewritten) response head: HTTP/1.1 bytes on the main path, or IR to the bridge
    /// sink. `bodyFollows` sets the IR END_STREAM flag (no body ⇒ the stream ends on the head).
    private func emitResponseHead(startLine: String, headers: [Header], bodyFollows: Bool, into output: inout Data) {
        if let sink = responseIRSink {
            sink.http1ResponseHead(status: responseStatusCode(from: startLine) ?? 0, headers: headers, endStream: !bodyFollows)
        } else {
            output.append(serializeHead(startLine: startLine, headers: headers))
        }
    }

    /// IR-mode body emission for the bridge. Returns true when handled via IR (the caller must then
    /// NOT append framed bytes); false on the main path, where the caller frames bytes as usual.
    private func emitBridgeBody(_ data: Data, endStream: Bool) -> Bool {
        guard let sink = responseIRSink else { return false }
        sink.http1ResponseBody(data, endStream: endStream)
        return true
    }

    /// IR-mode reset for the bridge: surfaces a malformed / unbridgeable response and drains. Returns
    /// true when handled via IR; the main (byte) path keeps its passthrough/terminator behavior.
    private func bridgeResetIfNeeded() -> Bool {
        guard let sink = responseIRSink else { return false }
        sink.http1ResponseReset()
        mode = .draining
        rxBuffer.removeAll(keepingCapacity: false)
        return true
    }

    private func serializeHead(startLine: String, headers: [Header]) -> Data {
        // Defense-in-depth: enforce the no-CR/LF/NUL invariant at the serialization boundary.
        let safeHeaders = headers.filter { entry in
            guard !Self.containsControlChars(entry.name),
                  !Self.containsControlChars(entry.value) else {
                logger.warning("HTTP/1 \(host): dropping header with CR/LF/NUL from serialized head: \(entry.name)")
                return false
            }
            return true
        }
        // Pre-size to avoid Data reallocation on heads with many headers.
        var size = startLine.utf8.count + 4
        for (name, value) in safeHeaders {
            size += name.utf8.count + 2 + value.utf8.count + 2
        }
        var out = Data(capacity: size)
        // Emit as ISO-8859-1 bytes so a header octet parsed as latin-1 round-trips exactly (a plain
        // `.utf8` would re-encode a 0x80–0xFF octet as a 2-byte sequence, corrupting it).
        out.appendHeaderFieldBytes(startLine)
        out.append(0x0D); out.append(0x0A)
        for (name, value) in safeHeaders {
            out.appendHeaderFieldBytes(name)
            out.append(0x3A); out.append(0x20) // ':'  ' '
            out.appendHeaderFieldBytes(value)
            out.append(0x0D); out.append(0x0A)
        }
        out.append(0x0D); out.append(0x0A)
        return out
    }

    /// Serializes an `Anywhere.respond(...)` payload as HTTP/1.1 and queues it,
    /// sanitizing headers so script-injected CRLF can't split the response.
    private func queueSynthesizedResponse(_ response: MITMScriptEngine.SynthesizedResponse) {
        let reason = canonicalReasonPhrase(for: response.status)
        let startLine = "HTTP/1.1 \(response.status) \(reason)"
        var headers = response.sanitizedHeaders(lowercaseNames: false) { name in
            logger.warning("[MITM][JS] HTTP/1 \(host): Anywhere.respond dropping invalid header: \(name)")
        }
        let body = response.truncatedBody(cap: Self.maxSynthesizedResponseBodyBytes) { size in
            logger.warning("[MITM][JS] HTTP/1 \(host): Anywhere.respond body \(size) B exceeds memory cap \(Self.maxSynthesizedResponseBodyBytes) B; truncating")
        }
        headers = response.withDateStamp(headers, lowercaseName: false)
        headers.append((name: "Content-Length", value: String(body.count)))
        var bytes = serializeHead(startLine: startLine, headers: headers)
        if !body.isEmpty {
            bytes.append(body)
        }
        // Pipeline order (RFC 9112 §9.3.2): if an earlier request still awaits its
        // response, attach the synth bytes to the newest in-flight record.
        if requestLog.isHTTP1QueueEmpty {
            pendingClientBytes.append(bytes)
        } else {
            requestLog.attachSynthAfterLastHTTP1(bytes)
        }
    }

    /// RFC 9110 §9.1: method is a `token`; blocks a script-supplied value from
    /// smuggling a full request line.
    private static func isValidMethodToken(_ s: String) -> Bool {
        return isValidHTTPHeaderName(s)
    }

    /// RFC 9112 §3.2: rejects SP/CTL/DEL in script- or regex-produced request-targets.
    private static func isValidRequestTarget(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        for byte in s.utf8 {
            if byte < 0x21 || byte == 0x7F {
                return false
            }
        }
        return true
    }

    // MARK: - Framing decision

    private enum Framing {
        case none
        case contentLength(Int)
        case chunked
        case readUntilClose
        case switchingProtocols
    }

    private func bodyFraming(
        startLine: String,
        headers: [Header],
        originatingMethod: String? = nil
    ) -> Framing {
        var responseStatus: Int?
        if phase == .httpResponse {
            // RFC 9110 §15.2: HEAD responses never carry a body regardless of Content-Length.
            if let method = originatingMethod,
               method.uppercased() == "HEAD" {
                return .none
            }
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let status = parseHTTPStatusCode(parts[1]) {
                responseStatus = status
                // RFC 9110 §9.3.6: 2xx to CONNECT makes the connection an opaque
                // tunnel; treat like 101.
                if (200..<300).contains(status),
                   originatingMethod?.uppercased() == "CONNECT" {
                    return .switchingProtocols
                }
                if status == 101 { return .switchingProtocols }
                // RFC 9110 §15: 1xx (except 101), 204, 304 carry no body regardless of CL/TE.
                if isNoBodyStatus(status) { return .none }
            }
        }
        // RFC 9112 §6.3: TE takes precedence over Content-Length.
        // `parseHead` already normalized the TE+CL smuggling case.
        var transferEncoding: String?
        var contentLength: String?
        for (name, value) in headers {
            if name.equalsIgnoringASCIICase("transfer-encoding") {
                transferEncoding = value
            } else if name.equalsIgnoringASCIICase("content-length") {
                contentLength = value
            }
        }
        if let te = transferEncoding {
            // RFC 9112 §6.1: `chunked` must be the final coding.
            if Self.transferEncodingIsChunked(te) {
                return .chunked
            }
        }
        if let cl = contentLength {
            let trimmed = cl.trimmingCharacters(in: CharacterSet.whitespaces)
            // `Int` accepts a leading `+`; use the same gate as `parseHead`.
            if Self.isCleanContentLength(trimmed), let length = Int(trimmed) {
                return length == 0 ? .none : .contentLength(length)
            }
        }
        // 205 Reset Content carries no content (RFC 9110 §15.3.6); with no explicit CL/TE above, frame
        // it as empty rather than read-until-close — the latter would hang a keep-alive connection
        // waiting for an EOF that never comes.
        if responseStatus == 205 { return .none }
        return phase == .httpRequest ? .none : .readUntilClose
    }

    /// Warns when a buffered script de-streams a streaming response (SSE etc.). Advisory only.
    private func warnIfBufferedScriptDeStreams(_ headers: [Header]) {
        let contentType = firstHeaderValue(headers, name: "content-type")
        guard phase == .httpResponse,
              MITMScriptTransform.isStreamingMediaType(contentType) else { return }
        logger.warning("\(host): buffered Script on a streaming response. Switch to Stream Script to rewrite frames as they arrive.")
    }

    /// All values for `name` joined by `", "` (RFC 9110 §5.3) — first-value-only
    /// would let a second `Content-Encoding` slip past undecoded.
    private func combinedHeaderValue(_ headers: [Header], name: String) -> String? {
        var parts: [String] = []
        for (n, v) in headers where n.equalsIgnoringASCIICase(name) {
            parts.append(v)
        }
        if parts.isEmpty { return nil }
        if parts.count == 1 { return parts[0] }
        return parts.joined(separator: ", ")
    }

    // MARK: - Rule application (head-time)

    /// Forces the `Host` header to `effectiveAuthority` when a transparent
    /// rewrite has changed the upstream host.
    private func applyAuthorityRewrite(_ headers: [Header]) -> [Header] {
        guard phase == .httpRequest, let authority = effectiveAuthority else {
            return headers
        }
        var result = headers.filter { !$0.name.equalsIgnoringASCIICase("host") }
        result.append((name: "Host", value: authority))
        return result
    }

    private enum RewriteOutcome {
        case rewritten(String)
        case synthesize(MITMScriptEngine.SynthesizedResponse)
    }

    /// Applies the first matching `rewrite` rule: `transparent` rewrites the
    /// request-target and sets the upstream; synthesize sub-modes return a canned response.
    private func applyRewrite(_ startLine: String) -> RewriteOutcome {
        guard phase == .httpRequest else { return .rewritten(startLine) }
        guard rules.contains(where: {
            if case .rewrite = $0.operation { return true }
            return false
        }) else { return .rewritten(startLine) }

        // Each request re-resolves its own upstream. Clear any target a *previous* request on this
        // keep-alive leg set, so a later request that matches no transparent rewrite resolves to the
        // original origin (and the session tears the leg down if that differs from the dialed host)
        // rather than inheriting the prior request's target and `Host`. Without this, request #2 on a
        // connection whose request #1 rewrote A→B is misrouted to B.
        effectiveAuthority = nil
        resolvedUpstream = nil

        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return .rewritten(startLine) }
        let method = String(parts[0])
        let target = String(parts[1])
        let version = String(parts[2])

        if target == "*" { return .rewritten(startLine) } // RFC 9112 §3.2.4 asterisk-form

        for rule in rules {
            guard case .rewrite(let action) = rule.operation else { continue }
            guard rule.matchesURL("https://\(host)\(target)") else { continue }
            switch action {
            case .transparent(let replacement):
                // Re-validate at use time as a backstop (validated at load time too).
                guard Self.isValidRequestTarget(replacement.requestTarget) else {
                    logger.warning("HTTP/1 \(host): rewrite produced an invalid request-target; skipping rule")
                    continue
                }
                effectiveAuthority = replacement.authority
                resolvedUpstream = (host: replacement.host, port: replacement.port)
                return .rewritten("\(method) \(replacement.requestTarget) \(version)")
            case .redirect302, .reject200Text, .reject200Gif, .reject200Data:
                guard let response = MITMRespondBuilder.response(for: action) else { continue }
                return .synthesize(response)
            }
        }
        return .rewritten(startLine)
    }

    /// Short-circuits a 302 / reject request: queues the synth response and
    /// discards the request body. Not logged — no upstream round-trip will pop
    /// the record, so logging would desync the FIFO.
    private func synthesizeRequestResponse(
        _ response: MITMScriptEngine.SynthesizedResponse,
        requestHeaders: [Header],
        into output: inout Data
    ) -> Bool {
        queueSynthesizedResponse(response)
        switch bodyFraming(startLine: "", headers: requestHeaders, originatingMethod: nil) {
        case .contentLength(let length) where length > 0:
            mode = .discardingLength(remaining: length)
        case .chunked:
            mode = .discardingChunked(reader: ChunkedReader(), afterSynth: true)
        case .none, .contentLength, .readUntilClose, .switchingProtocols:
            mode = .awaitingHead
        }
        return true
    }

    private func applyHeaderRules(_ headers: [Header], requestURL: String?) -> [Header] {
        guard !rules.isEmpty else { return headers }
        var current = headers
        for rule in rules {
            guard rule.matchesURL(requestURL) else { continue }
            switch rule.operation {
            case .headerAdd(let name, let value):
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                current.removeAll { $0.name.equalsIgnoringASCIICase(nameLower) }
            case .headerReplace(let name, let value):
                current = current.map { entry in
                    entry.name.equalsIgnoringASCIICase(name) ? (name: name, value: value) : entry
                }
            case .rewrite, .script, .streamScript, .bodyReplace, .bodyJSON:
                continue
            }
        }
        return current
    }

    /// URL used to gate rule matches; nil fails the gate closed.
    private func requestURLForGating(
        startLine: String,
        originatingRequest: MITMRequestLog.Record?
    ) -> String? {
        switch phase {
        case .httpRequest:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 2 else { return nil }
            let target = String(parts[1])
            return target == "*" ? nil : "https://\(host)\(target)" // asterisk-form: no match
        case .httpResponse:
            return originatingRequest?.url
        }
    }

    // MARK: - Message build / head rebuild

    private func buildMessage(
        startLine: String,
        headers: [Header],
        body: Data,
        originatingRequest: MITMRequestLog.Record?
    ) -> HTTPMessage {
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
            if parts.count >= 2, let code = parseHTTPStatusCode(parts[1]) {
                status = code
            }
            method = originatingRequest?.method
            url = originatingRequest?.url
        }
        return HTTPMessage(
            phase: phase,
            method: method,
            url: url,
            status: status,
            headers: headers,
            body: body,
            ruleSetID: ruleSetID
        )
    }

    /// Rebuilds the start line from a script-mutated message, preserving the
    /// original HTTP version; falls back to the original line on missing fields.
    private func rebuildStartLine(
        from message: HTTPMessage,
        fallback: String
    ) -> String {
        let parts = fallback.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        switch message.phase {
        case .httpRequest:
            guard let method = message.method, let url = message.url else {
                return fallback
            }
            guard Self.isValidMethodToken(method) else {
                logger.warning("[MITM][JS] HTTP/1 \(host): dropping invalid method '\(method)' from Script")
                return fallback
            }
            // For a relative script URL fall back to the original target
            // (absolute-form is legal but confuses upstreams).
            let originalTarget = parts.count >= 2 ? String(parts[1]) : "/"
            let candidateTarget = pathAndQuery(fromURL: url) ?? originalTarget
            // Guard against SP/CR/LF/CTL in a script-built URL splitting the start line.
            guard Self.isValidRequestTarget(candidateTarget) else {
                logger.warning("[MITM][JS] HTTP/1 \(host): dropping invalid request-target from Script")
                return fallback
            }
            let version = parts.count >= 3 ? String(parts[2]) : "HTTP/1.1"
            return "\(method) \(candidateTarget) \(version)"
        case .httpResponse:
            guard let status = message.status else { return fallback }
            let version = parts.count >= 1 ? String(parts[0]) : "HTTP/1.1"
            let reason = canonicalReasonPhrase(for: status)
            return "\(version) \(status) \(reason)"
        }
    }

    /// Returns the path-and-query from an absolute URL, or nil for relative references.
    private func pathAndQuery(fromURL url: String) -> String? {
        guard let components = URLComponents(string: url) else { return nil }
        if components.scheme == nil && components.host == nil {
            return nil
        }
        var target = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        if let query = components.percentEncodedQuery {
            target += "?\(query)"
        }
        return target
    }

    /// Canonical reason phrase, or `""` for unrecognised codes (clients ignore it, RFC 9112 §4).
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

    /// Records the request's method and URL for the response stream's script ctx.
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

/// Streaming chunked-transfer decoder: `consumeForward` re-emits framing verbatim;
/// `consumeBuffered` emits decoded data and returns original chunk sizes.
private final class ChunkedReader {
    private enum State {
        case sizeLine
        case chunkData(remaining: Int, originalSize: Int)
        case dataCRLF(originalSize: Int)
        case trailerOrEnd
    }

    private var state: State = .sizeLine
    private var sizes: [Int] = []
    /// CRLF scan resume offset (O(n) total, not O(n²)); reset when a line is consumed.
    private var scanCursor = 0

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

    func consumeForward(_ buffer: inout MITMByteBuffer, into output: inout Data) -> ForwardResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let line = buffer.subdata(in: 0..<lineEnd)
                // Validate before forwarding: the caller's synthesized `0\r\n\r\n`
                // recovery only frames cleanly if the bad size line was never emitted.
                guard let size = MITMHTTP1Stream.parseHexSize(line) else { return .malformed }
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
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
            case .dataCRLF:
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[0] == 0x0D, buffer[1] == 0x0A else {
                    return .malformed
                }
                output.append(0x0D); output.append(0x0A)
                buffer.removeFirst(2)
                // Forward mode never re-chunks; don't accumulate sizes.
                state = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let line = buffer.subdata(in: 0..<lineEnd)
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if line.isEmpty {
                    return .complete
                }
            }
        }
        return .needMore
    }

    /// Like `consumeForward`, but delivers each decoded chunk payload to `deliver` instead of
    /// re-framing it as HTTP/1.1 (the h2→h1 bridge frames payloads as HTTP/2 DATA). Trailer lines
    /// are dropped. `state` / `scanCursor` are shared, so a reader is used in exactly one mode for
    /// its lifetime.
    func consumeForwardIR(_ buffer: inout MITMByteBuffer, deliver: (Data) -> Void) -> ForwardResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let line = buffer.subdata(in: 0..<lineEnd)
                guard let size = MITMHTTP1Stream.parseHexSize(line) else { return .malformed }
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                state = size == 0 ? .trailerOrEnd : .chunkData(remaining: size, originalSize: size)
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                if take > 0 { deliver(Data(buffer.prefix(take))) }
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF:
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[0] == 0x0D, buffer[1] == 0x0A else { return .malformed }
                buffer.removeFirst(2)
                state = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let line = buffer.subdata(in: 0..<lineEnd)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if line.isEmpty { return .complete }
                // else: a trailer line — dropped.
            }
        }
        return .needMore
    }

    func consumeBuffered(_ buffer: inout MITMByteBuffer, into output: inout Data) -> BufferedResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let line = buffer.subdata(in: 0..<lineEnd)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                guard let size = MITMHTTP1Stream.parseHexSize(line) else { return .malformed }
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
                guard buffer[0] == 0x0D, buffer[1] == 0x0A else {
                    return .malformed
                }
                buffer.removeFirst(2)
                sizes.append(originalSize)
                state = .sizeLine
            case .trailerOrEnd:
                // Rewritten bodies use empty trailers; discard originals.
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let line = buffer.subdata(in: 0..<lineEnd)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if line.isEmpty {
                    return .complete(sizes: sizes)
                }
            }
        }
        return .needMore
    }
}

// MARK: - MITMMessageRewriter

extension MITMHTTP1Stream: MITMMessageRewriter {

    func feed(_ data: Data, completion: @escaping (Data) -> Void) {
        transform(data, completion: completion)
    }

    /// HTTP/1 has no flow-control windows; HTTP/2-only concept.
    func drainPendingServerBytes() -> Data { Data() }
}
