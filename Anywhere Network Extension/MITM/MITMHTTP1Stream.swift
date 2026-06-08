//
//  MITMHTTP1Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
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

    /// Hard cap on bytes accumulated in ``rxBuffer`` while waiting for
    /// the CRLF CRLF head terminator. nginx and Apache cap heads at
    /// 8 KiB and 64 KiB by default; legitimate traffic stays well
    /// under both. A hostile or malformed peer that streams bytes
    /// without ever closing the head would otherwise grow the buffer
    /// without bound. On cap exceed we permanently downgrade the stream to
    /// passthrough — the bytes are forwarded verbatim, the rewrite is
    /// abandoned, and the connection survives.
    private static let maxHeadBytes: Int = 64 * 1024

    /// Cap on a single chunk-size line or trailer field-line while the
    /// reader waits for its terminating CRLF. ``maxHeadBytes`` only guards
    /// the request/status head; once framing is chunked, a peer that streams
    /// a size line or trailer line that never ends (e.g. an unbounded run of
    /// hex digits or chunk-extension bytes with no CRLF) would otherwise grow
    /// ``rxBuffer`` without bound — a remote memory-exhaustion DoS. On exceed
    /// the framing is treated as malformed (the body is terminated and the stream downgrades
    /// to passthrough), mirroring the malformed-size-line handling.
    fileprivate static let maxChunkLineBytes: Int = 16 * 1024

    /// Cap on the body size that ``Anywhere.respond`` may emit on the
    /// HTTP/1.1 path. HTTP/1 has no flow-control window so the
    /// constraint here is purely about memory: a script that asks for
    /// a 1 GB synthesized response would otherwise force multiple
    /// gigabyte-scale ``Data`` copies (JS → Swift, queue, TLS send
    /// buffer) through a Network Extension limited to ~50 MiB.
    /// Matches ``MITMBodyCodec/maxBufferedBodyBytes`` so mocked
    /// responses sit inside the same memory envelope buffered-script
    /// bodies already use. Oversized bodies are truncated rather than
    /// rejected — a partial mock is more useful for debugging than a
    /// dropped one.
    private static let maxSynthesizedResponseBodyBytes: Int = MITMBodyCodec.maxBufferedBodyBytes

    private let host: String
    private let phase: MITMPhase
    /// Compiled rules for this stream's host + phase, captured once at
    /// init. Resolving them lowercases the host, walks the locked suffix
    /// trie, and filters the matched set into a fresh array — none of
    /// which changes between messages on the same session. Resolving
    /// once avoids repeating that work on every head, every body chunk,
    /// and every script invocation.
    private let rules: [CompiledMITMRule]
    /// ID of the rule set the host matched (or nil when no set
    /// applies). Used as the per-rule-set scope key for
    /// ``Anywhere.store`` and the ctx's ``ruleSetID`` field; same
    /// lifetime + same caching rationale as ``rules``.
    private let ruleSetID: UUID?
    /// When set, every request's `Host:` header is rewritten to this value
    /// so the upstream sees a consistent authority. Late-bound: set by the
    /// first transparent ``MITMOperation/rewrite`` to the replacement's
    /// authority (see ``applyRewrite``); nil means "leave Host alone". Used
    /// only on request streams; response streams leave it nil.
    ///
    /// Sticky by design: once a transparent rewrite changes the host, the
    /// connection's single upstream leg is committed to it, so this stays set
    /// and EVERY later request on the same kept-alive connection — including
    /// ones that match no rewrite rule — is routed to (and has its `Host`
    /// rewritten to) the replacement authority, never the original. A request
    /// that resolves a *different* host is torn down instead (see
    /// ``MITMSession/resolvedUpstreamMatchesDialed``); clearing the authority
    /// per-request to send unmatched requests to the original host would force a
    /// teardown + retry on every such request (connection thrash), which the
    /// one-upstream-per-connection model trades away for a stable authority.
    private var effectiveAuthority: String?

    /// The upstream the session should dial, surfaced when a transparent
    /// rewrite resolves a replacement host. nil until then (the session
    /// falls back to the original destination). Request phase only; read by
    /// the session's deferred-dial pump after the first ``transform``.
    private(set) var resolvedUpstream: (host: String, port: UInt16?)?

    /// Fired (once) when this stream commits to an opaque protocol switch — a
    /// `101 Switching Protocols` or a `2xx` response to a `CONNECT` — after
    /// which the connection is no longer HTTP and both directions must forward
    /// bytes verbatim. The session uses it to flip the OPPOSITE leg to
    /// passthrough too; without that, the other direction keeps trying to parse
    /// the post-upgrade byte stream as HTTP heads and stalls the tunnel (e.g.
    /// client→server WebSocket frames buffered in the head parser forever).
    /// Response phase only in practice. Invoked synchronously on the lwIP queue
    /// from ``consumeHead``.
    var onProtocolUpgrade: (() -> Void)?
    /// Lazy JS runtime, shared across both directions of the same MITM
    /// session. Touched only when a script rule fires.
    private let scriptEngineProvider: MITMScriptEngine.Provider
    /// Cross-direction request bookkeeping. The request stream records
    /// the (post-rewrite) method/URL as each request goes upstream; the
    /// response stream pops it to populate the script ctx's
    /// `method`/`url` fields on response phase.
    private let requestLog: MITMRequestLog

    /// The session's serial lwIP queue. Script execution hops off it onto
    /// ``MITMScriptTransform/scriptQueue``; the engine result is delivered
    /// back here so the parked driver resumes on the same queue every other
    /// part of the stream runs on. All ``drive``/``transform`` state is only
    /// ever touched on this queue.
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
        // Resolve the host's rule set with one trie walk, then derive the
        // phase-filtered rules and the set id from it. ``set(for:)``
        // lowercases the host and walks the locked trie, so reading the
        // rules and the id separately would walk it twice for one host.
        let matchedSet = policy.set(for: host)
        self.rules = matchedSet?.rules.filter { $0.phase == phase } ?? []
        self.ruleSetID = matchedSet?.id
        self.effectiveAuthority = effectiveAuthority
        self.scriptEngineProvider = scriptEngineProvider
        self.requestLog = requestLog
        self.lwipQueue = lwipQueue
    }

    // MARK: - State

    /// Snapshot of the rewritten head (start line + headers) plus the
    /// originating request context (looked up from ``MITMRequestLog`` on
    /// response phase). Saved when we decide to defer head emission so the
    /// body-completion path can rebuild the final head once the post-script
    /// body is known — its size sets ``Content-Length`` and decompression
    /// drops ``Content-Encoding``. Scripts mutate only the body, not the head.
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
        let originatingRequest: MITMRequestLog.Record?
        let startLine: String
        var frameIndex: Int = 0
        /// Holds the most recently completed chunk's bytes; we don't
        /// emit it until we know whether the next chunk exists (and
        /// thus whether the held chunk was the last one). nil before
        /// any chunk has completed.
        var pendingChunk: Data? = nil
        /// Resume cursor for the chunk-size / trailer CRLF scan, so a line
        /// dribbling in across many TLS records isn't re-scanned from the
        /// front on every append (O(n²) → O(n)). Holds the first index not
        /// yet checked as a CR candidate; reset to 0 the moment a line is
        /// consumed, advanced only on a no-progress (`needMore`) return.
        var lineScanCursor: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
    }

    /// What a streaming-frame resume must do *after* appending the framed
    /// chunk's result, once the off-queue ``applyFrame`` returns. Mirrors
    /// the three transient continuations that follow an
    /// ``emitStreamingChunk`` call in ``driveStreamingChunked``; captured at
    /// park time so the resume can reconstruct the loop's next step.
    private enum StreamingPostFrame {
        /// Hold the just-completed chunk as the new lookahead and continue
        /// at ``inner`` (normal mid-stream chunk boundary).
        case hold(nextPending: Data?, inner: StreamingChunkedInner)
        /// Final chunk just emitted: write the zero-size size line and drain
        /// the trailer section.
        case finalThenTrailer
        /// Per-chunk cap overflow: flip the stream to bypass, emit the
        /// overflowing accumulator verbatim, and keep reading the remaining
        /// `left` bytes of the current chunk.
        case bypassRemainder(left: Int, accumulator: Data)
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

        /// Buffering a read-until-close body — no Content-Length, no
        /// chunked framing — to rewrite it. Unlike the other rewrite
        /// modes there's no in-band terminator: the body ends when the
        /// upstream closes the connection, so the session pump calls
        /// ``finish()`` at EOF to run the script chain and flush. The
        /// head is withheld (in ``pending``) until then. Identity-coded
        /// only — the framing dispatch gates compressed bodies out,
        /// since a decompression bomb whose length we can't bound up
        /// front isn't safe to buffer optimistically. On cap overflow we
        /// fall back to emitting the head + buffered bytes and passing
        /// the remainder through verbatim.
        case rewritingUntilClose(pending: PendingHead, accumulator: Data)

        /// Parsing and discarding a chunked body. Two callers, distinguished by
        /// ``afterSynth``: a chunked body that overflowed
        /// ``MITMBodyCodec/maxBufferedBodyBytes`` mid-rewrite (`false` — head +
        /// truncated body already emitted, the remaining wire chunks are drained
        /// so the connection returns to ``awaitingHead`` cleanly), and a chunked
        /// request body whose response was synthesized locally (`true` — the
        /// request was answered here, so nothing goes upstream). The flag only
        /// changes malformed-framing recovery: a rewrite tail falls to
        /// ``passthrough`` (forward verbatim), but a post-synth body whose
        /// framing breaks must NOT forward the now-unframable bytes upstream, so
        /// it falls to ``draining`` instead.
        case discardingChunked(reader: ChunkedReader, afterSynth: Bool)

        /// Discarding a Content-Length request body after a synthesized
        /// 302 / reject response (``MITMOperation/rewrite``): the synth bytes
        /// are already queued for the inner leg and nothing goes upstream, so
        /// the body is read and dropped to keep a kept-alive connection framed.
        case discardingLength(remaining: Int)

        /// Terminal fail-closed blackhole: swallow every further byte on this
        /// leg, forward nothing. Reached when a chunked body being discarded
        /// (``discardingChunked``) hits a framing error — the message boundary
        /// is lost — on either leg:
        ///   - a request body discarded after a local synth response: the
        ///     request was already answered locally, so further client bytes
        ///     must not reach the upstream (which ``passthrough`` would do,
        ///     leaking bytes the reject/302 rule meant to keep off the wire);
        ///   - the over-cap rewrite tail: the truncated response already went
        ///     out as a complete Content-Length unit, so the leftover original
        ///     chunk bytes must not be forwarded to the receiver (which would
        ///     parse them as the next response and desync the connection).
        /// Either way the client retries on a fresh connection after it times
        /// out.
        case draining

        /// Per-chunk streaming-script mode. The head is already
        /// emitted; chunks flow through the script chain one at a
        /// time. A one-chunk lookahead in ``streaming.pendingChunk``
        /// lets us mark the final chunk before the terminator with
        /// ``frame.end = true``.
        case streamingChunked(streaming: StreamingState, inner: StreamingChunkedInner)

        /// Permanent: forward bytes verbatim. Reached on protocol
        /// upgrades (101), CONNECT-style tunnels, or any framing error.
        case passthrough

        /// Parked: a script call has been dispatched to
        /// ``MITMScriptTransform/scriptQueue`` and we are awaiting its
        /// result. The ``drive`` loop stops (consumes no further
        /// ``rxBuffer`` bytes) until the engine completion hops back to the
        /// lwIP queue and a resume method splices the scripted output,
        /// restores the real next mode, and resumes driving. Carries no
        /// payload: everything the resume needs is captured in the dispatch
        /// closure (see ``resumeBufferedBody``/``resumeHeadNoBody``/
        /// ``resumeStreamingFrame``).
        case awaitingScript
    }

    private var mode: Mode = .awaitingHead

    /// The in-flight ``transform``/``finish`` completion, retained only
    /// while a script hop is outstanding (``mode == .awaitingScript``). nil
    /// otherwise. The pump's one-read-in-flight discipline guarantees at most
    /// one is ever outstanding, so a plain optional suffices.
    private var parkedCompletion: ((Data) -> Void)?

    /// Output produced earlier in the current drive pass, held while a script
    /// hop is outstanding. The resume prepends it so the single completion
    /// carries every byte of the pass in wire order (e.g. a pipelined
    /// passthrough response that preceded a scripted one).
    private var pendingPreParkOutput = Data()

    /// Set when the owning session tears down. A resume that fires after this
    /// bails without touching a dead leg or firing a stale completion.
    private var torn = false

    /// Set when ``forcePassthrough`` is called while a script hop is still
    /// parked (so ``mode`` can't be spliced inline). The matching resume honors
    /// it instead of restoring the normal next mode. Not reachable for a real
    /// upgrade — the upgrade request carries no scripted body, so this leg is
    /// back in ``awaitingHead`` by the time the peer's 101 / 200 lands — but it
    /// keeps the force path from ever stomping a live parked completion.
    private var forcePassthroughPending = false
    /// Cursor-style buffer so prefix consumption is O(1). Chunked
    /// bodies streaming many small chunks would otherwise pay
    /// `O(remaining)` per ``Data.removeFirst`` shift; see
    /// ``MITMByteBuffer``.
    private var rxBuffer = MITMByteBuffer()

    /// How many leading bytes of ``rxBuffer`` ``consumeHead`` has already
    /// scanned for the `CRLF CRLF` head terminator while in
    /// ``Mode/awaitingHead``. Lets the next scan resume past the
    /// already-searched prefix instead of re-walking the whole buffer each
    /// time a slowly-arriving head appends another segment — O(n) total over
    /// the head rather than O(n²). Reset to 0 the instant a head completes or
    /// the stream downgrades, so the next message on a kept-alive connection
    /// scans from the front. ``rxBuffer`` is never drained while a head is
    /// still accumulating, so this stays a valid 0-relative index across the
    /// intervening appends.
    private var headScanned: Int = 0

    /// Bytes the request stream has synthesized in response to a
    /// `Anywhere.respond(...)` call and wants written straight back to
    /// the client (i.e. injected onto the inner TLS record). Request
    /// phase only; response streams never populate this. Drained by the
    /// session pump via ``drainPendingClientBytes()`` immediately after
    /// each ``transform(_:)`` call.
    private var pendingClientBytes = Data()

    /// Synth bytes the response stream has popped off
    /// ``MITMRequestLog.Record/synthAfter`` for the currently
    /// in-flight response, waiting to be appended to ``output`` as
    /// soon as that response's body finishes streaming. Response
    /// phase only; request streams never populate this. See
    /// ``flushSynthAfterResponse`` for the emission rule.
    private var pendingSynthAfterCurrentResponse = Data()

    // MARK: - Public API

    /// Feeds `data` through the rewrite pipeline. ``completion`` receives the
    /// peer-bound bytes and is invoked **exactly once**:
    /// - synchronously, inline, when no script runs (the common case — same
    ///   latency and allocations as a plain return), or
    /// - later, on the lwIP queue, when a script rule parks the stream while
    ///   its JavaScript runs off-queue.
    ///
    /// Client-bound synth bytes (from a request-phase `Anywhere.respond`) are
    /// not part of this completion; the pump drains them via
    /// ``drainPendingClientBytes()`` right after the completion fires.
    func transform(_ data: Data, completion: @escaping (Data) -> Void) {
        guard parkedCompletion == nil else { return failClosedReentry(completion) }
        if case .passthrough = mode {
            completion(data)
            return
        }
        rxBuffer.append(data)
        parkedCompletion = completion
        var output = Data()
        // Each iteration consumes from rxBuffer, parks on a script hop, or
        // returns when more bytes are needed.
        while drive(into: &output) { }
        finishDrivePass(output)
    }

    /// Tail of every drive pass — the synchronous one in ``transform`` and
    /// each resumed one. If a script hop started during the pass
    /// (``mode == .awaitingScript``), holds the bytes produced so far and
    /// returns without firing; the matching resume prepends them and fires
    /// once its hop completes. Otherwise fires the stashed completion exactly
    /// once with the accumulated output.
    private func finishDrivePass(_ output: Data) {
        if case .awaitingScript = mode {
            pendingPreParkOutput = output
            return
        }
        let completion = parkedCompletion
        parkedCompletion = nil
        completion?(output)
    }

    /// Marks the stream torn down (session cancelled). Any in-flight script
    /// resume that fires afterwards bails immediately. Idempotent.
    func markTorn() {
        torn = true
        parkedCompletion = nil
        pendingPreParkOutput = Data()
    }

    /// Forces this stream into permanent passthrough and returns whatever
    /// unparsed bytes are buffered, so the caller can forward them to the peer.
    /// Called by the session when the OPPOSITE direction commits to a protocol
    /// switch (101) or CONNECT tunnel: the connection is no longer HTTP, so this
    /// leg must stop parsing heads and forward verbatim — including any bytes it
    /// had already stranded in ``rxBuffer``. Idempotent (returns empty once
    /// already in passthrough). If a script hop is outstanding — not reachable
    /// for a real upgrade, see ``forcePassthroughPending`` — the switch is
    /// deferred to the resume and empty is returned now.
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

    /// If a ``forcePassthrough`` landed while this stream was parked on a script
    /// hop, honor it as the hop resumes: discard the now-irrelevant scripted
    /// output (the connection is becoming an opaque tunnel), flush whatever is
    /// buffered, and pin the stream to passthrough. Returns true when it fired,
    /// in which case the resume must do nothing further.
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

    /// Fail-closed handler for the should-never-happen case where
    /// ``transform``/``finish`` is re-entered while a script hop is still parked
    /// (``parkedCompletion != nil``). The session pump only re-arms its receive
    /// after the previous completion fires, so this can't happen today; the
    /// guard exists so a future regression surfaces loudly instead of silently
    /// overwriting the stashed completion — which would drop the prior read's
    /// re-arm callback and hang the connection half-open forever (a dual-leg
    /// leak). Fires only the new completion (empty) and leaves the stashed
    /// one intact so it still resumes exactly once.
    private func failClosedReentry(_ completion: (Data) -> Void) {
        logger.error("[MITM] HTTP/1 \(host): transform/finish re-entered while a script hop is outstanding; dropping this chunk to preserve the parked completion (one-read-in-flight invariant violated)")
        completion(Data())
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

    /// Called by the session pump when the upstream half-closes. A
    /// read-until-close body carries no in-band terminator — the close
    /// *is* the terminator — so this is where a buffered
    /// ``Mode/rewritingUntilClose`` body finally runs its script chain
    /// and gets emitted. ``completion`` receives the bytes to write toward
    /// the client before teardown: fired inline in every other mode (empty,
    /// since nothing was withheld), or after the script hop returns when a
    /// buffered body parks. The pass lands in ``Mode/passthrough``, so a
    /// second call (or stray late bytes) produces nothing.
    func finish(completion: @escaping (Data) -> Void) {
        guard parkedCompletion == nil else { return failClosedReentry(completion) }
        guard case .rewritingUntilClose(let pending, let accumulator) = mode else {
            completion(Data())
            return
        }
        // Stash the completion: the buffered body parks on its script, and
        // the resume fires this once it has emitted the flushed bytes. The
        // resume restores ``Mode/passthrough``, so a later finish (or stray
        // late bytes) is a no-op — preserving the idempotency contract.
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
            // Head was withheld, so `output` is empty here; the resume emits
            // the scripted body, flushes synth-after, and fires completion.
            pendingPreParkOutput = output
            return
        }
        // Decompression-fail passthrough: already emitted + set mode.
        finishDrivePass(output)
    }

    /// Appends any synth-after-response bytes captured when this
    /// response's request record was popped, and clears the buffer.
    /// Called by the response stream at every transition where the
    /// current response has finished streaming on the wire — i.e.,
    /// the wire byte for the response's last byte has been written to
    /// ``output`` and the next bytes can belong to either the next
    /// pipelined response or to the synth response that was attached
    /// to this record. Emitting earlier would corrupt the in-flight
    /// response's framing; emitting later would race the next
    /// upstream response head. No-op when nothing is pending (i.e.,
    /// the request stream did not attach a synth or this is the
    /// request stream).
    private func flushSynthAfterResponse(into output: inout Data) {
        if !pendingSynthAfterCurrentResponse.isEmpty {
            output.append(pendingSynthAfterCurrentResponse)
            pendingSynthAfterCurrentResponse.removeAll(keepingCapacity: false)
        }
    }

    // MARK: - Driver

    /// Returns true when state advanced and the loop should run again.
    private func drive(into output: inout Data) -> Bool {
        // Modes with mutable associated state are written back before inout
        // calls to avoid overlapping access to ``mode``.
        switch mode {
        case .passthrough:
            output.append(rxBuffer.prefix(rxBuffer.count))
            rxBuffer.removeAll(keepingCapacity: false)
            return false

        case .awaitingScript:
            // A script hop is outstanding; the resume will restore the real
            // mode and resume driving. Never reached in practice (the loop
            // stops the moment a handler parks), but defensively halt.
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
            // Terminal blackhole: swallow everything, forward nothing. See the
            // ``Mode/draining`` doc — a post-synth body whose framing broke must
            // not leak further bytes upstream.
            rxBuffer.removeAll(keepingCapacity: false)
            return false

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
        let crlfcrlf = Data([0x0D, 0x0A, 0x0D, 0x0A])
        // Resume the terminator search where the last unterminated pass
        // stopped, overlapping the final 3 bytes so a CRLF CRLF straddling the
        // boundary between already-scanned bytes and a freshly-appended segment
        // is still found. Re-scanning from the front on every segment would be
        // O(n²) over the head length for a head dribbled across many small TLS
        // records — bounded by ``maxHeadBytes`` but a needless quadratic on the
        // serial lwIP queue.
        let searchFrom = max(0, headScanned - (crlfcrlf.count - 1))
        guard let terminator = rxBuffer.range(of: crlfcrlf, from: searchFrom) else {
            if rxBuffer.count > Self.maxHeadBytes {
                // Hostile or pathologically-malformed peer: head
                // never terminates. Forward what we have verbatim
                // and downgrade — refusing to grow the buffer is
                // strictly safer than risking the NE's memory
                // budget on a single misbehaving connection.
                logger.warning("[MITM] HTTP/1 \(host): head exceeded \(Self.maxHeadBytes) B without CRLF CRLF; downgrading to passthrough")
                output.append(rxBuffer.prefix(rxBuffer.count))
                rxBuffer.removeAll(keepingCapacity: false)
                headScanned = 0
                mode = .passthrough
                return true
            }
            // Everything up to the current end is scanned; the next segment
            // resumes from here (less the straddle overlap, applied above).
            headScanned = rxBuffer.count
            return false
        }
        // Head complete — the next message scans fresh from the front.
        headScanned = 0
        let headEnd = terminator.upperBound
        let headData = rxBuffer.subdata(in: 0..<headEnd)
        rxBuffer.removeFirst(headEnd)

        guard let parsed = parseHead(headData) else {
            // If the head is not HTTP/1.x, stop rewriting and forward the
            // remaining bytes verbatim.
            mode = .passthrough
            output.append(headData)
            return true
        }

        // Apply the request-phase "Rewrite" operation. A transparent rewrite
        // updates the start-line target (and may set the dynamic authority +
        // dial target); a 302 / reject sub-mode short-circuits the request
        // with a synthesized response on the inner leg. Header rules below
        // touch the header block; Content-Length is recomputed if scripts run.
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

        // On the response side, every well-formed final message
        // corresponds to one request previously pushed by the request
        // stream. Pop the matching record here — once per final
        // response head, before framing is computed — so the FIFO
        // never drifts even when the response is passthrough or no
        // scripts fire, and so ``bodyFraming`` can see the originating
        // method (HEAD responses carry Content-Length / Transfer-
        // Encoding values that must not be followed by a body).
        //
        // It also has to land before header rules so a response-phase
        // rule's URL gate can be tested against the originating
        // request's path.
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
                let popped = requestLog.popHTTP1()
                originatingRequest = popped
                // Pipeline-order preservation: a pipelined follow-on
                // request may have synthesized its response via
                // ``Anywhere.respond`` while this record was still the
                // newest in-flight entry. Those bytes were attached
                // here instead of going straight to the client; the
                // response stream now owns emitting them, but only
                // after the current upstream response finishes
                // streaming (otherwise the client would consume the
                // synth bytes as part of this response's body).
                if let popped, !popped.synthAfter.isEmpty {
                    pendingSynthAfterCurrentResponse.append(popped.synthAfter)
                }
            }
        } else {
            originatingRequest = nil
        }

        // The whole request URL every rule's gate is tested against:
        // built from the (already rewritten) start-line target on
        // requests, the originating request's URL on responses — so request
        // and response rules in a set gate on the same URL the client asked
        // for. nil fails the gate closed.
        let gateURL = requestURLForGating(
            startLine: rewrittenStartLine,
            originatingRequest: originatingRequest
        )

        // Auto Host rewrite runs first so a headerReplace targeting Host
        // still overrides the canonical post-redirect value.
        let withAuthority = applyAuthorityRewrite(parsed.headers)
        let rewrittenHeaders = applyHeaderRules(withAuthority, requestURL: gateURL)

        let framing = bodyFraming(
            startLine: rewrittenStartLine,
            headers: rewrittenHeaders,
            originatingMethod: originatingRequest?.method
        )

        let scriptsApply = MITMScriptTransform.hasScriptRule(in: rules, requestURL: gateURL)
        // Buffered body transforms = a script OR one/more native text
        // replaces OR one/more native JSON edits. Each needs the whole
        // decompressed body in hand, so any of them drives buffering for
        // bodied framings below. The no-body (.none) path stays gated on
        // ``scriptsApply`` alone — a body edit has nothing to act on
        // without a body.
        let buffersBody = scriptsApply
            || MITMScriptTransform.hasBodyReplaceRule(in: rules, requestURL: gateURL)
            || MITMScriptTransform.hasBodyJSONRule(in: rules, requestURL: gateURL)

        // Protocol upgrades and "read until close" responses can't be
        // safely re-framed, so emit the rewritten head and downgrade.
        switch framing {
        case .switchingProtocols, .readUntilClose:
            // Read-until-close responses normally pass through
            // unmodified, but when a buffered script applies and the
            // body is identity-coded we can buffer it to EOF — the
            // connection close is the body terminator (see ``finish()``)
            // — run the script, and re-emit with a definite
            // Content-Length. Mirrors the HTTP/2 missing-length path
            // (``shouldBufferStream``). Compressed bodies stay
            // passthrough: a decompression bomb whose length we can't
            // bound up front isn't safe to buffer optimistically, same
            // stance as HTTP/2. Stream scripts need in-band framing they
            // don't get here, so they fall through too.
            if case .readUntilClose = framing, buffersBody,
               !MITMScriptTransform.hasStreamScriptRule(in: rules, requestURL: gateURL) {
                let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
                if codec.supported, !codec.requiresDecompression {
                    warnIfBufferedScriptDeStreams(rewrittenHeaders)
                    // Force ``Connection: close`` so both the success
                    // path (definite Content-Length, upstream already
                    // gone) and the overflow fallback (read-until-close
                    // passthrough) frame correctly for the client.
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
            // Request side records the outgoing request even though
            // scripts can't run, so the response leg can still look up
            // method/url on subsequent messages.
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            // RFC 9112 §6.3 case 7: a response without Content-Length
            // or Transfer-Encoding has a body of "indeterminate length,
            // ending only when the connection is closed". With
            // HTTP/1.1's default keep-alive, the receiver would
            // otherwise try to parse the next bytes on the connection
            // as a follow-on response head and hang. Force
            // ``Connection: close`` into the head so the receiver knows
            // to read until close; the rest of the connection enters
            // passthrough and the underlying TLS leg eventually closes
            // when the upstream finishes streaming.
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
            output.append(serializeHead(startLine: rewrittenStartLine, headers: finalHeaders))
            // Best-effort flush: a synth response attached to this
            // record can no longer be cleanly framed since the
            // connection is about to switch to passthrough (101) or
            // read-until-close. Emit the bytes immediately after this
            // head; pipelined clients with an in-flight 101 are a
            // pathological corner case (the upgrade consumes the
            // connection), but doing so beats silently dropping the
            // bytes the script asked us to deliver.
            flushSynthAfterResponse(into: &output)
            mode = .passthrough
            // 101 / CONNECT-2xx: the connection is now an opaque tunnel. Signal
            // the session so it flips the request direction to passthrough too —
            // otherwise client→server bytes (e.g. WebSocket frames) would sit in
            // the request leg's head parser forever, deadlocking the tunnel. Only
            // a true protocol switch fires this; a read-until-close response is
            // still HTTP and leaves the request leg parsing normally.
            if case .switchingProtocols = framing {
                onProtocolUpgrade?()
            }
            return true
        case .none, .contentLength, .chunked:
            break
        }

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
                return false // parked; the resume emits the head + flushes synth-after
            }
            if phase == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            // No-body framing — the response is complete with the
            // head alone, so this is the boundary for any synth bytes
            // attached to it. Skipped (as a no-op) when the head was
            // an interim 1xx, since we peeked rather than popped and
            // ``pendingSynthAfterCurrentResponse`` stays empty.
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
        // Stream scripts can't safely modify a length-prefixed body —
        // the head has already committed to a byte count we can't
        // change. Warn and fall through to either buffered-script or
        // passthrough.
        if MITMScriptTransform.hasStreamScriptRule(in: rules, requestURL: requestURL) {
            logger.warning("[MITM] HTTP/1 \(host): Stream Script skipped for Content-Length body (chunked encoding required)")
        }

        // The length is known up front, so we can opt out of buffering
        // before consuming a single body byte when the response would
        // exceed the cap. This keeps huge downloads (videos, archives)
        // from ever reaching the accumulator.
        let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
        let canRewrite = buffersBody && codec.supported && length <= MITMBodyCodec.maxBufferedBodyBytes

        if canRewrite {
            // The head is withheld until the whole body is buffered, which
            // stalls a client that sent Expect: 100-continue; answer it
            // ourselves and drop the header before the head goes upstream.
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
            logger.warning("[MITM] HTTP/1 \(host): Content-Length \(length) exceeds cap \(MITMBodyCodec.maxBufferedBodyBytes)")
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
        buffersBody: Bool,
        rules: [CompiledMITMRule],
        requestURL: String?,
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        // Streaming-script wins over buffered-script. Emit head
        // immediately and switch to per-chunk script mode. Stream
        // scripts can't mutate head fields, so head emission is
        // straightforward here.
        if MITMScriptTransform.hasStreamScriptRule(in: rules, requestURL: requestURL) {
            if buffersBody {
                logger.warning("[MITM] HTTP/1 \(host): Stream Script wins over buffered body rule")
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
            // The head is withheld until the body finishes buffering, so answer
            // Expect: 100-continue ourselves (see ``handleExpectContinue``).
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
        output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
        mode = .forwardingChunked(reader: ChunkedReader())
        return true
    }

    /// When a request body is buffered for rewrite, the head is withheld until
    /// the whole body is in hand (see ``rewriteLength`` / ``rewriteChunked``).
    /// An HTTP/1.1 client that sent ``Expect: 100-continue`` (RFC 9110 §10.1.1)
    /// waits for an interim ``100 Continue`` before sending that body — but the
    /// upstream can't send one, because it hasn't seen the head we're holding.
    /// The upload would stall until the client's continue-timeout (or hang for a
    /// strict client), so synthesize the ``100 Continue`` toward the client
    /// ourselves (queued on ``pendingClientBytes``, which the session injects on
    /// the inner leg), then strip ``Expect`` so the upstream — which receives
    /// head+body together — doesn't emit a second, redundant 100.
    ///
    /// Request phase + HTTP/1.1 only: HTTP/1.0 clients don't understand
    /// 100-continue and send the body immediately, so nothing stalls and no
    /// synthetic 100 is owed. No-op (headers returned unchanged) when the
    /// request carries no ``Expect: 100-continue``. The non-buffering forward
    /// path never calls this — it emits the head immediately, so the real server
    /// answers the expectation itself.
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
        let slice = rxBuffer.prefix(take)
        output.append(slice)
        rxBuffer.removeFirst(take)
        let left = remaining - take
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
        let result = reader.consumeForward(&rxBuffer, into: &output)
        switch result {
        case .needMore:
            mode = .forwardingChunked(reader: reader)
            return false
        case .complete:
            flushSynthAfterResponse(into: &output)
            mode = .awaitingHead
            return true
        case .malformed:
            // The head was already emitted with ``Transfer-Encoding:
            // chunked``, so the receiver is mid-parse and waiting for
            // ``0\r\n\r\n`` to terminate the body. Switching straight
            // to passthrough would leave the receiver hanging forever
            // (or, on keep-alive, consume bytes from the next message
            // as if they were part of this body). Synthesize the
            // zero-size terminator first so the current response
            // frames cleanly; the garbage bytes that follow in
            // ``rxBuffer`` are discarded since they would otherwise
            // be misparsed as the start of the next response.
            output.append(contentsOf: "0\r\n\r\n".utf8)
            rxBuffer.removeAll(keepingCapacity: false)
            flushSynthAfterResponse(into: &output)
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
            // Parks on the script (returns false to stop the loop; the resume
            // finishes). On a decompression-fail passthrough nothing parks and
            // the message is fully handled, so continue the loop.
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
            // Chunked bodies have no up-front length, so the cap can
            // only be enforced as bytes flow in. On overflow we apply
            // rules to the partial buffer, emit it, and drain the rest.
            // Lossy, but the alternative — refusing to rewrite chunked
            // bodies entirely — would silently break common APIs whose
            // bodies are well under the cap.
            if accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                logger.warning("[MITM] HTTP1 \(host): Chunked body exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes); truncating")
                // The rewritten head + truncated body form the complete
                // response on the wire (collapsed to a Content-Length unit);
                // the remaining original chunks are then drained server-side.
                // Synth-after bytes therefore belong right after the body
                // (handled by the resume / passthrough path), so we resume
                // into ``.discardingChunked``.
                let parked = applyScriptsAndEmit(
                    pending: pending,
                    rawBody: accumulator,
                    originalSizes: [accumulator.count],
                    resumeMode: .discardingChunked(reader: reader, afterSynth: false),
                    into: &output
                )
                return !parked
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
            flushSynthAfterResponse(into: &output)
            mode = .passthrough
            return true
        }
    }

    /// Accumulates a read-until-close body until the upstream closes
    /// (handled in ``finish()``). There's no in-band terminator and no
    /// up-front length, so the buffer cap is the only bound on how much
    /// we'll hold. On overflow we give up on rewriting: emit the
    /// (unmodified) head — still read-until-close framed via the
    /// ``Connection: close`` forced in at head time — flush what we
    /// buffered, and pass the remainder through verbatim. Mirrors the
    /// chunked-overflow fallback.
    private func rewriteUntilClose(
        pending: PendingHead,
        accumulator: inout Data,
        into output: inout Data
    ) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        accumulator.append(rxBuffer.prefix(rxBuffer.count))
        rxBuffer.removeAll(keepingCapacity: false)
        if accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] HTTP/1 \(host): read-until-close body exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes) B; bypassing Script and forwarding verbatim")
            output.append(serializeHead(startLine: pending.startLine, headers: pending.headers))
            output.append(accumulator)
            flushSynthAfterResponse(into: &output)
            mode = .passthrough
            return true
        }
        mode = .rewritingUntilClose(pending: pending, accumulator: accumulator)
        return false
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
                guard let lineEnd = rxBuffer.firstCRLF(from: streaming.lineScanCursor) else {
                    if rxBuffer.count > Self.maxChunkLineBytes {
                        // Chunk-size line that never terminates — treat as
                        // malformed (same handling as a bad size below) so the
                        // buffer can't grow without bound.
                        logger.warning("[MITM] HTTP/1 \(host): chunk-size line exceeded \(Self.maxChunkLineBytes) B without CRLF; terminating body and downgrading to passthrough")
                        output.append(contentsOf: "0\r\n\r\n".utf8)
                        rxBuffer.removeAll(keepingCapacity: false)
                        flushSynthAfterResponse(into: &output)
                        mode = .passthrough
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
                    // Head was already emitted with ``Transfer-Encoding:
                    // chunked``, so the receiver is waiting for
                    // ``0\r\n\r\n`` to end the body. Synthesize the
                    // terminator before downgrading so the current
                    // response frames cleanly; discard the rest of
                    // ``rxBuffer`` to avoid feeding garbage bytes to
                    // the receiver as the head of the next response.
                    output.append(contentsOf: "0\r\n\r\n".utf8)
                    rxBuffer.removeAll(keepingCapacity: false)
                    flushSynthAfterResponse(into: &output)
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
                    if emitOrParkStreamingFrame(
                        streaming: &streaming,
                        chunk: finalChunk,
                        isLast: true,
                        postFrame: .finalThenTrailer,
                        into: &output
                    ) {
                        return false // parked; resume emits "0\r\n" + drains trailers
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
                // Per-chunk buffer cap. The buffered-script path bounds
                // its accumulator at ``maxBufferedBodyBytes``; the
                // streaming path must too. A single declared chunk size
                // can be arbitrarily large (sizes up to ``Int.max``
                // parse), so a hostile or buggy upstream could otherwise grow
                // this accumulator without bound mid-chunk. On overflow we stop
                // trying to hand the script whole frames: flush any held chunk,
                // switch the stream to bypass, and emit the buffered
                // bytes verbatim as their own wire chunk. Re-chunking is
                // transparent to the receiver (it concatenates chunk
                // data), so the framing the head already promised holds
                // and no body bytes are lost — unlike the buffered path,
                // which truncates.
                if left != 0, accumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                    logger.warning("[MITM] HTTP/1 \(host): streaming chunk exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes) B; bypassing Script and forwarding remainder verbatim")
                    if let held = streaming.pendingChunk {
                        streaming.pendingChunk = nil
                        if emitOrParkStreamingFrame(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            postFrame: .bypassRemainder(left: left, accumulator: accumulator),
                            into: &output
                        ) {
                            return false // parked; resume bypasses + emits the remainder
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
                    // Chunk is complete. Flush the previous held chunk
                    // (with isLast=false now that we know more chunks
                    // follow), then hold this one.
                    if let held = streaming.pendingChunk {
                        if emitOrParkStreamingFrame(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            postFrame: .hold(nextPending: accumulator, inner: .dataCRLF),
                            into: &output
                        ) {
                            return false // parked; resume holds `accumulator` + continues
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
                    // Same situation as the malformed size-line above:
                    // head was already emitted as chunked, receiver is
                    // mid-parse. Synthesize the terminator + drop the
                    // garbage so the response is closed cleanly.
                    output.append(contentsOf: "0\r\n\r\n".utf8)
                    rxBuffer.removeAll(keepingCapacity: false)
                    flushSynthAfterResponse(into: &output)
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
                guard let lineEnd = rxBuffer.firstCRLF(from: streaming.lineScanCursor) else {
                    if rxBuffer.count > Self.maxChunkLineBytes {
                        logger.warning("[MITM] HTTP/1 \(host): chunk trailer line exceeded \(Self.maxChunkLineBytes) B without CRLF; terminating body and downgrading to passthrough")
                        // "0\r\n" was already emitted; close the trailer
                        // section with the empty line, then downgrade.
                        output.append(contentsOf: "\r\n".utf8)
                        rxBuffer.removeAll(keepingCapacity: false)
                        flushSynthAfterResponse(into: &output)
                        mode = .passthrough
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

    /// Runs the streaming-script chain on ``chunk`` and appends the
    /// result as a chunked-transfer chunk to ``output``. Empty results
    /// are dropped (no zero-size chunk emitted mid-stream — the
    /// terminator reserves that). ``cursor.bypass`` short-circuits the
    /// script chain so subsequent chunks pass through unchanged.
    private func emitOrParkStreamingFrame(
        streaming: inout StreamingState,
        chunk: Data,
        isLast: Bool,
        postFrame: StreamingPostFrame,
        into output: inout Data
    ) -> Bool {
        if streaming.cursor.bypass {
            // Fast path: the stream is bypassed, so no script runs — emit
            // synchronously and tell the caller it did not park.
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
        // Capture the stream value (its ``cursor`` is shared by reference, so
        // the engine's bypass/state mutations are visible on resume) plus the
        // post-frame continuation, then dispatch off-queue and park.
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

    /// Resume for a parked streaming frame. Appends the framed result onto
    /// the held pre-park bytes, applies the captured ``StreamingPostFrame``
    /// continuation, and resumes the chunked-streaming loop. Mirrors the
    /// synchronous tail of ``emitOrParkStreamingFrame`` plus the transient
    /// step that followed the original call site.
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
        // ``cursor.bypass``/``cursor.state`` were already updated in place by
        // ``applyFrame`` (the cursor is shared by reference).
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

    /// Parses the hex size from a chunked size line (ignoring any
    /// chunk extensions after `;`).
    fileprivate static func parseHexSize(_ data: Data) -> Int? {
        guard let raw = String(data: data, encoding: .ascii) else { return nil }
        let head = raw.split(separator: ";", maxSplits: 1).first.map(String.init) ?? raw
        let trimmed = head.trimmingCharacters(in: CharacterSet.whitespaces)
        // RFC 9112 §7.1: chunk-size is `1*HEXDIG` — an unsigned count.
        // ``Int(_:radix:)`` also accepts a leading `-`, so a hostile or
        // buggy peer's `-1\r\n` size line would parse to a negative
        // ``remaining`` and drive ``min(remaining, count)`` negative,
        // trapping the whole Network Extension in ``MITMByteBuffer``'s
        // ``prefix``/``subdata`` range math. Reject negatives; nil flows
        // to the caller's malformed-chunk handling (synthesize the
        // terminator, drop to passthrough), the same as any other
        // unparseable size line. Also require pure ASCII hex: ``Int(_:radix:)``
        // admits a leading `+` too, another framing-divergence vector.
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isHexDigit && $0.isASCII }),
              let size = Int(trimmed, radix: 16), size >= 0 else { return nil }
        return size
    }

    /// Drains the remaining wire chunks of an over-cap rewriting body.
    /// The truncated rewritten body has already been emitted, so all we
    /// need to do is keep the stream parser advancing until the
    /// terminator/trailers and then return to ``awaitingHead`` so the
    /// next message on this connection is parsed normally.
    /// Reads and drops a Content-Length request body after a synthesized
    /// 302 / reject. Mirrors ``forwardLength`` but appends nothing — the
    /// response is already queued for the inner leg and the upstream leg may
    /// not even exist. Returns to ``awaitingHead`` once the body is drained.
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
            // The truncated rewritten body has already gone on the wire and the
            // trailers are drained, so this is the response's last wire byte —
            // the correct boundary to release any synth-after bytes attached to
            // this response. ``afterSynth`` discards are request streams (which
            // never carry synth-after); only the over-cap rewrite tail
            // (``afterSynth == false``) is a response stream that can owe them.
            // Flush here rather than relying on a *next* response arriving to
            // carry the flush: if this is the last response on the connection,
            // no later ``drive`` iteration would ever emit them and the
            // synthesized (e.g. pipelined) response would be silently dropped.
            if !afterSynth {
                flushSynthAfterResponse(into: &output)
            }
            mode = .awaitingHead
            return true
        case .malformed:
            // Framing is irrecoverable — the next message boundary is lost, so
            // the leftover bytes must be blackholed on BOTH legs, never
            // forwarded. A request body discarded after a LOCAL synth response
            // must not reach the upstream (which ``passthrough`` would do,
            // leaking the bytes the reject/302 rule meant to keep off the wire).
            // And the over-cap rewrite tail (``afterSynth == false``) follows a
            // truncated response already emitted as a *complete* Content-Length
            // unit (see ``rewriteChunked``): forwarding the remaining original
            // chunk bytes verbatim would make the receiver parse them as the
            // next response's start line, desyncing the connection. The over-cap
            // path already intends these chunks to be drained server-side and
            // the ``.complete`` case above does exactly that — ``.malformed``
            // must too, not fall through to ``passthrough``.
            mode = .draining
            return true
        }
    }

    // MARK: - Script application + head rebuild

    /// Decompresses the buffered body and dispatches the buffered ``.script``
    /// off-queue (parking the stream). The rebuilt head + re-emitted body are
    /// produced later by ``resumeBufferedBody`` once the engine returns.
    ///
    /// Returns `true` when a script hop was parked: the caller must stop the
    /// drive loop (`return false`); the resume restores `resumeMode`, flushes
    /// synth-after bytes, and finishes the pass. Returns `false` when
    /// decompression failed — the original bytes were emitted as an identity
    /// passthrough (no script), `flushSynthAfterResponse` ran, and `mode` was
    /// set to `resumeMode` here, so the caller should treat the message as
    /// fully handled (`return true`). Passing the original bytes through on a
    /// decompression failure beats breaking the connection.
    ///
    /// On the parked path the head is withheld, so nothing is appended to
    /// `output`.
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

    /// Resume for the buffered ``.script`` path. Runs on the lwIP queue once
    /// the off-queue engine call returns. Prepends the bytes held since the
    /// park, emits the rebuilt head + body (or queues a synth response),
    /// flushes synth-after, restores the body handler's `resumeMode`, and
    /// resumes the drive pass — firing the stashed completion exactly once.
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
            // Always set an explicit Content-Length matching the post-script
            // body size. The original message may have been chunked, but we
            // emit the rewritten body as a single length-prefixed unit since
            // we've already buffered all of it.
            finalHeaders.append((name: "Content-Length", value: String(result.body.count)))
            if phase == .httpRequest {
                logRequest(startLine: finalStartLine)
            }
            resumed.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
            if !result.body.isEmpty {
                resumed.append(result.body)
            }
        case .synthesizedResponse(let response):
            // Request-phase short-circuit. Drop the request bytes we'd
            // otherwise emit to upstream and queue the synthesized HTTP/1.1
            // response for the inner leg.
            queueSynthesizedResponse(response)
        }
        flushSynthAfterResponse(into: &resumed)
        mode = resumeMode
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    /// Resume for the no-body (``.none`` framing) ``.script`` path. Emits the
    /// scripted head (or queues a synth response), flushes synth-after, and
    /// resumes the pass from ``.awaitingHead``.
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
            queueSynthesizedResponse(response)
        }
        flushSynthAfterResponse(into: &resumed)
        mode = .awaitingHead
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
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
    ///
    /// HEAD-response carve-out: per RFC 9110 §15.2 a response to HEAD
    /// never carries a body, but its `Content-Length` /
    /// `Transfer-Encoding` are informational — they mirror what GET
    /// would return. Overwriting them with `Content-Length: 0` would
    /// silently lie to the client about resource size. Pass the
    /// originating request method in so the response leg can preserve
    /// the server's framing headers and never write a body even if a
    /// script accidentally populated one.
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
            // Leave the server's framing headers intact; the receiver
            // sent HEAD and knows not to read a body, so the values are
            // purely informational. Still drop `Content-Encoding` when
            // the (zero-byte) body was decompressed — but that's a
            // theoretical case for HEAD since the .none framing path
            // never decompresses.
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
        output.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
        // HEAD responses MUST NOT carry a body (§15.2); a script that
        // wrote into ctx.body gets that write dropped on the wire
        // rather than risking response-splitting against the next
        // pipelined message.
        if !result.body.isEmpty, !isHeadResponse {
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
        return parseHTTPStatusCode(parts[1])
    }

    /// Strips framing-related headers that we re-emit ourselves
    /// (`Transfer-Encoding`, `Content-Length`) and, when we just
    /// decompressed the body, `Content-Encoding`.
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

    // MARK: - Re-chunking. Used only on the chunked decompression-
    // failure passthrough, which preserves the original chunk shape
    // rather than collapsing the body to a single Content-Length unit.

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
        // ``components(separatedBy: "\r\n")`` only splits on the exact
        // CRLF sequence, so a peer that smuggled a lone CR or a lone LF
        // inside the request-target / status line lands here intact.
        // Re-emitting verbatim via ``serializeHead`` would then put that
        // byte on the wire — strict receivers reject, but lax receivers
        // (still common in the wild) may treat the lone LF as a line
        // terminator and read the bytes that follow it as a smuggled
        // header. Refusing the parse forces the stream into
        // ``passthrough`` so the bytes flow unmodified to the receiver,
        // which is the safer failure mode than us injecting a CRLF we
        // can't take back. NUL is also rejected since it is forbidden
        // anywhere in HTTP/1 syntax (RFC 9112 §2.2).
        if Self.containsControlChars(startLine) { return nil }
        var headers: [Header] = []
        var contentLengthValues: [String] = []
        var transferEncodingValues: [String] = []
        var hasTEChunked = false
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            // RFC 9112 §5.2: reject obs-fold (a field-line beginning with SP or
            // HTAB — the deprecated line-folding continuation of the previous
            // field). It is already refused below (a folded line has no colon, or
            // yields a leading-whitespace field-name that ``isValidHTTPHeaderName``
            // rejects), but reject it explicitly here so the protection can't
            // silently lapse if that name check is ever relaxed: folding lets a
            // lax downstream peer reassemble a value we treated as a separate
            // line, a smuggling vector.
            if let first = line.utf8.first, first == 0x20 || first == 0x09 {
                return nil
            }
            // RFC 9112 §5.1: a header field-line MUST contain a colon.
            // A line without a colon is a syntax error — silently
            // dropping it is unsafe because a lax downstream parser
            // might still interpret the bytes (e.g. "Transfer-Encoding
            // chunked" with SP instead of `:`) as a real framing
            // header, desynchronizing the proxy's framing from the
            // peer's and opening a smuggling vector.
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = String(line[..<colon])
            let value = String(line[line.index(after: colon)...])
                .trimmingCharacters(in: CharacterSet.whitespaces)
            // RFC 9110 §5.6.2: field-name is a `token` — tchar+ only.
            // Anything outside that (SP, CTL, `:`, CR, LF, NUL, …) is a
            // smuggling vector: SP inside a name lets an attacker craft
            // headers that we ignore but a lax downstream peer honors
            // (the classic obfuscated-TE smuggling trick).
            guard isValidHTTPHeaderName(name) else { return nil }
            // Field-value: CR/LF/NUL are forbidden anywhere; allowing
            // any would let a value split into two header lines on
            // re-emission (response-splitting).
            if Self.containsControlChars(value) { return nil }
            // Track framing-relevant headers so we can detect and
            // normalize smuggling vectors before the head is accepted.
            if name.equalsIgnoringASCIICase("content-length") {
                contentLengthValues.append(
                    value.trimmingCharacters(in: CharacterSet.whitespaces)
                )
            } else if name.equalsIgnoringASCIICase("transfer-encoding") {
                // Collect every Transfer-Encoding field line; the combined
                // coding list is validated once after the loop so this head's
                // implied framing matches what ``bodyFraming`` later applies.
                transferEncodingValues.append(value)
            }
            headers.append((name: name, value: value))
        }
        // Every Content-Length we forward verbatim must be a shape
        // ``bodyFraming`` will honor (a single in-range non-negative integer).
        // A value like `+5`, `5 5`, or a 30-digit overflow is forwarded
        // verbatim here but framed as bodyless by ``bodyFraming`` — the same
        // proxy/upstream framing divergence the conflicting-header guards below
        // close, and a request-smuggling vector. Refuse the head so the bytes
        // flow through untouched for the receiver to adjudicate, rather than us
        // imposing a framing the wire contradicts.
        if contentLengthValues.contains(where: { !Self.isCleanContentLength($0) }) {
            return nil
        }
        // Transfer-Encoding: combine the field lines into one ordered coding
        // list (RFC 9112 §6.1) and require `chunked` to be the final coding for
        // chunked framing — decided exactly as ``bodyFraming`` so the framing
        // this head implies always matches the framing we apply.
        if !transferEncodingValues.isEmpty {
            // Multiple TE field lines let the per-line and combined-list
            // readings diverge (and are a known smuggling vector); don't rewrite.
            if transferEncodingValues.count > 1 { return nil }
            guard Self.transferEncodingIsChunked(transferEncodingValues[0]) else {
                // TE present but not chunked-final: unframeable for a request
                // (RFC 9112 §6.1) and exotic for a response. Refuse to rewrite so
                // the bytes pass through verbatim rather than under a framing the
                // forwarded Transfer-Encoding contradicts.
                return nil
            }
            hasTEChunked = true
        }
        // RFC 9112 §6.3.5: multiple Content-Length values that differ
        // is malformed and a primary smuggling vector. Distinct
        // downstream parsers will disagree on which value to honor,
        // letting an attacker desync framing. Reject the head; the
        // stream downgrades to passthrough and the bytes flow verbatim
        // for the receiver to defend against.
        let uniqueLengths = Set(contentLengthValues)
        if uniqueLengths.count > 1 {
            return nil
        }
        // RFC 9112 §6.1: when both Transfer-Encoding (with `chunked`
        // as the final coding) and Content-Length are present, the
        // spec calls for treating the message as an error since two
        // distinct framing sources let an attacker smuggle a second
        // request through a downstream peer that picks the other
        // value.
        if hasTEChunked && !contentLengthValues.isEmpty {
            headers = headers.filter {
                !$0.name.equalsIgnoringASCIICase("content-length")
            }
        } else if contentLengthValues.count > 1 {
            // Multiple matching Content-Length entries collapse to one
            // so the outbound head is unambiguous to the next hop.
            var filtered = headers.filter {
                !$0.name.equalsIgnoringASCIICase("content-length")
            }
            filtered.append((name: "Content-Length", value: contentLengthValues[0]))
            headers = filtered
        }
        return ParsedHead(startLine: startLine, headers: headers)
    }

    /// True when an end-trimmed Content-Length field value is a single,
    /// in-range, non-negative integer — the only shape ``bodyFraming`` honors
    /// as a body length. ``parseHead`` refuses any head carrying a value of
    /// another shape (`+5`, `5 5`, an interior space, a value that overflows
    /// ``Int``) so the length forwarded verbatim can never disagree with the
    /// framing applied — that divergence is a request-smuggling vector
    /// (RFC 9112 §6.3). Both call sites go through this one predicate so they
    /// cannot drift apart.
    static func isCleanContentLength(_ trimmed: String) -> Bool {
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isASCII && $0.isNumber }) else { return false }
        guard let length = Int(trimmed), length >= 0 else { return false }
        return true
    }

    /// True when a single Transfer-Encoding field value has ``chunked`` as its
    /// final comma-separated transfer-coding (RFC 9112 §6.1) — the only TE shape
    /// that frames as chunked. Only the last trimmed token is compared, so a
    /// value like ``x-chunked-encoding`` does not false-match. ``parseHead`` (to
    /// validate/normalize the head) and ``bodyFraming`` (to apply the framing)
    /// both decide chunked framing through this one predicate, so the head's
    /// implied framing can never drift from the framing actually applied — that
    /// divergence is a request-smuggling vector.
    static func transferEncodingIsChunked(_ value: String) -> Bool {
        let last = value
            .split(separator: ",", omittingEmptySubsequences: false)
            .last?
            .trimmingCharacters(in: CharacterSet.whitespaces)
        return last?.equalsIgnoringASCIICase("chunked") == true
    }

    /// True when ``s`` contains a lone CR, lone LF, or NUL — any byte
    /// that would split or terminate an HTTP/1 head line on the wire if
    /// re-emitted via ``serializeHead``. Intentionally tighter than the
    /// header-field-value rule (which only bans CR / LF / NUL): the
    /// start line and field-name positions have no legal use for those
    /// bytes either way.
    private static func containsControlChars(_ s: String) -> Bool {
        for byte in s.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return true
            }
        }
        return false
    }

    private func isHTTPStartLine(_ line: String) -> Bool {
        // Response: HTTP/1.x SP status SP reason
        if line.hasPrefix("HTTP/1.") { return true }
        // Request: METHOD SP path SP HTTP/1.x. The version suffix
        // check alone admits start lines whose METHOD position is
        // not a token (e.g. ``"AB/CD / HTTP/1.1"`` — wire-illegal
        // but parseable here). Tighten by requiring the prefix up
        // to the first SP to satisfy the RFC 9110 §9.1 token
        // alphabet so the parser never accepts a method we can't
        // safely interpolate back onto the wire.
        guard line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0") else {
            return false
        }
        guard let firstSpace = line.firstIndex(of: " ") else { return false }
        let method = String(line[..<firstSpace])
        return Self.isValidMethodToken(method)
    }

    /// True when ``startLine`` is a response start line with a 1xx
    /// status that isn't 101 — i.e. an informational interim response
    /// (100 Continue, 102 Processing, 103 Early Hints) that will be
    /// followed by additional headers on the same request. 101 is a
    /// final response (protocol upgrade) and pops normally.
    private func isInterimResponseStartLine(_ startLine: String) -> Bool {
        guard startLine.hasPrefix("HTTP/1.") else { return false }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, let status = parseHTTPStatusCode(parts[1]) else { return false }
        return (100..<200).contains(status) && status != 101
    }

    private func serializeHead(startLine: String, headers: [Header]) -> Data {
        // Defense in depth against response-splitting: never put a header whose
        // name or value carries CR / LF / NUL on the wire. Every current caller
        // already feeds validated headers (``parseHead`` rejects them on the
        // original path; the synth / ``Anywhere.respond`` paths validate; and
        // script readback is body-only, so a script's ``ctx.headers`` write
        // never reaches here), so this drops nothing in practice — it just makes
        // the no-splitting invariant local to the one function that emits the
        // head, so a future change that lets a script mutate headers can't
        // silently reopen a splitting hole at this boundary.
        let safeHeaders = headers.filter { entry in
            guard !Self.containsControlChars(entry.name),
                  !Self.containsControlChars(entry.value) else {
                logger.warning("[MITM] HTTP/1 \(host): dropping header with CR/LF/NUL from serialized head: \(entry.name)")
                return false
            }
            return true
        }
        // Total bytes: start line + CRLF, then each header as
        // `name: value` + CRLF, then a final CRLF. Reserving up front
        // skips the `Data` reallocation chain a head with many
        // headers would otherwise trigger.
        var size = startLine.utf8.count + 4
        for (name, value) in safeHeaders {
            size += name.utf8.count + 2 + value.utf8.count + 2
        }
        var out = Data(capacity: size)
        out.append(contentsOf: startLine.utf8)
        out.append(0x0D); out.append(0x0A)
        for (name, value) in safeHeaders {
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
    ///
    /// Header names are checked against RFC 9110 §5.6.2 (token chars
    /// only) and values against §5.5 (no CR/LF/NUL). Entries that
    /// violate either are dropped with a warning so a script — even an
    /// imported third-party one — can't smuggle CRLF into the header
    /// block and split the response (response-splitting).
    private func queueSynthesizedResponse(_ response: MITMScriptEngine.SynthesizedResponse) {
        let reason = canonicalReasonPhrase(for: response.status)
        let startLine = "HTTP/1.1 \(response.status) \(reason)"
        var headers = response.sanitizedHeaders(lowercaseNames: false) { name in
            logger.warning("[MITM][JS] HTTP/1 \(host): Anywhere.respond dropping invalid header: \(name)")
        }
        let body = response.truncatedBody(cap: Self.maxSynthesizedResponseBodyBytes) { size in
            logger.warning("[MITM][JS] HTTP/1 \(host): Anywhere.respond body \(size) B exceeds memory cap \(Self.maxSynthesizedResponseBodyBytes) B; truncating")
        }
        headers.append((name: "Content-Length", value: String(body.count)))
        var bytes = serializeHead(startLine: startLine, headers: headers)
        if !body.isEmpty {
            bytes.append(body)
        }
        // Pipeline-order preservation: when an earlier pipelined
        // request is still awaiting its upstream response, the synth
        // bytes MUST land after that response or the client (which
        // matches responses to requests by arrival order, RFC 9112
        // §9.3.2) will pair them with the wrong request. Attach to
        // the newest in-flight record so the response stream emits
        // them once its matching response has streamed in full. With
        // an empty queue there is no predecessor to wait on — the
        // bytes go straight to the client via the existing inject
        // path, which the session pump drains into the inner TLS
        // record right after this transform call returns.
        if requestLog.isHTTP1QueueEmpty {
            pendingClientBytes.append(bytes)
        } else {
            requestLog.attachSynthAfterLastHTTP1(bytes)
        }
    }

    /// RFC 9110 §9.1: a method name is a `token` — the same tchar+
    /// alphabet as header field-names. Scripts can write ``ctx.method``
    /// to any string, so validating it blocks a value like
    /// ``"GET /attacker HTTP/1.1\r\nHost: a"`` from smuggling a full
    /// request line into the start position.
    private static func isValidMethodToken(_ s: String) -> Bool {
        return isValidHTTPHeaderName(s)
    }

    /// RFC 9112 §3.2: a request-target's syntax forbids SP, HTAB, CR,
    /// LF, NUL, and other CTL bytes. We additionally reject DEL (0x7F)
    /// since it is a CTL byte under RFC 9110 §5.6.1. Used to guard the
    /// post-script and post-regex-substitution request-target before
    /// it is interpolated into the start line.
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
        if phase == .httpResponse {
            // RFC 9110 §15.2: a response to HEAD never carries a body
            // regardless of Content-Length / Transfer-Encoding. Without
            // this short-circuit a HEAD response with `Content-Length:
            // 1234` would have us wait for 1234 bytes that never arrive
            // — or, on keep-alive, consume bytes from the next pipelined
            // response.
            if let method = originatingMethod,
               method.uppercased() == "HEAD" {
                return .none
            }
            // Status line: "HTTP/1.x SSS Reason"
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let status = parseHTTPStatusCode(parts[1]) {
                // RFC 9110 §9.3.6: a 2xx response to CONNECT turns the
                // connection into an opaque tunnel — no body, and no further
                // HTTP framing on either leg. Treat it like 101 so the head is
                // forwarded untouched (no spurious `Connection: close`) and the
                // session flips BOTH directions to passthrough. A non-2xx CONNECT
                // response means the tunnel was refused and is framed normally.
                if (200..<300).contains(status),
                   originatingMethod?.uppercased() == "CONNECT" {
                    return .switchingProtocols
                }
                if status == 101 { return .switchingProtocols }
                if status == 204 || status == 304 { return .none }
                if status >= 100 && status < 200 { return .none }
            }
        }
        // Single-pass scan: Transfer-Encoding takes precedence over
        // Content-Length per RFC 9112 §6.3. ``parseHead`` already
        // normalized the smuggling vector where both appear on the same
        // head (it strips ``Content-Length`` when TE: chunked is
        // present), so this scan only needs to decide framing.
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
            // RFC 9112 §6.1: ``chunked`` MUST be the final transfer-coding.
            // ``Transfer-Encoding: gzip`` (no chunked) frames as read-until-close
            // for a response; for a request it is a protocol error. Decided via
            // the same ``transferEncodingIsChunked`` predicate ``parseHead``
            // validates with, so the framing applied here can never drift from
            // the head's implied framing (a smuggling-vector divergence).
            if Self.transferEncodingIsChunked(te) {
                return .chunked
            }
        }
        if let cl = contentLength {
            let trimmed = cl.trimmingCharacters(in: CharacterSet.whitespaces)
            // RFC 9112 §6.3: Content-Length is `1*DIGIT`. ``Int`` also accepts a
            // leading `+`, so `Content-Length: +5` would parse here yet be
            // rejected (or read differently) by a stricter peer — a framing
            // divergence that enables request smuggling. ``isCleanContentLength``
            // (the same gate ``parseHead`` rejects on) requires pure ASCII digits.
            if Self.isCleanContentLength(trimmed), let length = Int(trimmed) {
                return length == 0 ? .none : .contentLength(length)
            }
        }
        return phase == .httpRequest ? .none : .readUntilClose
    }

    /// Advisory log for when a buffered ``.script`` rule is about to
    /// rewrite a streaming response (SSE and friends; see
    /// ``MITMScriptTransform/isStreamingMediaType(_:)``). Buffering
    /// de-streams the body — the client sees nothing until the whole
    /// body arrives or the buffer cap trips — so we point the author at
    /// ``streamScript``. We still apply the rule, as requested; this is
    /// advisory only. Response phase only.
    private func warnIfBufferedScriptDeStreams(_ headers: [Header]) {
        let contentType = firstHeaderValue(headers, name: "content-type")
        guard phase == .httpResponse,
              MITMScriptTransform.isStreamingMediaType(contentType) else { return }
        logger.warning("[MITM] \(host): buffered Script on a streaming response. Switch to Stream Script to rewrite frames as they arrive.")
    }

    /// Returns all values for a header name, joined by ``", "`` per
    /// RFC 9110 §5.3 (semantically equivalent to a single field with
    /// the combined value). Used for headers like
    /// ``Content-Encoding`` where multiple values across separate
    /// header lines must all be honored — picking only the first via
    /// ``firstHeaderValue`` would let a second ``Content-Encoding:
    /// br`` slip past while we only decoded ``gzip``, leaving the
    /// brotli-compressed body on the wire with the encoding header
    /// stripped.
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

    /// When a transparent ``MITMOperation/rewrite`` has set
    /// ``effectiveAuthority`` (the replacement changed the host), the
    /// request's Host header is forced to that authority so the redirected
    /// request reaches an authority the upstream can route.
    private func applyAuthorityRewrite(_ headers: [Header]) -> [Header] {
        guard phase == .httpRequest, let authority = effectiveAuthority else {
            return headers
        }
        var result = headers.filter { !$0.name.equalsIgnoringASCIICase("host") }
        result.append((name: "Host", value: authority))
        return result
    }

    /// Outcome of applying the request-phase "Rewrite" operation to a start
    /// line: either continue with a (possibly rewritten) start line, or
    /// short-circuit the request with a synthesized response (302 / reject).
    private enum RewriteOutcome {
        case rewritten(String)
        case synthesize(MITMScriptEngine.SynthesizedResponse)
    }

    /// Applies the first matching request-phase ``MITMOperation/rewrite``
    /// rule. Request phase only; no-op on responses, asterisk-form
    /// (`OPTIONS *`), or unparseable lines. A `transparent` rule rewrites the
    /// request-target to the replacement's path+query and sets
    /// ``effectiveAuthority`` + ``resolvedUpstream`` so the authority is
    /// rewritten and the session dials the replacement host; the synthesize
    /// sub-modes return a canned response. First match wins (the replacement
    /// is a literal full URL, so chaining rewrites is meaningless).
    private func applyRewrite(_ startLine: String) -> RewriteOutcome {
        guard phase == .httpRequest else { return .rewritten(startLine) }
        guard rules.contains(where: {
            if case .rewrite = $0.operation { return true }
            return false
        }) else { return .rewritten(startLine) }

        // Request-line shape: METHOD SP request-target SP HTTP-version.
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return .rewritten(startLine) }
        let method = String(parts[0])
        let target = String(parts[1])
        let version = String(parts[2])

        // Asterisk-form (RFC 9112 section 3.2.4) is reserved for OPTIONS *
        // and is not a meaningful target for rewrites.
        if target == "*" { return .rewritten(startLine) }

        for rule in rules {
            guard case .rewrite(let action) = rule.operation else { continue }
            guard rule.matchesURL("https://\(host)\(target)") else { continue }
            switch action {
            case .transparent(let replacement):
                // The replacement path is validated wire-safe at load time;
                // re-validate as a backstop before splicing it onto the line.
                guard Self.isValidRequestTarget(replacement.requestTarget) else {
                    logger.warning("[MITM] HTTP/1 \(host): rewrite produced an invalid request-target; skipping rule")
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

    /// Request-phase short-circuit for a 302 / reject ``MITMOperation/rewrite``:
    /// queues the synthesized response for the inner leg (the session pump
    /// drains it via ``drainPendingClientBytes``), emits nothing upstream, and
    /// consumes the request body per its framing so a kept-alive connection
    /// parses the next request cleanly. The request is deliberately NOT logged
    /// to ``requestLog`` — there is no upstream round-trip to correlate, so a
    /// record would never be popped and would desync the FIFO.
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

    /// ``requestURL`` is the whole request URL the gate is tested against;
    /// a rule whose ``urlPattern`` doesn't match it is skipped.
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

    /// The whole request URL used to gate every rule's ``urlPattern``.
    /// Request phase: `https://host` joined with the (already rewritten)
    /// start-line target. Response phase: the originating request's URL, so
    /// a response rule gates on the URL the client asked for. nil —
    /// indeterminate — fails the gate closed.
    private func requestURLForGating(
        startLine: String,
        originatingRequest: MITMRequestLog.Record?
    ) -> String? {
        switch phase {
        case .httpRequest:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 2 else { return nil }
            let target = String(parts[1])
            // Asterisk-form (OPTIONS *) is not a path to match against.
            return target == "*" ? nil : "https://\(host)\(target)"
        case .httpResponse:
            return originatingRequest?.url
        }
    }

    // MARK: - Message build / head rebuild

    /// Builds a ``HTTPMessage`` from the in-flight head
    /// state. On response phase, fills in `method`/`url` from the
    /// originating request (looked up via ``MITMRequestLog`` by the
    /// caller).
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

    /// Rebuilds the start/status line from a (possibly script-mutated)
    /// message. For requests, the URL's path-and-query becomes the
    /// request-target; the host portion is ignored since the upstream
    /// is fixed at session creation. For responses, the status code
    /// flows into the status line with a canonical reason phrase. The
    /// HTTP version is preserved from the input start line on both
    /// phases so a legacy HTTP/1.0 peer isn't silently upgraded mid-
    /// session. Falls back to the original line when the message
    /// lacks the fields needed to rebuild.
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
            // Validate script-supplied method against RFC 9110 §9.1
            // (method = token). A script bug or hostile rule set that
            // set ``ctx.method = "GET /x HTTP/1.1\r\n"`` would
            // otherwise smuggle a full request line through the
            // upstream side, bypassing any upstream auth that gates
            // off the first request line.
            guard Self.isValidMethodToken(method) else {
                logger.warning("[MITM][JS] HTTP/1 \(host): dropping invalid method '\(method)' from Script")
                return fallback
            }
            // ``pathAndQuery`` returns nil for inputs that look
            // relative (no scheme + no host). Fall back to the original
            // request-target rather than the raw ``url`` string: on a
            // malformed input the raw string could put an absolute-form
            // (``https://host/path``) request-target on the wire —
            // legal per RFC 9112 §3.2.2 but unintended and confusing
            // for upstreams. The fallback preserves wire shape when the
            // script wrote a URL the parser doesn't recognise.
            let originalTarget = parts.count >= 2 ? String(parts[1]) : "/"
            let candidateTarget = pathAndQuery(fromURL: url) ?? originalTarget
            // RFC 9112 §3.2: SP/CR/LF/NUL/CTL cannot appear in the
            // request-target. A script that built a URL containing
            // any of those (via percent-decode mishap or template
            // injection) would otherwise split the start line.
            guard Self.isValidRequestTarget(candidateTarget) else {
                logger.warning("[MITM][JS] HTTP/1 \(host): dropping invalid request-target from Script")
                return fallback
            }
            // Request start line: METHOD SP target SP HTTP-version.
            // ``parts[2]`` is the version when the fallback parsed; fall
            // back to 1.1 only when the original line was malformed.
            let version = parts.count >= 3 ? String(parts[2]) : "HTTP/1.1"
            return "\(method) \(candidateTarget) \(version)"
        case .httpResponse:
            guard let status = message.status else { return fallback }
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
    /// Resume cursor for the chunk-size / trailer CRLF scan so a line arriving
    /// across many records isn't re-scanned from the front each call (O(n²) →
    /// O(n)). First index not yet checked as a CR candidate; reset to 0 when a
    /// line is consumed, advanced only on a `needMore` (no-consume) return. The
    /// buffer is presented 0-indexed and only grows at the end while a line is
    /// pending, so the cursor stays valid across appends/compaction.
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
                // Validate the size line *before* forwarding it. On a malformed
                // size the caller synthesizes a clean ``0\r\n\r\n`` terminator —
                // but that only frames cleanly if we haven't already emitted the
                // unparseable size line ahead of it. Return ``.malformed`` with
                // the bytes still in the buffer (the caller clears them).
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
                // Forward mode never re-chunks, so it has no use for the
                // original chunk sizes; appending one ``Int`` per chunk here
                // would grow ``sizes`` for the whole body with nothing ever
                // reading it — an unbounded accumulation a small-chunk stream
                // can amplify. Only ``consumeBuffered`` (which returns them for
                // re-chunking) tracks sizes.
                state = .sizeLine
            case .trailerOrEnd:
                // Forward the trailer block (zero or more lines + CRLF)
                // verbatim until the empty-line terminator.
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
                // Rewritten bodies are re-chunked with empty trailers, so
                // consume and discard any original trailers here.
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

    /// Unified entry point for ``MITMSession``'s pumps; forwards to
    /// ``transform(_:completion:)``, the HTTP/1 framing state machine's feed.
    func feed(_ data: Data, completion: @escaping (Data) -> Void) {
        transform(data, completion: completion)
    }

    /// HTTP/1 has no per-stream flow-control windows, so there is no
    /// upstream-bound credit to drain — the concept is HTTP/2-only.
    func drainPendingServerBytes() -> Data { Data() }
}
