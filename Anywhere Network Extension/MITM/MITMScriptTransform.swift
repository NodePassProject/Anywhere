//
//  MITMScriptTransform.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import JavaScriptCore

/// Applies the script subset of a compiled rule list to a buffered,
/// decompressed HTTP message. The HTTP/1.1 and HTTP/2 rewriters share
/// this entry point so the rule-application loop lives in one place.
///
/// **Single-rule semantics.** At most one ``.script`` and at most one
/// ``.streamScript`` fire on a given message; when several rules of the
/// same kind match the request's URL, the last in rule order wins.
///
/// Capping at one rule per kind keeps the hot path lean — no chain
/// orchestration, no repeated Swift↔JS ctx round-trips per rule, no
/// intermediate message copies — and rules out a state-collision hazard
/// a chain would create: ``Anywhere.store`` keys are scoped to the rule
/// set (not the rule), and the per-stream ``FrameCursor.state`` slot is
/// single-valued, so two scripts chained on the same URL would stomp
/// each other's persistent state on every frame. Authors who need
/// composed behaviour should consolidate logic into a single
/// `process(ctx)` function.
enum MITMScriptTransform {

    /// Serial queue that carries every off-lwIP-queue script invocation.
    ///
    /// All MITM JavaScript runs here rather than inline on the lwIP queue,
    /// so a slow or pathological `process(ctx)` on one connection parks only
    /// that connection while every other flow in the tunnel keeps moving on
    /// the lwIP queue. One process-wide serial queue is correct and
    /// sufficient: a ``MITMScriptEngine``'s ``JSContext`` shares a single
    /// process-wide ``JSVirtualMachine`` whose internal mutex already
    /// serializes heap access across engines, and each engine's
    /// ``invocationLock`` enforces the "calls are serialized" contract the
    /// engine was built around (see the lock note in ``MITMScriptEngine``).
    /// Serial also gives the property the async entry points below rely on:
    /// per stream, frame N's engine call completes before frame N+1's begins,
    /// so the shared ``FrameCursor`` is never touched concurrently.
    static let scriptQueue = DispatchQueue(
        label: AWCore.Identifier.mitmScriptQueue,
        qos: .userInitiated
    )

    /// Builds the JS engine and compiles the `process` source of every
    /// script / streamScript rule ahead of any traffic, on ``scriptQueue``
    /// (off the lwIP queue). Called from ``MITMRewritePolicy/load`` when
    /// MITM is (re)configured, so the cold start lands there instead of
    /// inside the first intercepted flow that matches a script rule — where
    /// it would otherwise run while that connection is parked. The cold
    /// start is the dominant first-call cost: the first engine spins up the
    /// shared ``JSVirtualMachine`` and installs the whole ``Anywhere`` API,
    /// then each unique source is parsed and compiled. (JIT tier-up still
    /// happens on the first real call — warming it would mean executing
    /// user code speculatively, which isn't safe.)
    ///
    /// One async task per scope so a real script call dispatched mid-prewarm
    /// interleaves between scopes rather than waiting for all of them.
    static func prewarm(scopedRules: [(scope: UUID, rules: [CompiledMITMRule])]) {
        for entry in scopedRules {
            // Dedupe by cache key: the same source on several rules (e.g.
            // request + response phase) needs compiling only once. ``let`` so
            // the list is captured by value into the sendable async closure.
            var seen = Set<Int>()
            let scripts: [(source: String, sourceKey: Int)] = entry.rules.compactMap { rule in
                switch rule.operation {
                case .script(let source, let sourceKey), .streamScript(let source, let sourceKey):
                    return seen.insert(sourceKey).inserted ? (source: source, sourceKey: sourceKey) : nil
                case .rewrite, .headerAdd, .headerDelete, .headerReplace, .bodyReplace, .bodyJSON:
                    return nil
                }
            }
            guard !scripts.isEmpty else { continue }
            let scope = entry.scope
            scriptQueue.async {
                let engine = MITMScriptEngine.sharedEngine(forScope: scope)
                for script in scripts {
                    engine.precompile(source: script.source, sourceKey: script.sourceKey)
                }
            }
        }
    }

    /// Result of running a buffered ``.script`` rule on a message.
    /// Distinguishes the normal rewrite path (``message``) from a
    /// request-phase `Anywhere.respond(...)` short-circuit
    /// (``synthesizedResponse``). Streaming-script rules don't produce
    /// this outcome — see ``applyFrame``.
    enum Outcome {
        /// Use the (possibly mutated) message as the rewrite result;
        /// emit to the upstream leg as usual.
        case message(HTTPMessage)
        /// Request-phase script called `Anywhere.respond(...)`. Drop
        /// the request without forwarding upstream and synthesize this
        /// response back to the client.
        case synthesizedResponse(MITMScriptEngine.SynthesizedResponse)
    }

    /// True when at least one ``.script`` rule in ``rules`` would fire
    /// for the given request URL. Rewriters consult this at
    /// head-completion time to decide whether to defer head emission
    /// (and, for bodied messages, buffer the body).
    ///
    /// Streaming rules win when both apply (see ``hasStreamScriptRule``)
    /// so callers should check the streaming variant first and only
    /// fall through to the buffered path when no stream rule matches.
    static func hasScriptRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .script:
                return rule.matchesURL(requestURL)
            case .streamScript, .rewrite, .headerAdd, .headerDelete, .headerReplace, .bodyReplace, .bodyJSON:
                return false
            }
        }
    }

    /// True when at least one ``.streamScript`` rule in ``rules``
    /// would fire for the given request URL. Both rewriters
    /// consult this at head-completion time to decide whether to
    /// enter per-frame streaming mode (emit head immediately, no
    /// body buffering, no HTTP-level decompression).
    static func hasStreamScriptRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .streamScript:
                return rule.matchesURL(requestURL)
            case .script, .rewrite, .headerAdd, .headerDelete, .headerReplace, .bodyReplace, .bodyJSON:
                return false
            }
        }
    }

    /// True when at least one ``.bodyJSON`` rule in ``rules`` would fire
    /// for the given request URL. ``.bodyJSON`` is a buffered body
    /// transform like ``.script`` — the rewriters must accumulate and
    /// decompress the body before its native JSON edits can run — so it is
    /// folded into ``hasBufferedBodyRule``.
    static func hasBodyJSONRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        rules.contains { rule in
            if case .bodyJSON = rule.operation { return rule.matchesURL(requestURL) }
            return false
        }
    }

    /// True when at least one ``.bodyReplace`` rule in ``rules`` would fire
    /// for the given request URL. Like ``.bodyJSON`` it is a buffered
    /// body transform (the regex runs over the whole decompressed body), so
    /// it too is folded into ``hasBufferedBodyRule``.
    static func hasBodyReplaceRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        rules.contains { rule in
            if case .bodyReplace = rule.operation { return rule.matchesURL(requestURL) }
            return false
        }
    }

    /// True when any **buffered** body transform would fire: a ``.script``,
    /// one or more ``.bodyReplace`` edits, or one or more ``.bodyJSON``
    /// edits. The HTTP/1 and HTTP/2 rewriters gate body buffering on this —
    /// every kind needs the whole (decompressed) body in hand before it can
    /// run, and all are applied together by ``apply``. ``.streamScript`` is
    /// deliberately excluded: it runs per-frame without buffering and is
    /// gated by ``hasStreamScriptRule`` instead, which callers must check
    /// first.
    static func hasBufferedBodyRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        hasScriptRule(in: rules, requestURL: requestURL)
            || hasBodyReplaceRule(in: rules, requestURL: requestURL)
            || hasBodyJSONRule(in: rules, requestURL: requestURL)
    }

    /// Recognises response media types whose whole point is incremental
    /// delivery — Server-Sent Events, multipart server-push / motion
    /// JPEG, and the newline-/record-delimited JSON streaming formats.
    /// A buffered ``.script`` rule on one of these de-streams it: the
    /// rewriter must accumulate the entire body before the client sees a
    /// single byte. The rule still runs (the author asked for it), but
    /// the rewriters use this to warn that a ``.streamScript`` rule
    /// (per-frame, no buffering) is the better fit. Matches on the media
    /// type alone — parameters like `; charset=utf-8` or `; boundary=…`
    /// don't change the verdict.
    static func isStreamingMediaType(_ contentType: String?) -> Bool {
        guard let raw = contentType else { return false }
        let mediaType = raw
            .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            ?? ""
        switch mediaType {
        case "text/event-stream",            // Server-Sent Events
             "multipart/x-mixed-replace",    // server push / motion JPEG
             "application/x-ndjson",         // newline-delimited JSON
             "application/jsonl",
             "application/stream+json",
             "application/json-seq":         // RFC 7464 JSON text sequences
            return true
        default:
            return false
        }
    }

    /// Applies the composing native body transforms — every matching
    /// ``.bodyJSON`` edit, then every matching ``.bodyReplace`` edit, each in
    /// rule order — to ``message`` and returns the edited copy. JSON edits run
    /// before the text replace so the latter operates on the re-serialized
    /// JSON; both run before any ``.script`` (which sees the already-edited
    /// body) and survive its ``Anywhere.exit``, mirroring how header rules
    /// commit before the script. Header-only and script rules are untouched
    /// here. The async entry point below runs this ahead of the script.
    private static func applyNativeBodyEdits(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule]
    ) -> HTTPMessage {
        let requestURL = message.url
        var message = message
        let jsonOps = matchingBodyJSONOps(in: rules, requestURL: requestURL)
        if !jsonOps.isEmpty {
            message.body = MITMJSONPatch.applyAll(jsonOps, to: message.body)
        }
        let replaceOps = matchingBodyReplaceOps(in: rules, requestURL: requestURL)
        if !replaceOps.isEmpty {
            message.body = MITMBodyReplace.applyAll(replaceOps, to: message.body)
        }
        return message
    }

    /// The compiled ``.bodyJSON`` edits whose URL pattern matches the
    /// request URL, in rule order. Unlike the single-rule ``.script``
    /// (last match wins), **every** matching ``.bodyJSON`` rule is
    /// returned so the edits compose — ``MITMJSONPatch/applyAll`` runs them
    /// against one parse of the body.
    private static func matchingBodyJSONOps(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) -> [MITMJSONPatch.CompiledOp] {
        var ops: [MITMJSONPatch.CompiledOp] = []
        for rule in rules {
            if case .bodyJSON(let op) = rule.operation, rule.matchesURL(requestURL) {
                ops.append(op)
            }
        }
        return ops
    }

    /// The compiled ``.bodyReplace`` edits whose URL pattern matches the
    /// request URL, in rule order. Like ``matchingBodyJSONOps``, **every**
    /// matching rule is returned so the regex replacements compose —
    /// ``MITMBodyReplace/applyAll`` runs them against the running body text.
    private static func matchingBodyReplaceOps(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) -> [MITMBodyReplace.CompiledOp] {
        var ops: [MITMBodyReplace.CompiledOp] = []
        for rule in rules {
            if case .bodyReplace(let search, let replacement) = rule.operation, rule.matchesURL(requestURL) {
                ops.append(MITMBodyReplace.CompiledOp(search: search, replacement: replacement))
            }
        }
        return ops
    }

    /// The script entry point the HTTP/1 and HTTP/2 rewriters call. Runs the
    /// native body edits and the matching ``.script`` rule on ``scriptQueue``
    /// (never on the caller's lwIP queue) and delivers the ``Outcome`` back on
    /// ``resumeQueue``. The script runs through ``MITMScriptEngine/applyAsync``,
    /// so an `async function process(ctx)` that `await`s ``Anywhere.http``
    /// suspends **without holding ``scriptQueue``** — other connections' scripts
    /// keep running while this one waits on the network — and the connection
    /// stays parked until its fetch(es) settle. A plain (synchronous) script is
    /// unaffected: it settles inline before the queue is released.
    ///
    /// Contract the rewriters depend on:
    /// - ``completion`` is invoked **exactly once**, **on ``resumeQueue``**
    ///   (so the caller's parked driver always resumes on the lwIP queue),
    ///   however long the awaited fetch takes.
    /// - The work always hops: callers reach this only after their own
    ///   head-time gate (`hasScriptRule`) said a script applies, so the
    ///   lwIP-side fast path lives entirely above this call and never pays a
    ///   queue round-trip. A rule that no longer matches once re-checked here
    ///   (e.g. a `rewrite` changed the path) simply yields
    ///   ``Outcome/message`` unchanged.
    /// - ``message`` (and its `body` `Data`) is captured by the dispatched
    ///   closure and stays alive for the engine call's duration; it is a
    ///   value copy, never aliased to the caller's receive buffer.
    static func apply(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider?,
        resumeOn resumeQueue: DispatchQueue,
        completion: @escaping (Outcome) -> Void
    ) {
        scriptQueue.async {
            // Native body edits run synchronously here (they never await); the
            // script then sees the already-edited body.
            let requestURL = message.url
            let edited = applyNativeBodyEdits(message, rules: rules)
            guard let match = lastMatchingScriptSource(in: rules, requestURL: requestURL),
                  let engineProvider
            else {
                resumeQueue.async { completion(.message(edited)) }
                return
            }
            // ``applyAsync`` frees this serial queue while the script awaits an
            // ``Anywhere.http`` fetch (so other connections' scripts keep
            // running) and delivers the engine ``Outcome`` on ``resumeQueue``
            // exactly once — the closure below already runs there and maps
            // straight to a transform ``Outcome``. ``.exit`` reverts to the
            // post-native-edit message, since the native edits commit ahead of
            // the script and survive it.
            engineProvider.get().applyAsync(
                edited,
                source: match.source,
                sourceKey: match.sourceKey,
                resumeOn: resumeQueue
            ) { outcome in
                switch outcome {
                case .modified(let updated):  completion(.message(updated))
                case .done(let updated):      completion(.message(updated))
                case .exit:                   completion(.message(edited))
                case .respond(let response):  completion(.synthesizedResponse(response))
                }
            }
        }
    }

    /// Per-stream cursor for ``applyFrame``: the script's persistent
    /// state object and a sticky "skip remainder" flag set when a
    /// previous frame returned ``FrameOutcome/done`` or ``exit``. The
    /// caller owns one of these per active stream and threads it
    /// through each frame.
    ///
    /// With single-rule semantics the ``state`` slot has unambiguous
    /// ownership: it belongs to the one ``.streamScript`` rule that
    /// matched the stream's request URL at head time. Earlier
    /// matching rules don't run on this stream and so can't trample
    /// the slot.
    final class FrameCursor {
        /// The script's persistent per-stream state object, threaded frame
        /// to frame. A ``JSValue`` bound to the process-wide shared
        /// ``MITMScriptEngine`` VM; it is **only ever read or written on
        /// ``scriptQueue``** (inside the engine's ``applyFrame``). Its
        /// release is hopped to ``scriptQueue`` by ``deinit`` — see there.
        var state: JSValue?
        /// True once a script directive said "we're done with this
        /// stream" — subsequent frames bypass the script entirely.
        var bypass: Bool = false
        /// Memoized stream-script resolution for this stream. A stream's
        /// request URL and rule list are fixed for its lifetime, so
        /// ``applyFrame`` resolves the matching ``.streamScript`` on the
        /// first frame and reuses it — avoiding a per-frame URL parse and
        /// a per-frame walk of the rule list (each rule a regex match) on
        /// long-lived streams (SSE, gRPC, chunked APIs). Outer `nil` means
        /// "not resolved yet"; `.some(nil)` means "resolved: no rule
        /// matches"; `.some(.some)` carries the matched script.
        fileprivate var resolvedMatch: ScriptMatch??
        init() {}

        deinit {
            // ``state``'s final release calls JSValueUnprotect, which mutates
            // GC / protected-set bookkeeping on the process-wide shared
            // JSVirtualMachine. That must run on ``scriptQueue`` — the one
            // queue that touches the VM — not on whatever queue drops the last
            // reference to this cursor (typically the lwIP queue on stream
            // teardown, or ARC during connection teardown), where it would
            // race another connection's in-flight script span on the same VM
            // and risk heap corruption. Handing the value to ``scriptQueue``
            // moves the 0-refcount release (the actual JSValueUnprotect) there;
            // the stored-property release during this deinit only decrements to
            // the closure's reference, so no VM bookkeeping happens off-queue.
            guard let state else { return }
            MITMScriptTransform.scriptQueue.async { withExtendedLifetime(state) {} }
        }
    }

    /// Result of running the matching streaming-script rule on one
    /// frame.
    struct StreamFrameResult {
        let body: Data
        let bypass: Bool
    }

    /// Runs the single matching ``.streamScript`` rule against one
    /// frame, picking the last matching rule when several qualify
    /// (overwrite semantics). ``Anywhere.done`` short-circuits and
    /// sets ``cursor.bypass`` so the caller stops feeding subsequent
    /// frames to the script. ``Anywhere.exit`` reverts to the input
    /// frame and also sets ``bypass``.
    static func applyFrame(
        _ frame: Data,
        rules: [CompiledMITMRule],
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) -> StreamFrameResult {
        // Resolve the stream-script on the first frame and reuse it
        // thereafter; see ``FrameCursor.resolvedMatch``.
        let resolved: ScriptMatch?
        if let cached = cursor.resolvedMatch {
            resolved = cached
        } else {
            resolved = lastMatchingStreamScriptSource(in: rules, requestURL: frameContext.url)
            cursor.resolvedMatch = resolved
        }
        guard let match = resolved, let engineProvider
        else { return StreamFrameResult(body: frame, bypass: false) }
        let outcome = engineProvider.get().applyFrame(
            frame,
            source: match.source,
            sourceKey: match.sourceKey,
            frameContext: frameContext,
            state: cursor.state
        )
        switch outcome {
        case .modified(let body, let state):
            cursor.state = state
            return StreamFrameResult(body: body, bypass: false)
        case .done(let body):
            cursor.bypass = true
            return StreamFrameResult(body: body, bypass: true)
        case .exit:
            cursor.bypass = true
            return StreamFrameResult(body: frame, bypass: true)
        }
    }

    /// Off-queue counterpart to
    /// ``applyFrame(_:rules:frameContext:cursor:engineProvider:)``. Runs the
    /// matching ``.streamScript`` rule on ``scriptQueue`` and delivers the
    /// ``StreamFrameResult`` back on ``resumeQueue``.
    ///
    /// Same contract as the async ``apply`` above: ``completion`` fires
    /// exactly once on ``resumeQueue``. ``cursor`` is a reference type whose
    /// ``state``/``bypass`` are mutated by the engine call on ``scriptQueue``;
    /// this is safe because the caller never dispatches frame N+1 until frame
    /// N's completion has fired (one-frame-in-flight), so the cursor is never
    /// read on the lwIP queue while a hop is outstanding.
    static func applyFrame(
        _ frame: Data,
        rules: [CompiledMITMRule],
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?,
        resumeOn resumeQueue: DispatchQueue,
        completion: @escaping (StreamFrameResult) -> Void
    ) {
        scriptQueue.async {
            let result = applyFrame(
                frame,
                rules: rules,
                frameContext: frameContext,
                cursor: cursor,
                engineProvider: engineProvider
            )
            resumeQueue.async { completion(result) }
        }
    }

    // MARK: - Last-match selection

    /// Match for a script lookup: the source the engine compiles plus
    /// the precomputed cache key the engine uses to dedup compilation
    /// across calls.
    fileprivate struct ScriptMatch {
        let source: String
        let sourceKey: Int
    }

    /// Returns the source of the last ``.script`` rule whose URL
    /// pattern matches the request URL, or nil when none match.
    /// Walks rules back-to-front so the first hit is the winner.
    private static func lastMatchingScriptSource(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .script(let source, let sourceKey) = rule.operation,
               rule.matchesURL(requestURL) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }

    /// Returns the source of the last ``.streamScript`` rule whose
    /// URL pattern matches the request URL, or nil when none match.
    private static func lastMatchingStreamScriptSource(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .streamScript(let source, let sourceKey) = rule.operation,
               rule.matchesURL(requestURL) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }
}
