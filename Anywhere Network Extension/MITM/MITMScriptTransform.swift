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
                case .urlReplace, .headerAdd, .headerDelete, .headerReplace:
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
        case message(MITMScriptEngine.Message)
        /// Request-phase script called `Anywhere.respond(...)`. Drop
        /// the request without forwarding upstream and synthesize this
        /// response back to the client.
        case synthesizedResponse(MITMScriptEngine.SynthesizedResponse)
    }

    /// True when at least one ``.script`` rule in ``rules`` would fire
    /// for the given request-target. Rewriters consult this at
    /// head-completion time to decide whether to defer head emission
    /// (and, for bodied messages, buffer the body).
    ///
    /// Streaming rules win when both apply (see ``hasStreamScriptRule``)
    /// so callers should check the streaming variant first and only
    /// fall through to the buffered path when no stream rule matches.
    static func hasScriptRule(in rules: [CompiledMITMRule], pathAndQuery: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .script:
                return rule.matchesURL(pathAndQuery)
            case .streamScript, .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                return false
            }
        }
    }

    /// True when at least one ``.streamScript`` rule in ``rules``
    /// would fire for the given request-target. Both rewriters
    /// consult this at head-completion time to decide whether to
    /// enter per-frame streaming mode (emit head immediately, no
    /// body buffering, no HTTP-level decompression).
    static func hasStreamScriptRule(in rules: [CompiledMITMRule], pathAndQuery: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .streamScript:
                return rule.matchesURL(pathAndQuery)
            case .script, .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                return false
            }
        }
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

    /// Runs the single ``.script`` rule whose URL pattern matches the
    /// request-target, picking the last matching rule when several
    /// would qualify (overwrite semantics; see the type-level note).
    /// Header-only rules are no-ops here (they ran at head time).
    /// Returns ``Outcome/message`` carrying the input unchanged when
    /// no rule matches or ``engineProvider`` is nil; returns
    /// ``Outcome/synthesizedResponse`` when a request-phase script
    /// called `Anywhere.respond(...)`.
    static func apply(
        _ message: MITMScriptEngine.Message,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider? = nil
    ) -> Outcome {
        let pathAndQuery = MITMRequestURL.pathAndQuery(from: message.url)
        guard let match = lastMatchingScriptSource(in: rules, pathAndQuery: pathAndQuery),
              let engineProvider
        else { return .message(message) }
        let outcome = engineProvider.get().apply(
            message,
            source: match.source,
            sourceKey: match.sourceKey
        )
        switch outcome {
        case .modified(let updated):  return .message(updated)
        case .done(let updated):      return .message(updated)
        case .exit:                   return .message(message)
        case .respond(let response):  return .synthesizedResponse(response)
        }
    }

    /// Off-queue counterpart to ``apply(_:rules:engineProvider:)``. Runs the
    /// matching ``.script`` rule on ``scriptQueue`` (never on the caller's
    /// lwIP queue) and delivers the ``Outcome`` back on ``resumeQueue``.
    ///
    /// Contract the rewriters depend on:
    /// - ``completion`` is invoked **exactly once**, **on ``resumeQueue``**
    ///   (so the caller's parked driver always resumes on the lwIP queue).
    /// - The work always hops: callers reach this only after their own
    ///   head-time gate (`hasScriptRule`) said a script applies, so the
    ///   lwIP-side fast path lives entirely above this call and never pays a
    ///   queue round-trip. A rule that no longer matches once re-checked here
    ///   (e.g. a `url-replace` moved the path) simply yields
    ///   ``Outcome/message`` unchanged — same as the synchronous variant.
    /// - ``message`` (and its `body` `Data`) is captured by the dispatched
    ///   closure and stays alive for the engine call's duration; it is a
    ///   value copy, never aliased to the caller's receive buffer.
    static func apply(
        _ message: MITMScriptEngine.Message,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider?,
        resumeOn resumeQueue: DispatchQueue,
        completion: @escaping (Outcome) -> Void
    ) {
        scriptQueue.async {
            let outcome = apply(message, rules: rules, engineProvider: engineProvider)
            resumeQueue.async { completion(outcome) }
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
    /// matched the stream's request-target at head time. Earlier
    /// matching rules don't run on this stream and so can't trample
    /// the slot.
    final class FrameCursor {
        var state: JSValue?
        /// True once a script directive said "we're done with this
        /// stream" — subsequent frames bypass the script entirely.
        var bypass: Bool = false
        /// Memoized stream-script resolution for this stream. A stream's
        /// request-target and rule list are fixed for its lifetime, so
        /// ``applyFrame`` resolves the matching ``.streamScript`` on the
        /// first frame and reuses it — avoiding a per-frame URL parse and
        /// a per-frame walk of the rule list (each rule a regex match) on
        /// long-lived streams (SSE, gRPC, chunked APIs). Outer `nil` means
        /// "not resolved yet"; `.some(nil)` means "resolved: no rule
        /// matches"; `.some(.some)` carries the matched script.
        fileprivate var resolvedMatch: ScriptMatch??
        init() {}
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
            let pathAndQuery = MITMRequestURL.pathAndQuery(from: frameContext.url)
            resolved = lastMatchingStreamScriptSource(in: rules, pathAndQuery: pathAndQuery)
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
    /// pattern matches the request-target, or nil when none match.
    /// Walks rules back-to-front so the first hit is the winner.
    private static func lastMatchingScriptSource(
        in rules: [CompiledMITMRule],
        pathAndQuery: String?
    ) -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .script(let source, let sourceKey) = rule.operation,
               rule.matchesURL(pathAndQuery) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }

    /// Returns the source of the last ``.streamScript`` rule whose
    /// URL pattern matches the request-target, or nil when none match.
    private static func lastMatchingStreamScriptSource(
        in rules: [CompiledMITMRule],
        pathAndQuery: String?
    ) -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .streamScript(let source, let sourceKey) = rule.operation,
               rule.matchesURL(pathAndQuery) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }
}
