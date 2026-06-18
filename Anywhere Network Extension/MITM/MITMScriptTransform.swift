//
//  MITMScriptTransform.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import JavaScriptCore

/// At most one `.script` and one `.streamScript` fire per message (last match wins): chaining would
/// collide on rule-set-scoped store keys and the single-valued per-stream state slot.
enum MITMScriptTransform {

    /// Serial queue carrying every script invocation (off the lwIP queue, so a slow process(ctx)
    /// parks only its connection). Serial ordering keeps FrameCursor from concurrent touches.
    static let scriptQueue = DispatchQueue(
        label: AWCore.Identifier.mitmScriptQueue,
        qos: .userInitiated
    )

    /// Compiles every script rule on scriptQueue at (re)configuration time so cold-start cost doesn't
    /// land on the first intercepted flow. One async dispatch per scope so real calls can interleave.
    static func prewarm(scopedRules: [(scope: UUID, rules: [CompiledMITMRule])]) {
        for entry in scopedRules {
            // Dedupe by cache key: the same source on multiple rules compiles once.
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
                // An in-place script edit produces a new content-hash key; drop the stale compilation.
                engine.pruneCompiled(keeping: Set(scripts.map { $0.sourceKey }))
            }
        }
    }

    enum Outcome {
        case message(HTTPMessage)
        /// Request-phase `Anywhere.respond(...)` — drop the upstream request and send this to the client.
        case synthesizedResponse(MITMScriptEngine.SynthesizedResponse)
    }

    /// True when a `.script` rule would fire for the URL; check hasStreamScriptRule first — streaming takes priority.
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

    static func hasBodyJSONRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        rules.contains { rule in
            if case .bodyJSON = rule.operation { return rule.matchesURL(requestURL) }
            return false
        }
    }

    static func hasBodyReplaceRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        rules.contains { rule in
            if case .bodyReplace = rule.operation { return rule.matchesURL(requestURL) }
            return false
        }
    }

    /// True when any buffered body transform (needing the full decompressed body) would fire;
    /// `.streamScript` is deliberately excluded.
    static func hasBufferedBodyRule(in rules: [CompiledMITMRule], requestURL: String?) -> Bool {
        hasScriptRule(in: rules, requestURL: requestURL)
            || hasBodyReplaceRule(in: rules, requestURL: requestURL)
            || hasBodyJSONRule(in: rules, requestURL: requestURL)
    }

    /// True for media types meant for incremental delivery (SSE, NDJSON, etc.), where buffered
    /// `.script` is a poor fit. Matches the media type only — parameters don't affect the result.
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

    /// Applies all matching `.bodyJSON` then `.bodyReplace` rules; JSON runs first so the replacement
    /// regex sees the re-serialized JSON. Both run before any `.script` and survive `Anywhere.exit`.
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

    /// All matching `.bodyJSON` edits in rule order; unlike `.script`, every match is returned so edits compose.
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

    /// All matching `.bodyReplace` edits in rule order; every match composes over the running body text.
    private static func matchingBodyReplaceOps(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) -> [MITMBodyReplace.CompiledOp] {
        var ops: [MITMBodyReplace.CompiledOp] = []
        for rule in rules {
            if case .bodyReplace(let op) = rule.operation, rule.matchesURL(requestURL) {
                ops.append(op)
            }
        }
        return ops
    }

    /// Runs native body edits and the matching `.script` rule on scriptQueue. An awaiting
    /// process(ctx) suspends without holding the queue; `completion` fires exactly once on
    /// `resumeQueue`, and `message` is a value copy never aliased to the caller's buffer.
    static func apply(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider?,
        resumeOn resumeQueue: DispatchQueue,
        completion: @escaping (Outcome) -> Void
    ) {
        scriptQueue.async {
            let requestURL = message.url
            let edited = applyNativeBodyEdits(message, rules: rules)
            guard let match = lastMatchingScriptSource(in: rules, requestURL: requestURL),
                  let engineProvider
            else {
                resumeQueue.async { completion(.message(edited)) }
                return
            }
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

    /// Per-stream cursor threaded through each applyFrame call.
    final class FrameCursor {
        /// Script's persistent per-stream state; only ever touched on scriptQueue (deinit hops its release there).
        var state: JSValue?
        /// Set by a done/exit directive; subsequent frames bypass the script.
        var bypass: Bool = false
        /// Outer nil = unresolved, `.some(nil)` = no rule matches.
        fileprivate var resolvedMatch: ScriptMatch??
        init() {}

        deinit {
            // state's final release runs JSValueUnprotect, which mutates VM bookkeeping; off
            // scriptQueue that would race in-flight scripts and corrupt the VM heap.
            guard let state else { return }
            MITMScriptTransform.scriptQueue.async { withExtendedLifetime(state) {} }
        }
    }

    struct StreamFrameResult {
        let body: Data
        let bypass: Bool
    }

    /// Runs the last matching `.streamScript` rule against one frame. `Anywhere.done`/`exit`
    /// both set `cursor.bypass`; exit additionally reverts to the original frame data.
    static func applyFrame(
        _ frame: Data,
        rules: [CompiledMITMRule],
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) -> StreamFrameResult {
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

    /// Async counterpart: runs on scriptQueue, delivers on `resumeQueue` exactly once. Cursor
    /// mutation is safe because the caller keeps only one frame in flight at a time.
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

    fileprivate struct ScriptMatch {
        let source: String
        let sourceKey: Int
    }

    /// Returns the last matching ``.script`` rule (last-wins semantics), or nil.
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

    /// Returns the last matching ``.streamScript`` rule (last-wins semantics), or nil.
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
