//
//  MITMScriptTransform.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import JavaScriptCore

nonisolated enum MITMScriptTransform {

    /// Compiles every script rule on the JSC queue at (re)configuration time so cold-start cost doesn't
    /// land on the first intercepted flow. One async dispatch per scope so real calls can interleave.
    static func prewarm(scopedRules: [(scope: UUID, rules: [CompiledMITMRule])]) {
        // scope → its deduped script/streamScript sources (the same source on multiple rules compiles once).
        var scriptsByScope: [UUID: [(source: String, sourceKey: Int)]] = [:]
        for entry in scopedRules {
            var seen = Set<Int>()
            let scripts: [(source: String, sourceKey: Int)] = entry.rules.compactMap { rule in
                switch rule.operation {
                case .script(let source, let sourceKey), .streamScript(let source, let sourceKey):
                    return seen.insert(sourceKey).inserted ? (source: source, sourceKey: sourceKey) : nil
                case .rewrite, .headerAdd, .headerDelete, .headerReplace, .bodyReplace, .bodyJSON:
                    return nil
                }
            }
            if !scripts.isEmpty { scriptsByScope[entry.scope] = scripts }
        }
        // Reset every surviving engine first.
        let keepByScope = scriptsByScope.mapValues { Set($0.map { $0.sourceKey }) }
        MITMScriptEngine.resetCachesOnReload(keepByScope: keepByScope)
        // Precompile per scope.
        for (scope, scripts) in scriptsByScope {
            JSCConcurrencyBridge.shared.enqueue {
                // The enqueue body runs on the JSC queue = the engine's actor executor.
                let engine = MITMScriptEngine.sharedEngine(forScope: scope)
                for script in scripts {
                    engine.assumeIsolated { $0.precompile(source: script.source, sourceKey: script.sourceKey) }
                }
            }
        }
    }

    enum Outcome {
        case message(HTTPMessage)
        /// Request-phase `Anywhere.respond(...)` — drop the upstream request and send this to the client.
        case synthesizedResponse(MITMScriptEngine.SynthesizedResponse)
    }

    /// True when a `.script` rule would fire per the head-time verdicts; check
    /// hasStreamScriptRule first — streaming takes priority.
    static func hasScriptRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        for (index, rule) in rules.enumerated() {
            if case .script = rule.operation, verdicts.matches(at: index) { return true }
        }
        return false
    }

    static func hasStreamScriptRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        for (index, rule) in rules.enumerated() {
            if case .streamScript = rule.operation, verdicts.matches(at: index) { return true }
        }
        return false
    }

    static func hasBodyJSONRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        for (index, rule) in rules.enumerated() {
            if case .bodyJSON = rule.operation, verdicts.matches(at: index) { return true }
        }
        return false
    }

    static func hasBodyReplaceRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        for (index, rule) in rules.enumerated() {
            if case .bodyReplace = rule.operation, verdicts.matches(at: index) { return true }
        }
        return false
    }

    /// True when any buffered body transform (needing the full decompressed body) would fire;
    /// `.streamScript` is deliberately excluded.
    static func hasBufferedBodyRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        hasScriptRule(in: rules, verdicts: verdicts)
            || hasBodyReplaceRule(in: rules, verdicts: verdicts)
            || hasBodyJSONRule(in: rules, verdicts: verdicts)
    }

    /// True when any rule would read or rewrite the body — buffered (`hasBufferedBodyRule`) or
    /// per-frame (`.streamScript`).
    static func hasBodyAccessingRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        hasBufferedBodyRule(in: rules, verdicts: verdicts)
            || hasStreamScriptRule(in: rules, verdicts: verdicts)
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
    /// `.bodyReplace` awaits the ReDoS-bounded substitution; neither op touches JSC, so this runs on
    /// the caller's executor rather than `scriptQueue`.
    private static func applyNativeBodyEdits(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule]
    ) async -> HTTPMessage {
        let requestURL = message.url
        var message = message
        let jsonOperations = await matchingBodyJSONOperations(in: rules, requestURL: requestURL)
        if !jsonOperations.isEmpty {
            message.body = MITMJSONPatch.applyAll(jsonOperations, to: message.body)
        }
        let replaceOperations = await matchingBodyReplaceOperations(in: rules, requestURL: requestURL)
        if !replaceOperations.isEmpty {
            message.body = await MITMBodyReplace.applyAll(replaceOperations, to: message.body)
        }
        return message
    }

    /// All matching `.bodyJSON` edits in rule order; unlike `.script`, every match is returned so edits compose.
    private static func matchingBodyJSONOperations(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) async -> [MITMJSONPatch.CompiledOperation] {
        var operations: [MITMJSONPatch.CompiledOperation] = []
        for rule in rules {
            if case .bodyJSON(let operation) = rule.operation, await rule.matchesURL(requestURL) {
                operations.append(operation)
            }
        }
        return operations
    }

    /// All matching `.bodyReplace` edits in rule order; every match composes over the running body text.
    private static func matchingBodyReplaceOperations(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) async -> [MITMBodyReplace.CompiledOperation] {
        var operations: [MITMBodyReplace.CompiledOperation] = []
        for rule in rules {
            if case .bodyReplace(let operation) = rule.operation, await rule.matchesURL(requestURL) {
                operations.append(operation)
            }
        }
        return operations
    }

    /// Runs native body edits and the matching `.script` rule. The `.script` engine hop confines the
    /// JSC work to `scriptQueue` itself; an awaiting process(ctx) suspends without holding the queue.
    /// `message` is a value copy never aliased to the caller's buffer. The caller awaits on its own
    /// executor and re-establishes its confinement after the await.
    static func apply(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider?
    ) async -> Outcome {
        let requestURL = message.url
        let edited = await applyNativeBodyEdits(message, rules: rules)
        guard let match = await lastMatchingScriptSource(in: rules, requestURL: requestURL),
              let engineProvider
        else {
            return .message(edited)
        }
        let outcome = await engineProvider.get().applyAsync(
            edited,
            source: match.source,
            sourceKey: match.sourceKey
        )
        switch outcome {
        case .modified(let updated):  return .message(updated)
        case .done(let updated):      return .message(updated)
        case .exit:                   return .message(edited)
        case .respond(let response):  return .synthesizedResponse(response)
        }
    }

    /// Per-stream cursor threaded through each applyFrame call. Created via
    /// ``makeFrameCursor(rules:verdicts:)`` at head time, when the gate verdicts are in scope —
    /// the per-frame path never consults a gate.
    final class FrameCursor {
        /// Script's persistent per-stream state; only ever touched on scriptQueue (deinit hops its release there).
        var state: JSValue?
        /// Set by a done/exit directive; subsequent frames bypass the script.
        var bypass: Bool = false
        /// The last matching `.streamScript` rule, resolved at creation; nil = no rule matches.
        fileprivate let resolvedMatch: ScriptMatch?

        fileprivate init(resolvedMatch: ScriptMatch?) {
            self.resolvedMatch = resolvedMatch
        }

        deinit {
            // state's final release runs JSValueUnprotect, which mutates VM bookkeeping; off
            // scriptQueue that would race in-flight scripts and corrupt the VM heap.
            guard let state else { return }
            JSCConcurrencyBridge.shared.enqueue { withExtendedLifetime(state) {} }
        }
    }

    /// Creates the per-stream cursor, resolving the last matching `.streamScript` rule
    /// (last-wins semantics) from the head-time verdicts.
    static func makeFrameCursor(
        rules: [CompiledMITMRule],
        verdicts: MITMGateVerdictTable
    ) -> FrameCursor {
        for (index, rule) in zip(rules.indices, rules).reversed() {
            if case .streamScript(let source, let sourceKey) = rule.operation,
               verdicts.matches(at: index) {
                return FrameCursor(resolvedMatch: ScriptMatch(source: source, sourceKey: sourceKey))
            }
        }
        return FrameCursor(resolvedMatch: nil)
    }

    struct StreamFrameResult {
        let body: Data
        let bypass: Bool
    }

    /// Runs the last matching `.streamScript` rule against one frame. `Anywhere.done`/`exit`
    /// both set `cursor.bypass`; exit additionally reverts to the original frame data.
    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) -> StreamFrameResult {
        guard let match = cursor.resolvedMatch, let engineProvider
        else { return StreamFrameResult(body: frame, bypass: false) }
        // Runs inside `JSCConcurrencyBridge.shared.run` (the async counterpart below) — on the
        // engine's JSC executor — so enter its isolation synchronously.
        let outcome = engineProvider.get().assumeIsolated {
            $0.applyFrame(frame, source: match.source, sourceKey: match.sourceKey,
                          frameContext: frameContext, state: cursor.state)
        }
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

    /// Async counterpart: hops to the JSC bridge (the JSC home queue), runs the sync span, and
    /// resumes the caller exactly once. Cursor mutation is safe because the caller keeps only one
    /// frame in flight at a time.
    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) async -> StreamFrameResult {
        await JSCConcurrencyBridge.shared.run {
            applyFrame(
                frame,
                frameContext: frameContext,
                cursor: cursor,
                engineProvider: engineProvider
            )
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
    ) async -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .script(let source, let sourceKey) = rule.operation,
               await rule.matchesURL(requestURL) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }
}
