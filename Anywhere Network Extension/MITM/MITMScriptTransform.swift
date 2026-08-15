//
//  MITMScriptTransform.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import JavaScriptCore
import Synchronization

nonisolated enum MITMScriptTransform {
    static func prewarm(scopedRules: [(scope: UUID, rules: [CompiledMITMRule])]) {
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
        let keepByScope = scriptsByScope.mapValues { Set($0.map { $0.sourceKey }) }
        MITMScriptEngine.resetCachesOnReload(keepByScope: keepByScope)
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
        case synthesizedResponse(MITMScriptEngine.SynthesizedResponse)
    }

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

    static func hasBufferedBodyRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        hasScriptRule(in: rules, verdicts: verdicts)
            || hasBodyReplaceRule(in: rules, verdicts: verdicts)
            || hasBodyJSONRule(in: rules, verdicts: verdicts)
    }

    static func hasBodyAccessingRule(in rules: [CompiledMITMRule], verdicts: MITMGateVerdictTable) -> Bool {
        hasBufferedBodyRule(in: rules, verdicts: verdicts)
            || hasStreamScriptRule(in: rules, verdicts: verdicts)
    }

    static func isStreamingMediaType(_ contentType: String?) -> Bool {
        guard let raw = contentType else { return false }
        let mediaType = raw
            .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            ?? ""
        switch mediaType {
        case "text/event-stream",
             "multipart/x-mixed-replace",
             "application/x-ndjson",
             "application/jsonl",
             "application/stream+json",
             "application/json-seq":
            return true
        default:
            return false
        }
    }

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

    static func apply(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider?
    ) async -> Outcome {
        if Task.isCancelled { return .message(message) }
        let requestURL = message.url
        let edited = await applyNativeBodyEdits(message, rules: rules)
        if Task.isCancelled { return .message(edited) }
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
    
    final class FrameCursor: Sendable {
        struct Mutable {
            var state: JSValue?
            var bypass = false
        }
        let mutable = Mutex(Mutable())

        fileprivate let resolvedMatch: ScriptMatch?

        fileprivate init(resolvedMatch: ScriptMatch?) {
            self.resolvedMatch = resolvedMatch
        }

        deinit {
            guard let state = mutable.withLock({ $0.state }) else { return }
            JSCConcurrencyBridge.shared.enqueue { withExtendedLifetime(state) {} }
        }
    }

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

    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) -> StreamFrameResult {
        guard let match = cursor.resolvedMatch, let engineProvider
        else { return StreamFrameResult(body: frame, bypass: false) }
        let state = cursor.mutable.withLock { $0.state }
        let outcome = engineProvider.get().assumeIsolated {
            $0.applyFrame(frame, source: match.source, sourceKey: match.sourceKey,
                          frameContext: frameContext, state: state)
        }
        switch outcome {
        case .modified(let body, let state):
            cursor.mutable.withLock { $0.state = state }
            return StreamFrameResult(body: body, bypass: false)
        case .done(let body):
            cursor.mutable.withLock { $0.bypass = true }
            return StreamFrameResult(body: body, bypass: true)
        case .exit:
            cursor.mutable.withLock { $0.bypass = true }
            return StreamFrameResult(body: frame, bypass: true)
        }
    }

    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) async -> StreamFrameResult {
        if Task.isCancelled { return StreamFrameResult(body: frame, bypass: false) }
        return await JSCConcurrencyBridge.shared.run {
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
