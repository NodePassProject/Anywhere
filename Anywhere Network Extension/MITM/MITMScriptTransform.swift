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
    static func rulesDidReload(scopedRules: [(scope: UUID, rules: [CompiledMITMRule])]) {
        let hasScriptRule = scopedRules.contains { entry in
            entry.rules.contains { rule in
                switch rule.operation {
                case .script, .streamScript: return true
                case .rewrite, .headerAdd, .headerDelete, .headerReplace, .bodyReplace, .bodyJSON: return false
                }
            }
        }
        guard hasScriptRule else { return }
        MITMScriptEngine.warmVirtualMachine()
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
        rules: [CompiledMITMRule]
    ) async -> Outcome {
        if Task.isCancelled { return .message(message) }
        let requestURL = message.url
        let edited = await applyNativeBodyEdits(message, rules: rules)
        if Task.isCancelled { return .message(edited) }
        guard let match = await lastMatchingScriptSource(in: rules, requestURL: requestURL) else {
            return .message(edited)
        }
        let outcome = await MITMScriptEngine.shared.applyAsync(edited, source: match.source)
        switch outcome {
        case .modified(let updated):  return .message(updated)
        case .done(let updated):      return .message(updated)
        case .exit:                   return .message(edited)
        case .respond(let response):  return .synthesizedResponse(response)
        }
    }
    
    final class FrameCursor: Sendable {
        struct Mutable {
            var run: MITMScriptEngine.ScriptRun?
            var bypass = false
        }
        let mutable = Mutex(Mutable())

        fileprivate let resolvedMatch: ScriptMatch?

        fileprivate init(resolvedMatch: ScriptMatch?) {
            self.resolvedMatch = resolvedMatch
        }

        deinit {
            guard let run = mutable.withLock({ $0.run }) else { return }
            JSCConcurrencyBridge.shared.enqueue {
                MITMScriptEngine.shared.assumeIsolated { $0.closeStreamRun(run) }
            }
        }
    }

    static func makeFrameCursor(
        rules: [CompiledMITMRule],
        verdicts: MITMGateVerdictTable
    ) -> FrameCursor {
        for (index, rule) in zip(rules.indices, rules).reversed() {
            if case .streamScript(let source) = rule.operation,
               verdicts.matches(at: index) {
                return FrameCursor(resolvedMatch: ScriptMatch(source: source))
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
        cursor: FrameCursor
    ) -> StreamFrameResult {
        guard let match = cursor.resolvedMatch
        else { return StreamFrameResult(body: frame, bypass: false) }
        return MITMScriptEngine.shared.assumeIsolated { engine -> StreamFrameResult in
            let run: MITMScriptEngine.ScriptRun
            if let open = cursor.mutable.withLock({ $0.run }) {
                run = open
            } else if let opened = engine.openStreamRun(scope: frameContext.ruleSetID) {
                cursor.mutable.withLock { $0.run = opened }
                run = opened
            } else {
                cursor.mutable.withLock { $0.bypass = true }
                return StreamFrameResult(body: frame, bypass: true)
            }

            let outcome = engine.applyFrame(
                frame, source: match.source, frameContext: frameContext, run: run
            )
            switch outcome {
            case .modified(let body):
                return StreamFrameResult(body: body, bypass: false)
            case .done(let body):
                engine.closeStreamRun(run)
                cursor.mutable.withLock { $0.run = nil; $0.bypass = true }
                return StreamFrameResult(body: body, bypass: true)
            case .exit:
                engine.closeStreamRun(run)
                cursor.mutable.withLock { $0.run = nil; $0.bypass = true }
                return StreamFrameResult(body: frame, bypass: true)
            }
        }
    }

    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor
    ) async -> StreamFrameResult {
        if Task.isCancelled { return StreamFrameResult(body: frame, bypass: false) }
        return await JSCConcurrencyBridge.shared.run {
            applyFrame(
                frame,
                frameContext: frameContext,
                cursor: cursor
            )
        }
    }

    // MARK: - Last-match selection

    fileprivate struct ScriptMatch {
        let source: String
    }

    private static func lastMatchingScriptSource(
        in rules: [CompiledMITMRule],
        requestURL: String?
    ) async -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .script(let source) = rule.operation,
               await rule.matchesURL(requestURL) {
                return ScriptMatch(source: source)
            }
        }
        return nil
    }
}
