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
        operations: [CompiledMITMOperation]
    ) async -> HTTPMessage {
        var message = message
        var jsonOperations: [MITMJSONPatch.CompiledOperation] = []
        var replaceOperations: [MITMBodyReplace.CompiledOperation] = []
        for operation in operations {
            if case .bodyJSON(let jsonOperation) = operation { jsonOperations.append(jsonOperation) }
            if case .bodyReplace(let replaceOperation) = operation { replaceOperations.append(replaceOperation) }
        }
        if !jsonOperations.isEmpty {
            message.body = MITMJSONPatch.applyAll(jsonOperations, to: message.body)
        }
        if !replaceOperations.isEmpty {
            message.body = await MITMBodyReplace.applyAll(replaceOperations, to: message.body)
        }
        return message
    }

    static func apply(
        _ message: HTTPMessage,
        rules: [CompiledMITMRule]
    ) async -> Outcome {
        if Task.isCancelled { return .message(message) }
        let bodyRules = rules.filter { rule in
            switch rule.operation {
            case .script, .bodyReplace, .bodyJSON: return true
            case .rewrite, .headerAdd, .headerDelete, .headerReplace, .streamScript: return false
            }
        }
        let verdicts = await MITMGateVerdictTable.resolve(rules: bodyRules, url: message.url)
        let matched = bodyRules.indices.filter { verdicts.matches(at: $0) }.map { bodyRules[$0].operation }
        let edited = await applyNativeBodyEdits(message, operations: matched)
        if Task.isCancelled { return .message(edited) }
        var scriptSource: String?
        for operation in matched {
            if case .script(let source) = operation { scriptSource = source }
        }
        guard let scriptSource else { return .message(edited) }
        let outcome = await MITMScriptEngine.shared.applyAsync(edited, source: scriptSource)
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
            var isBypassed = false
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
        let isBypassed: Bool
    }

    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor
    ) -> StreamFrameResult {
        guard let match = cursor.resolvedMatch
        else { return StreamFrameResult(body: frame, isBypassed: false) }
        return MITMScriptEngine.shared.assumeIsolated { engine -> StreamFrameResult in
            let run: MITMScriptEngine.ScriptRun
            if let open = cursor.mutable.withLock({ $0.run }) {
                run = open
            } else if let opened = engine.openStreamRun(scope: frameContext.ruleSetID) {
                cursor.mutable.withLock { $0.run = opened }
                run = opened
            } else {
                cursor.mutable.withLock { $0.isBypassed = true }
                return StreamFrameResult(body: frame, isBypassed: true)
            }

            let outcome = engine.applyFrame(
                frame, source: match.source, frameContext: frameContext, run: run
            )
            switch outcome {
            case .modified(let body):
                return StreamFrameResult(body: body, isBypassed: false)
            case .done(let body):
                engine.closeStreamRun(run)
                cursor.mutable.withLock {
                    $0.run = nil
                    $0.isBypassed = true
                }
                return StreamFrameResult(body: body, isBypassed: true)
            case .exit:
                engine.closeStreamRun(run)
                cursor.mutable.withLock {
                    $0.run = nil
                    $0.isBypassed = true
                }
                return StreamFrameResult(body: frame, isBypassed: true)
            }
        }
    }

    static func applyFrame(
        _ frame: Data,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor
    ) async -> StreamFrameResult {
        if Task.isCancelled { return StreamFrameResult(body: frame, isBypassed: false) }
        return await JSCConcurrencyBridge.shared.run {
            applyFrame(
                frame,
                frameContext: frameContext,
                cursor: cursor
            )
        }
    }

    fileprivate struct ScriptMatch {
        let source: String
    }
}
