//
//  MITMHTTP2Rewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMHTTP2Rewriter")

nonisolated final class MITMHTTP2Rewriter: Sendable {

    let host: String
    
    private let requestRules: [CompiledMITMRule]
    private let responseRules: [CompiledMITMRule]
    private let cachedRuleSetID: UUID?
    
    private struct RewriteState {
        var effectiveAuthority: String?
    }
    private let rewriteState: Mutex<RewriteState>

    let requestLog: MITMRequestLog

    init(
        host: String,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?,
        requestLog: MITMRequestLog
    ) {
        self.host = host
        let matchedSet = policy.set(for: host)
        let matchedRules = matchedSet?.rules ?? []
        self.requestRules = matchedRules.filter { $0.phase == .httpRequest }
        self.responseRules = matchedRules.filter { $0.phase == .httpResponse }
        self.cachedRuleSetID = matchedSet?.id
        self.rewriteState = Mutex(RewriteState(effectiveAuthority: effectiveAuthority))
        self.requestLog = requestLog
    }

    // MARK: - Headers
    
    nonisolated struct RequestHeadGates: Sendable {
        let pre: MITMGateVerdictTable
        let post: MITMGateVerdictTable
        /// Index of the transparent-rewrite rule that fired; rules past it gate on `post`.
        /// nil when no transparent rewrite fires (every rule gates on `pre`).
        let rewriteIndex: Int?
        /// Response-phase rules @ the post-rewrite gating URL — the Accept-Encoding clamp gate.
        let responseGates: MITMGateVerdictTable

        func requestVerdicts(at index: Int) -> MITMGateVerdictTable {
            if let rewriteIndex, index > rewriteIndex { return post }
            return pre
        }
    }
    
    private func postRewrite(originalPath: String?, pre: MITMGateVerdictTable) -> (path: String?, index: Int?) {
        for (index, rule) in requestRules.enumerated() {
            guard case .rewrite(.transparent) = rule.operation else { continue }
            if case .transparent(let replacement)? = rule.resolvedRewriteAction(verdicts: pre, at: index) {
                return (replacement.requestTarget, index)
            }
        }
        return (originalPath, nil)
    }
    
    func resolveRequestHeadGates(originalPath: String?) async -> RequestHeadGates {
        let preURL = originalPath.map { "https://\(host)\($0)" }
        let pre = await MITMGateVerdictTable.resolve(rules: requestRules, url: preURL)
        let (postPath, rewriteIndex) = postRewrite(originalPath: originalPath, pre: pre)
        let postURL = postPath.map { "https://\(host)\($0)" }
        let post = postURL == preURL ? pre : await MITMGateVerdictTable.resolve(rules: requestRules, url: postURL)
        let responseGates = await MITMGateVerdictTable.resolve(rules: responseRules, url: postURL)
        return RequestHeadGates(pre: pre, post: post, rewriteIndex: rewriteIndex, responseGates: responseGates)
    }
    
    func peekRequestHeadGates(originalPath: String?) -> RequestHeadGates? {
        let preURL = originalPath.map { "https://\(host)\($0)" }
        guard let pre = MITMGateVerdictTable.peek(rules: requestRules, url: preURL) else { return nil }
        let (postPath, rewriteIndex) = postRewrite(originalPath: originalPath, pre: pre)
        let postURL = postPath.map { "https://\(host)\($0)" }
        let post: MITMGateVerdictTable
        if postURL == preURL {
            post = pre
        } else {
            guard let resolved = MITMGateVerdictTable.peek(rules: requestRules, url: postURL) else { return nil }
            post = resolved
        }
        guard let responseGates = MITMGateVerdictTable.peek(rules: responseRules, url: postURL) else { return nil }
        return RequestHeadGates(pre: pre, post: post, rewriteIndex: rewriteIndex, responseGates: responseGates)
    }
    
    func transformRequestHeaders(
        _ headers: [(name: String, value: String)],
        gates: RequestHeadGates
    ) -> (headers: [(name: String, value: String)], resolvedUpstream: (host: String, port: UInt16?)?) {
        // :authority rewrite runs first so header rules see the post-rewrite value.
        let withAuthority = applyAuthorityRewrite(headers)
        return applyRequestHeaderRules(withAuthority, gates: gates)
    }
    
    func transformResponseHeaders(
        _ headers: [(name: String, value: String)],
        verdicts: MITMGateVerdictTable
    ) -> [(name: String, value: String)] {
        applyResponseHeaderRules(headers, verdicts: verdicts)
    }

    static func requestPath(in headers: [(name: String, value: String)]) -> String? {
        return HTTPHeader.firstValue(in: headers, named: ":path")
    }
    
    func requestSynthResponse(gates: RequestHeadGates) -> MITMScriptEngine.SynthesizedResponse? {
        for (index, rule) in requestRules.enumerated() {
            guard case .rewrite(let action) = rule.operation else { continue }
            // A transparent rewrite never synthesizes; it's handled in the header path.
            // Defer to it only when it actually resolves — an unresolvable template is
            // skipped so a later matching rule can still synthesize.
            if case .transparent = action {
                if rule.resolvedRewriteAction(verdicts: gates.pre, at: index) != nil { return nil }
                continue
            }
            guard let resolved = rule.resolvedRewriteAction(verdicts: gates.pre, at: index) else { continue }
            return MITMRespondBuilder.response(for: resolved)
        }
        return nil
    }

    // MARK: - Script preflight + application
    
    func hasStreamScriptRule(phase: MITMPhase, verdicts: MITMGateVerdictTable) -> Bool {
        MITMScriptTransform.hasStreamScriptRule(in: rules(phase: phase), verdicts: verdicts)
    }
    
    func hasBufferedBodyRule(phase: MITMPhase, verdicts: MITMGateVerdictTable) -> Bool {
        MITMScriptTransform.hasBufferedBodyRule(in: rules(phase: phase), verdicts: verdicts)
    }
    
    func hasBodyAccessingRule(phase: MITMPhase, verdicts: MITMGateVerdictTable) -> Bool {
        MITMScriptTransform.hasBodyAccessingRule(in: rules(phase: phase), verdicts: verdicts)
    }

    func rules(phase: MITMPhase) -> [CompiledMITMRule] {
        phase == .httpRequest ? requestRules : responseRules
    }
    
    var ruleSetID: UUID? { cachedRuleSetID }
    
    func applyScripts(
        _ message: HTTPMessage,
        phase: MITMPhase
    ) async -> MITMScriptTransform.Outcome {
        await MITMScriptTransform.apply(message, rules: rules(phase: phase))
    }
    
    func makeResponseFrameCursor(verdicts: MITMGateVerdictTable) -> MITMScriptTransform.FrameCursor {
        MITMScriptTransform.makeFrameCursor(rules: responseRules, verdicts: verdicts)
    }

    // MARK: - Authority rewrite
    
    private func applyAuthorityRewrite(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        guard let authority = rewriteState.withLock({ $0.effectiveAuthority }) else { return headers }
        // Trailer check kept local so caller classification can't break the invariant.
        let hasMethod = headers.contains { ASCII.equalsIgnoringCase($0.name, ":method") }
        guard hasMethod else { return headers }
        var sawAuthority = false
        var result = headers.compactMap { entry -> (name: String, value: String)? in
            // Drop a client-sent Host — the rewritten `:authority` supersedes it (RFC 9113 §8.3.1).
            if ASCII.equalsIgnoringCase(entry.name, "host") { return nil }
            // RFC 9113 §8.2.1: normalise a peer's mis-cased `:Authority` on the way out.
            if ASCII.equalsIgnoringCase(entry.name, ":authority") {
                sawAuthority = true
                return (name: ":authority", value: authority)
            }
            return entry
        }
        if !sawAuthority {
            result.insert((name: ":authority", value: authority), at: 0)
        }
        return result
    }

    // MARK: - Header rule application

    private func applyRequestHeaderRules(
        _ headers: [(name: String, value: String)],
        gates: RequestHeadGates
    ) -> (headers: [(name: String, value: String)], resolvedUpstream: (host: String, port: UInt16?)?) {
        guard !requestRules.isEmpty else { return (headers, nil) }

        var current = headers
        var resolvedUpstream: (host: String, port: UInt16?)?
        // First matching transparent rewrite wins; later rewrite rules are skipped.
        var rewroteRequest = false
        for (index, rule) in requestRules.enumerated() {
            // Request rules gate on the live `:path` (an earlier transparent rewrite may have
            // changed it) — `gates` carries the pre/post verdicts split at the rewrite index.
            let verdicts = gates.requestVerdicts(at: index)
            guard verdicts.matches(at: index) else { continue }
            switch rule.operation {
            case .rewrite:
                guard !rewroteRequest,
                      let resolved = rule.resolvedRewriteAction(verdicts: verdicts, at: index),
                      case .transparent(let replacement) = resolved else { continue }
                rewroteRequest = true
                rewriteState.withLock { $0.effectiveAuthority = replacement.authority }
                resolvedUpstream = (host: replacement.host, port: replacement.port)
                var sawAuthority = false
                current = current.compactMap { entry -> (name: String, value: String)? in
                    if ASCII.equalsIgnoringCase(entry.name, "host") { return nil }
                    if ASCII.equalsIgnoringCase(entry.name, ":path") {
                        return (name: ":path", value: replacement.requestTarget)
                    }
                    if ASCII.equalsIgnoringCase(entry.name, ":authority") {
                        sawAuthority = true
                        return (name: ":authority", value: replacement.authority)
                    }
                    return entry
                }
                if !sawAuthority {
                    current.insert((name: ":authority", value: replacement.authority), at: 0)
                }
            case .headerAdd(let name, let value):
                // No pseudo-header edits: adding duplicates/smuggles one; removing a
                // required one trips PROTOCOL_ERROR on strict peers (RFC 9113 §8.3).
                guard !name.hasPrefix(":") else { continue }
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                guard !nameLower.hasPrefix(":") else { continue }
                current.removeAll { ASCII.equalsIgnoringCase($0.name, nameLower) }
            case .headerReplace(let name, let value):
                guard !name.hasPrefix(":") else { continue }
                current = current.map { entry in
                    ASCII.equalsIgnoringCase(entry.name, name) ? (name: name, value: value) : entry
                }
            case .script, .streamScript, .bodyReplace, .bodyJSON:
                continue
            }
        }
        return (current, resolvedUpstream)
    }

    private func applyResponseHeaderRules(
        _ headers: [(name: String, value: String)],
        verdicts: MITMGateVerdictTable
    ) -> [(name: String, value: String)] {
        guard !responseRules.isEmpty else { return headers }

        var current = headers
        for (index, rule) in responseRules.enumerated() {
            guard verdicts.matches(at: index) else { continue }
            switch rule.operation {
            case .headerAdd(let name, let value):
                guard !name.hasPrefix(":") else { continue }
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                guard !nameLower.hasPrefix(":") else { continue }
                current.removeAll { ASCII.equalsIgnoringCase($0.name, nameLower) }
            case .headerReplace(let name, let value):
                guard !name.hasPrefix(":") else { continue }
                current = current.map { entry in
                    ASCII.equalsIgnoringCase(entry.name, name) ? (name: name, value: value) : entry
                }
            case .rewrite, .script, .streamScript, .bodyReplace, .bodyJSON:
                continue
            }
        }
        return current
    }
}
