//
//  MITMHTTP2Rewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "MITMHTTP2Rewriter")

// MARK: Code quality violation
nonisolated final class MITMHTTP2Rewriter: @unchecked Sendable {

    let host: String
    /// Split by phase at init so per-frame paths don't re-pay the policy trie walk.
    private let requestRules: [CompiledMITMRule]
    private let responseRules: [CompiledMITMRule]
    private let cachedRuleSetID: UUID?
    /// Every subsequent request's `:authority` is rewritten to this value (last write wins).
    /// Single-upstream commitment is enforced by the session, not here.
    private var effectiveAuthority: String?

    /// Upstream to dial when a transparent rewrite resolves a replacement host; nil falls
    /// back to the original destination. Reflects the latest transparent rewrite only.
    private(set) var resolvedUpstream: (host: String, port: UInt16?)?
    let scriptEngineProvider: MITMScriptEngine.Provider
    /// Inbound records post-rewrite method/url per stream; outbound reads them for response-script ctx.
    let requestLog: MITMRequestLog

    init(
        host: String,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?,
        scriptEngineProvider: MITMScriptEngine.Provider,
        requestLog: MITMRequestLog
    ) {
        self.host = host
        let matchedSet = policy.set(for: host)
        let matchedRules = matchedSet?.rules ?? []
        self.requestRules = matchedRules.filter { $0.phase == .httpRequest }
        self.responseRules = matchedRules.filter { $0.phase == .httpResponse }
        self.cachedRuleSetID = matchedSet?.id
        self.effectiveAuthority = effectiveAuthority
        self.scriptEngineProvider = scriptEngineProvider
        self.requestLog = requestLog
    }

    // MARK: - Headers

    /// Everything the request head path needs from the gate regexes, resolved once at the
    /// async seam (the regex bridge) so the leg's synchronous pump never touches the engine.
    /// The request header rules re-gate on the `:path` as a transparent rewrite evolves it, so
    /// two verdict tables are carried: `pre` (original `:path`) and `post` (rewritten `:path`),
    /// with `rewriteIndex` marking the rule after which `post` applies.
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

    /// Derives the post-rewrite `:path` and the firing transparent-rewrite index from the
    /// pre-rewrite verdicts (first-match-wins).
    private func postRewrite(originalPath: String?, pre: MITMGateVerdictTable) -> (path: String?, index: Int?) {
        for (index, rule) in requestRules.enumerated() {
            guard case .rewrite(.transparent) = rule.operation else { continue }
            if case .transparent(let replacement)? = rule.resolvedRewriteAction(verdicts: pre, at: index) {
                return (replacement.requestTarget, index)
            }
        }
        return (originalPath, nil)
    }

    /// Resolves the request-head gates for a decoded head. Runs in async context (the caller's
    /// planner) so gate-cache misses suspend on the regex bridge instead of blocking the pump.
    func resolveRequestHeadGates(originalPath: String?) async -> RequestHeadGates {
        let preURL = originalPath.map { "https://\(host)\($0)" }
        let pre = await MITMGateVerdictTable.resolve(rules: requestRules, url: preURL)
        let (postPath, rewriteIndex) = postRewrite(originalPath: originalPath, pre: pre)
        let postURL = postPath.map { "https://\(host)\($0)" }
        let post = postURL == preURL ? pre : await MITMGateVerdictTable.resolve(rules: requestRules, url: postURL)
        let responseGates = await MITMGateVerdictTable.resolve(rules: responseRules, url: postURL)
        return RequestHeadGates(pre: pre, post: post, rewriteIndex: rewriteIndex, responseGates: responseGates)
    }

    /// Synchronous fast path of ``resolveRequestHeadGates(originalPath:)``: returns the gates
    /// when every needed verdict answers from a literal gate or the memo cache, else nil.
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
    ) -> [(name: String, value: String)] {
        // :authority rewrite runs first so header rules see the post-rewrite value.
        let withAuthority = applyAuthorityRewrite(headers)
        return applyRequestHeaderRules(withAuthority, gates: gates)
    }

    /// ``verdicts`` gates response-phase rules at the request URL; response headers carry no ``:path``.
    func transformResponseHeaders(
        _ headers: [(name: String, value: String)],
        verdicts: MITMGateVerdictTable
    ) -> [(name: String, value: String)] {
        applyResponseHeaderRules(headers, verdicts: verdicts)
    }

    static func requestPath(in headers: [(name: String, value: String)]) -> String? {
        // Case-insensitive: the HPACK decoder doesn't lowercase names, so a literal-encoded
        // `:Path` would otherwise bypass every request-phase rule.
        return HTTPHeader.firstValue(in: headers, named: ":path")
    }

    /// Synthesized response when the first matching request-phase rewrite rule is a
    /// 302 / reject sub-mode; nil for transparent or no match.
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

    /// HEADERS emitted immediately, scripts run per-frame.
    func hasStreamScriptRule(phase: MITMPhase, verdicts: MITMGateVerdictTable) -> Bool {
        MITMScriptTransform.hasStreamScriptRule(in: rules(phase: phase), verdicts: verdicts)
    }

    /// Check ``hasStreamScriptRule`` first — streaming takes precedence and never
    /// coexists with buffered mode.
    func hasBufferedBodyRule(phase: MITMPhase, verdicts: MITMGateVerdictTable) -> Bool {
        MITMScriptTransform.hasBufferedBodyRule(in: rules(phase: phase), verdicts: verdicts)
    }

    /// True when a rule of `phase` would read or rewrite the body (buffered or per-frame).
    func hasBodyAccessingRule(phase: MITMPhase, verdicts: MITMGateVerdictTable) -> Bool {
        MITMScriptTransform.hasBodyAccessingRule(in: rules(phase: phase), verdicts: verdicts)
    }

    func rules(phase: MITMPhase) -> [CompiledMITMRule] {
        phase == .httpRequest ? requestRules : responseRules
    }

    /// Matched rule set ID used as the script-store scope key.
    var ruleSetID: UUID? { cachedRuleSetID }

    /// Runs off the caller's executor; the caller re-establishes its confinement (lwIP queue) after
    /// the await. Caller must pass a decompressed body. `.synthesizedResponse` fires only on request
    /// phase — caller must then suppress upstream emission and answer on the inner leg.
    func applyScripts(
        _ message: HTTPMessage,
        phase: MITMPhase
    ) async -> MITMScriptTransform.Outcome {
        await MITMScriptTransform.apply(
            message,
            rules: rules(phase: phase),
            engineProvider: scriptEngineProvider
        )
    }

    /// Per-stream streaming-script cursor, resolved from the response-phase head gates.
    func makeResponseFrameCursor(verdicts: MITMGateVerdictTable) -> MITMScriptTransform.FrameCursor {
        MITMScriptTransform.makeFrameCursor(rules: responseRules, verdicts: verdicts)
    }

    // MARK: - Authority rewrite

    /// Rewrites `:authority`, inserting it before regular headers if absent (RFC 9113 §8.3).
    /// Skips trailers — pseudo-headers there are forbidden (§8.1) and strict receivers RST_STREAM.
    private func applyAuthorityRewrite(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        guard let authority = effectiveAuthority else { return headers }
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
    ) -> [(name: String, value: String)] {
        guard !requestRules.isEmpty else { return headers }

        var current = headers
        // First matching transparent rewrite wins; later rewrite rules are skipped.
        var rewroteRequest = false
        for (index, rule) in requestRules.enumerated() {
            // Request rules gate on the live `:path` (an earlier transparent rewrite may have
            // changed it) — `gates` carries the pre/post verdicts split at the rewrite index.
            let verdicts = gates.requestVerdicts(at: index)
            guard verdicts.matches(at: index) else { continue }
            switch rule.operation {
            case .rewrite:
                // 302/reject sub-modes were handled by the pre-check.
                // resolvedRewriteAction expands any `$1`-style target template against the match.
                guard !rewroteRequest,
                      let resolved = rule.resolvedRewriteAction(verdicts: verdicts, at: index),
                      case .transparent(let replacement) = resolved else { continue }
                rewroteRequest = true
                effectiveAuthority = replacement.authority
                resolvedUpstream = (host: replacement.host, port: replacement.port)
                var sawAuthority = false
                current = current.compactMap { entry -> (name: String, value: String)? in
                    // Drop a client-sent Host — the rewritten `:authority` supersedes it (RFC 9113 §8.3.1).
                    if ASCII.equalsIgnoringCase(entry.name, "host") { return nil }
                    // RFC 9113 §8.2.1: normalise mis-cased pseudo-headers on the way out.
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
                    // RFC 9113 §8.3.1: insert :authority before regular headers.
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
        return current
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
            // No rewrite in response phase (RFC: rewrite is request-only); scripts/body run elsewhere.
            case .rewrite, .script, .streamScript, .bodyReplace, .bodyJSON:
                continue
            }
        }
        return current
    }
}
