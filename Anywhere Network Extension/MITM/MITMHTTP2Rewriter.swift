//
//  MITMHTTP2Rewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMHTTP2Rewriter")

/// HTTP/2 rule applier. Stateless — per-stream buffering lives on the connection.
final class MITMHTTP2Rewriter {

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

    func transformRequestHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32
    ) -> [(name: String, value: String)] {
        // :authority rewrite runs first so header rules see the post-rewrite value.
        let withAuthority = applyAuthorityRewrite(headers)
        return applyHeaderRules(withAuthority, phase: .httpRequest, requestURL: nil)
    }

    /// ``requestURL`` gates response-phase rules; response headers carry no ``:path``.
    func transformResponseHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32,
        requestURL: String?
    ) -> [(name: String, value: String)] {
        applyHeaderRules(headers, phase: .httpResponse, requestURL: requestURL)
    }

    static func requestPath(in headers: [(name: String, value: String)]) -> String? {
        // Case-insensitive: the HPACK decoder doesn't lowercase names, so a literal-encoded
        // `:Path` would otherwise bypass every request-phase rule.
        return firstHeaderValue(headers, name: ":path")
    }

    /// Synthesized response when the first matching request-phase rewrite rule is a
    /// 302 / reject sub-mode; nil for transparent or no match.
    func requestSynthResponse(requestURL: String?) -> MITMScriptEngine.SynthesizedResponse? {
        for rule in requestRules {
            guard case .rewrite(let action) = rule.operation else { continue }
            // A transparent rewrite never synthesizes; it's handled in the header path.
            // Defer to it only when it actually resolves — an unresolvable template is
            // skipped so a later matching rule can still synthesize.
            if case .transparent = action {
                if rule.resolvedRewriteAction(for: requestURL) != nil { return nil }
                continue
            }
            guard let resolved = rule.resolvedRewriteAction(for: requestURL) else { continue }
            return MITMRespondBuilder.response(for: resolved)
        }
        return nil
    }

    // MARK: - Script preflight + application

    /// HEADERS emitted immediately, scripts run per-frame.
    func hasStreamScriptRule(phase: MITMPhase, requestURL: String?) -> Bool {
        MITMScriptTransform.hasStreamScriptRule(
            in: rules(phase: phase),
            requestURL: requestURL
        )
    }

    /// Check ``hasStreamScriptRule`` first — streaming takes precedence and never
    /// coexists with buffered mode.
    func hasBufferedBodyRule(phase: MITMPhase, requestURL: String?) -> Bool {
        MITMScriptTransform.hasBufferedBodyRule(
            in: rules(phase: phase),
            requestURL: requestURL
        )
    }

    func rules(phase: MITMPhase) -> [CompiledMITMRule] {
        phase == .httpRequest ? requestRules : responseRules
    }

    /// Matched rule set ID used as the script-store scope key.
    var ruleSetID: UUID? { cachedRuleSetID }

    /// Runs off-queue, resuming on `resumeQueue`. Caller must pass a decompressed body.
    /// `.synthesizedResponse` fires only on request phase — caller must then suppress
    /// upstream emission and answer on the inner leg.
    func applyScripts(
        _ message: HTTPMessage,
        phase: MITMPhase,
        resumeOn resumeQueue: DispatchQueue,
        completion: @escaping (MITMScriptTransform.Outcome) -> Void
    ) {
        MITMScriptTransform.apply(
            message,
            rules: rules(phase: phase),
            engineProvider: scriptEngineProvider,
            resumeOn: resumeQueue,
            completion: completion
        )
    }

    // MARK: - Authority rewrite

    /// Rewrites `:authority`, inserting it before regular headers if absent (RFC 9113 §8.3).
    /// Skips trailers — pseudo-headers there are forbidden (§8.1) and strict receivers RST_STREAM.
    private func applyAuthorityRewrite(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        guard let authority = effectiveAuthority else { return headers }
        // Trailer check kept local so caller classification can't break the invariant.
        let hasMethod = headers.contains { $0.name.equalsIgnoringASCIICase(":method") }
        guard hasMethod else { return headers }
        var sawAuthority = false
        var result = headers.map { entry -> (name: String, value: String) in
            // RFC 9113 §8.2.1: normalise a peer's mis-cased `:Authority` on the way out.
            if entry.name.equalsIgnoringASCIICase(":authority") {
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

    private func applyHeaderRules(
        _ headers: [(name: String, value: String)],
        phase: MITMPhase,
        requestURL: String?
    ) -> [(name: String, value: String)] {
        let rulesForPhase = rules(phase: phase)
        guard !rulesForPhase.isEmpty else { return headers }

        var current = headers
        // First matching transparent rewrite wins; later rewrite rules are skipped.
        var rewroteRequest = false
        for rule in rulesForPhase {
            // Request rules gate on the live `:path` (an earlier rule may have
            // rewritten it); response rules on the originating request URL.
            let gateURL = (phase == .httpRequest)
                ? Self.requestPath(in: current).map { "https://\(host)\($0)" }
                : requestURL
            guard rule.matchesURL(gateURL) else { continue }
            switch rule.operation {
            case .rewrite:
                // Request-phase only; 302/reject sub-modes were handled by the pre-check.
                // resolvedRewriteAction expands any `$1`-style target template against the match.
                guard phase == .httpRequest, !rewroteRequest,
                      let resolved = rule.resolvedRewriteAction(for: gateURL),
                      case .transparent(let replacement) = resolved else { continue }
                rewroteRequest = true
                effectiveAuthority = replacement.authority
                resolvedUpstream = (host: replacement.host, port: replacement.port)
                var sawAuthority = false
                current = current.map { entry in
                    // RFC 9113 §8.2.1: normalise mis-cased pseudo-headers on the way out.
                    if entry.name.equalsIgnoringASCIICase(":path") {
                        return (name: ":path", value: replacement.requestTarget)
                    }
                    if entry.name.equalsIgnoringASCIICase(":authority") {
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
                current.removeAll { $0.name.equalsIgnoringASCIICase(nameLower) }
            case .headerReplace(let name, let value):
                guard !name.hasPrefix(":") else { continue }
                current = current.map { entry in
                    entry.name.equalsIgnoringASCIICase(name) ? (name: name, value: value) : entry
                }
            case .script, .streamScript, .bodyReplace, .bodyJSON:
                continue
            }
        }
        return current
    }
}
