//
//  MITMHTTP2Rewriter.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// HTTP/2 analog of ``MITMHTTP1Stream``. Where the HTTP/1.1 path
/// operates on raw bytes, this rewriter operates on (name, value)
/// arrays after HPACK decode and on whole-body buffers handed in by
/// ``MITMHTTP2Connection``.
///
/// Stateless: per-stream buffering lives on the connection. The
/// rewriter applies the compiled rule list for the host.
final class MITMHTTP2Rewriter {

    let host: String
    let policy: MITMRewritePolicy
    /// When set, every request's `:authority` pseudo-header is rewritten to
    /// this value. Driven by the rule set's ``rewriteTarget``; nil means
    /// "leave :authority alone".
    private let effectiveAuthority: String?
    /// Lazy JS runtime, shared with the HTTP/1 streams of the same
    /// session. Touched only when a script rule fires.
    let scriptEngineProvider: MITMScriptEngine.Provider
    /// Cross-direction request bookkeeping. The inbound HTTP/2
    /// connection records the (post-rewrite) method/url per stream so
    /// the outbound connection can populate `ctx.method` / `ctx.url`
    /// on response scripts.
    let requestLog: MITMRequestLog

    init(
        host: String,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?,
        scriptEngineProvider: MITMScriptEngine.Provider,
        requestLog: MITMRequestLog
    ) {
        self.host = host
        self.policy = policy
        self.effectiveAuthority = effectiveAuthority
        self.scriptEngineProvider = scriptEngineProvider
        self.requestLog = requestLog
    }

    // MARK: - Headers

    func transformRequestHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32
    ) -> [(name: String, value: String)] {
        // :authority rewrite runs first so configured headerReplace rules
        // see the canonical post-redirect value and can override it.
        let withAuthority = applyAuthorityRewrite(headers)
        return applyHeaderRules(withAuthority, phase: .httpRequest)
    }

    func transformResponseHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32
    ) -> [(name: String, value: String)] {
        applyHeaderRules(headers, phase: .httpResponse)
    }

    // MARK: - Script preflight + application

    /// Whether any buffered script rule applies for this host + phase
    /// with the in-flight message's ``contentType``. Callers should
    /// check ``hasStreamScriptRule`` first — streaming rules take
    /// precedence and never coexist with buffered mode on the same
    /// stream.
    func hasScriptRule(phase: MITMPhase, contentType: String?) -> Bool {
        MITMScriptTransform.hasScriptRule(
            in: policy.rules(for: host, phase: phase),
            contentType: contentType
        )
    }

    /// Whether any streaming-script rule applies. Streaming rules tell
    /// the connection to emit HEADERS immediately and run scripts
    /// per-frame instead of buffering the full body.
    func hasStreamScriptRule(phase: MITMPhase, contentType: String?) -> Bool {
        MITMScriptTransform.hasStreamScriptRule(
            in: policy.rules(for: host, phase: phase),
            contentType: contentType
        )
    }

    /// Compiled rule list for the host/phase, exposed so the connection
    /// can pass it into ``MITMScriptTransform.applyFrame`` without
    /// re-resolving the policy on every DATA frame.
    func rules(phase: MITMPhase) -> [CompiledMITMRule] {
        policy.rules(for: host, phase: phase)
    }

    /// The matched rule set's ID, used as the script-store scope key.
    /// Stable for the rewriter's lifetime since ``host`` is fixed at
    /// init time.
    var ruleSetID: UUID? {
        policy.set(for: host)?.id
    }

    /// Applies every script rule for the given phase whose Content-Type
    /// filter accepts the message's `content-type` header. The caller
    /// is responsible for decompressing the body before passing it in;
    /// the returned message has the (possibly modified) body in
    /// identity form.
    func applyScripts(
        _ message: MITMScriptEngine.Message,
        phase: MITMPhase
    ) -> MITMScriptEngine.Message {
        MITMScriptTransform.apply(
            message,
            rules: policy.rules(for: host, phase: phase),
            engineProvider: scriptEngineProvider
        )
    }

    // MARK: - Authority rewrite

    /// HTTP/2 analog of HTTP/1.1's Host rewrite. The `:authority`
    /// pseudo-header is replaced; if absent, one is inserted before regular
    /// headers as required by RFC 9113 section 8.3.
    private func applyAuthorityRewrite(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        guard let authority = effectiveAuthority else { return headers }
        var sawAuthority = false
        var result = headers.map { entry -> (name: String, value: String) in
            if entry.name == ":authority" {
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
        phase: MITMPhase
    ) -> [(name: String, value: String)] {
        let rules = policy.rules(for: host, phase: phase)
        guard !rules.isEmpty else { return headers }

        var current = headers
        for rule in rules {
            switch rule.operation {
            case .urlReplace(let regex, let replacement):
                guard phase == .httpRequest else { continue }
                current = current.map { entry in
                    guard entry.name == ":path" else { return entry }
                    let range = NSRange(entry.value.startIndex..., in: entry.value)
                    guard regex.firstMatch(in: entry.value, options: [], range: range) != nil else {
                        return entry
                    }
                    let rewritten = regex.stringByReplacingMatches(
                        in: entry.value,
                        options: [],
                        range: range,
                        withTemplate: replacement
                    )
                    return (name: entry.name, value: rewritten)
                }
            case .headerAdd(let name, let value):
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                current.removeAll { $0.name.lowercased() == nameLower }
            case .headerReplace(let regex, let name, let value):
                current = current.map { entry in
                    let literal = "\(entry.name): \(entry.value)"
                    let range = NSRange(literal.startIndex..., in: literal)
                    guard regex.firstMatch(in: literal, options: [], range: range) != nil else {
                        return entry
                    }
                    return (name: name, value: value)
                }
            case .script, .streamScript:
                continue
            }
        }
        return current
    }
}
