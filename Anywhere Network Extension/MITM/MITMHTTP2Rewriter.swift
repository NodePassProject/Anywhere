//
//  MITMHTTP2Rewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
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
    /// Compiled rules for this rewriter's host, split by phase and
    /// captured once at init. Resolving them lowercases the host, walks
    /// the suffix trie, and allocates a fresh filtered array — none of
    /// which changes between messages on the same session. Same
    /// rationale as in ``MITMHTTP1Stream``: every HEADERS frame would
    /// otherwise pay that cost twice (script preflight + scripting), and
    /// DATA frames on streaming-script rules would re-resolve on every
    /// frame.
    private let requestRules: [CompiledMITMRule]
    private let responseRules: [CompiledMITMRule]
    private let cachedRuleSetID: UUID?
    /// When set, every request's `:authority` pseudo-header is rewritten to
    /// this value. Late-bound: set by the first transparent
    /// ``MITMOperation/rewrite`` to the replacement's authority; nil means
    /// "leave :authority alone".
    private var effectiveAuthority: String?

    /// The upstream the session should dial, surfaced when a transparent
    /// rewrite resolves a replacement host. nil until then (the session falls
    /// back to the original destination). Read by the session's deferred-dial
    /// pump after the first request HEADERS are processed.
    private(set) var resolvedUpstream: (host: String, port: UInt16?)?
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
        // Resolve the host's rule set once — each ``set(for:)`` /
        // ``rules(for:phase:)`` lowercases the host and walks the locked
        // trie — then split into per-phase lists and read the id from
        // that single lookup instead of three.
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
        // :authority rewrite runs first so configured headerReplace rules
        // see the canonical post-redirect value and can override it.
        // Request rules gate on the whole URL built from the live ``:path``
        // (read per-rule inside applyHeaderRules), so none is threaded here.
        let withAuthority = applyAuthorityRewrite(headers)
        return applyHeaderRules(withAuthority, phase: .httpRequest, requestURL: nil)
    }

    /// ``requestURL`` is the originating request's whole URL, the gate for
    /// response-phase rules (response headers carry no ``:path``).
    func transformResponseHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32,
        requestURL: String?
    ) -> [(name: String, value: String)] {
        applyHeaderRules(headers, phase: .httpResponse, requestURL: requestURL)
    }

    /// The `:path` pseudo-header (request-target) from a decoded header
    /// list, or nil if absent.
    static func requestPath(in headers: [(name: String, value: String)]) -> String? {
        for (name, value) in headers where name == ":path" { return value }
        return nil
    }

    /// Pre-check for a 302 / reject ``MITMOperation/rewrite`` on a request:
    /// returns the synthesized response when the first matching request-phase
    /// rewrite rule is a synthesize sub-mode, so the connection can answer on
    /// the inner leg without opening the stream upstream. Returns nil when the
    /// first matching rewrite is transparent (handled by
    /// ``transformRequestHeaders``) or no rewrite rule matches. First match
    /// wins, mirroring ``applyHeaderRules``.
    func requestSynthResponse(requestURL: String?) -> MITMScriptEngine.SynthesizedResponse? {
        for rule in requestRules {
            guard case .rewrite(let action) = rule.operation else { continue }
            guard rule.matchesURL(requestURL) else { continue }
            if case .transparent = action { return nil }
            return MITMRespondBuilder.response(for: action)
        }
        return nil
    }

    // MARK: - Script preflight + application

    /// Whether any streaming-script rule applies. Streaming rules tell
    /// the connection to emit HEADERS immediately and run scripts
    /// per-frame instead of buffering the full body.
    func hasStreamScriptRule(phase: MITMPhase, requestURL: String?) -> Bool {
        MITMScriptTransform.hasStreamScriptRule(
            in: rules(phase: phase),
            requestURL: requestURL
        )
    }

    /// Whether any buffered body transform — a script, one/more native text
    /// replaces (``MITMOperation/bodyReplace``), or one/more native JSON
    /// edits (``MITMOperation/bodyJSON``) — applies for this host + phase and
    /// request URL. The connection gates body buffering on this; every
    /// kind needs the full decompressed body and they are applied together
    /// by ``applyScripts``. Check ``hasStreamScriptRule`` first — streaming
    /// rules take precedence and never coexist with buffered mode on the
    /// same stream.
    func hasBufferedBodyRule(phase: MITMPhase, requestURL: String?) -> Bool {
        MITMScriptTransform.hasBufferedBodyRule(
            in: rules(phase: phase),
            requestURL: requestURL
        )
    }

    /// Compiled rule list for the host/phase, exposed so the connection
    /// can pass it into ``MITMScriptTransform.applyFrame`` without
    /// re-resolving the policy on every DATA frame.
    func rules(phase: MITMPhase) -> [CompiledMITMRule] {
        phase == .httpRequest ? requestRules : responseRules
    }

    /// The matched rule set's ID, used as the script-store scope key.
    /// Stable for the rewriter's lifetime since ``host`` is fixed at
    /// init time.
    var ruleSetID: UUID? { cachedRuleSetID }

    /// Applies the script rule for the given phase whose URL pattern matches
    /// the request URL. Runs the match on
    /// ``MITMScriptTransform/scriptQueue`` and delivers the ``Outcome`` back
    /// on ``resumeQueue`` (the connection's lwIP queue), so a slow script
    /// parks the connection instead of stalling packet processing.
    ///
    /// The caller is responsible for decompressing the body before passing
    /// it in; on the ``.message`` branch the returned message has the
    /// (possibly modified) body in identity form. The
    /// ``.synthesizedResponse`` branch fires only on request phase when the
    /// script called `Anywhere.respond(...)` — the caller must suppress
    /// upstream emission and inject the response on the inner leg instead.
    func applyScripts(
        _ message: MITMScriptEngine.Message,
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

    /// HTTP/2 analog of HTTP/1.1's Host rewrite. The `:authority`
    /// pseudo-header is replaced; if absent, one is inserted before regular
    /// headers as required by RFC 9113 section 8.3.
    ///
    /// Skips trailer HEADERS (those that lack ``:method``) entirely.
    /// RFC 9113 §8.1 forbids pseudo-headers in trailers; strict
    /// receivers (Go, nghttp2) treat any pseudo-header in a trailer
    /// as PROTOCOL_ERROR and RST_STREAM the request mid-body. Without
    /// this guard, a trailer HEADERS on a request stream with an
    /// effective authority set would otherwise have ``:authority``
    /// injected.
    private func applyAuthorityRewrite(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        guard let authority = effectiveAuthority else { return headers }
        // Detect trailer (request HEADERS that lacks ``:method`` per
        // §8.1). The MITMHTTP2Connection's caller already
        // classifies trailers via the same predicate before invoking
        // us, but the defensive check here makes the
        // pseudo-header-safety invariant local to the function.
        let hasMethod = headers.contains { $0.name == ":method" }
        guard hasMethod else { return headers }
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
        phase: MITMPhase,
        requestURL: String?
    ) -> [(name: String, value: String)] {
        let rulesForPhase = rules(phase: phase)
        guard !rulesForPhase.isEmpty else { return headers }

        var current = headers
        // First matching transparent rewrite wins (the replacement is a literal
        // full URL, so chaining is meaningless); later rewrite rules are skipped.
        var rewroteRequest = false
        for rule in rulesForPhase {
            // Request rules gate on the whole URL built from the live
            // ``:path`` — an earlier transparent rewrite in this same list may have
            // rewritten it. Response rules gate on the originating request's
            // URL (passed in, since responses carry no ``:path``).
            let gateURL = (phase == .httpRequest)
                ? Self.requestPath(in: current).map { "https://\(host)\($0)" }
                : requestURL
            guard rule.matchesURL(gateURL) else { continue }
            switch rule.operation {
            case .rewrite(let action):
                // Request-phase only. The 302 / reject sub-modes synthesize on
                // the inner leg via the connection's pre-check
                // (``requestSynthResponse``); here we only apply a transparent
                // rewrite — rewrite ``:path`` to the replacement's request
                // target and ``:authority`` to its host, and surface the dial
                // target. Subsequent requests reuse ``effectiveAuthority`` via
                // ``applyAuthorityRewrite``.
                guard phase == .httpRequest, !rewroteRequest,
                      case .transparent(let replacement) = action else { continue }
                rewroteRequest = true
                effectiveAuthority = replacement.authority
                resolvedUpstream = (host: replacement.host, port: replacement.port)
                var sawAuthority = false
                current = current.map { entry in
                    if entry.name == ":path" {
                        return (name: ":path", value: replacement.requestTarget)
                    }
                    if entry.name == ":authority" {
                        sawAuthority = true
                        return (name: ":authority", value: replacement.authority)
                    }
                    return entry
                }
                if !sawAuthority {
                    // RFC 9113 §8.3.1: requests carry :authority. Insert it
                    // before the regular headers if the client omitted it.
                    current.insert((name: ":authority", value: replacement.authority), at: 0)
                }
            case .headerAdd(let name, let value):
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                current.removeAll { $0.name.equalsIgnoringASCIICase(nameLower) }
            case .headerReplace(let name, let value):
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
