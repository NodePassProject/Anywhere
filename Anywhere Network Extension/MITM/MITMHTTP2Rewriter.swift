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

    private let host: String
    private let policy: MITMRewritePolicy
    /// When set, every request's `:authority` pseudo-header is rewritten to
    /// this value. Driven by the rule set's ``rewriteTarget``; nil means
    /// "leave :authority alone".
    private let effectiveAuthority: String?

    init(host: String, policy: MITMRewritePolicy, effectiveAuthority: String?) {
        self.host = host
        self.policy = policy
        self.effectiveAuthority = effectiveAuthority
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

    // MARK: - Body rewrite preflight

    /// Whether any ``bodyReplace`` rule applies for this host + phase.
    /// The connection uses this to decide whether to buffer DATA frames.
    func hasBodyRewrite(phase: MITMPhase) -> Bool {
        policy.rules(for: host, phase: phase).contains {
            if case .bodyReplace = $0.operation { return true }
            return false
        }
    }

    /// Applies every ``bodyReplace`` rule for the given phase. Bodies
    /// are mapped to a Latin-1 string (1:1 byte-to-codepoint) so the
    /// regex round-trip preserves binary and non-UTF-8 payloads
    /// exactly. The caller is responsible for decompressing
    /// content-encoded bodies before passing them in.
    func rewriteBody(_ data: Data, phase: MITMPhase) -> Data {
        let rules = policy.rules(for: host, phase: phase)
        guard var bodyString = String(bytes: data, encoding: .isoLatin1) else {
            return data
        }
        var changed = false
        for rule in rules {
            guard case .bodyReplace(let regex, let replacement) = rule.operation else {
                continue
            }
            let range = NSRange(bodyString.startIndex..., in: bodyString)
            let mutated = regex.stringByReplacingMatches(
                in: bodyString,
                options: [],
                range: range,
                withTemplate: replacement
            )
            if mutated != bodyString {
                bodyString = mutated
                changed = true
            }
        }
        guard changed else { return data }
        return bodyString.data(using: .isoLatin1) ?? data
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
            case .bodyReplace:
                continue
            }
        }
        return current
    }
}
