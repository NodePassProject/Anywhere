//
//  MITMRewritePolicy.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// One rewrite as the runtime sees it: regexes pre-compiled, header
/// names case-folded.
struct CompiledMITMRule {
    let phase: MITMPhase
    let operation: CompiledMITMOperation
}

enum CompiledMITMOperation {
    case urlReplace(regex: NSRegularExpression, replacement: String)
    case headerAdd(name: String, value: String)
    case headerDelete(nameLower: String)
    case headerReplace(regex: NSRegularExpression, name: String, value: String)
    /// JavaScript transform. ``source`` is the decoded UTF-8 source of
    /// `function process(body, ctx)`. Compilation/execution belongs to
    /// ``MITMScriptEngine`` so the policy stays free of JSContext.
    case bodyScript(source: String)
}

/// Compiled view of a rule set at one trie terminal: the specific suffix
/// reached, the optional upstream redirect, and rules ready to apply. A
/// source set with multiple suffixes produces one of these per suffix,
/// each sharing the same compiled rules and target. ``id`` is copied
/// from the source ``MITMRuleSet`` so the runtime can use it as a
/// stable scope key for ``MITMScriptStore``.
struct CompiledMITMRuleSet {
    let id: UUID
    let domainSuffix: String
    let rewriteTarget: MITMRewriteTarget?
    let rules: [CompiledMITMRule]
}

/// Owns configured MITM rule sets in compiled form. Decides:
///   - whether a given SNI/destination host should be intercepted
///     (``matches``), driving the lwIP-side branch into ``MITMSession``;
///   - which set's rules apply for a host (``set(for:)``), consumed by
///     the HTTP/1.1 and HTTP/2 rewriters.
///
/// Domain suffix matching is **most-specific-win**: when both
/// `example.com` and `api.example.com` are configured, a request to
/// `api.example.com` selects only the latter set's rules and target.
/// A trie of reversed labels enforces that ordering.
final class MITMRewritePolicy {

    private final class TrieNode {
        var children: [String: TrieNode] = [:]
        var ruleSet: CompiledMITMRuleSet?
    }

    private var root = TrieNode()
    private var setCount: Int = 0

    /// Whether any rule sets have been loaded. Used by the lwIP path so
    /// the no-op case stays at a single bool check.
    var hasRules: Bool { setCount > 0 }

    func reset() {
        root = TrieNode()
        setCount = 0
    }

    /// Replaces the in-memory rule set table from a typed
    /// ``MITMSnapshot``. Suffixes that are empty are skipped silently;
    /// a set with no usable suffixes contributes nothing. Rules whose
    /// regex fails to compile are dropped with a log line; the rest of
    /// the set still applies.
    ///
    /// Conflict handling: if two sets declare the same suffix, the
    /// later one wins (with a warning).
    func load(ruleSets: [MITMRuleSet]) {
        reset()
        for set in ruleSets {
            insert(set)
        }
        logger.debug("[MITM] Loaded \(ruleSets.count) rule set(s)")
    }

    private func insert(_ set: MITMRuleSet) {
        let suffixes = set.domainSuffixes
            .map { $0.lowercased().trimmingCharacters(in: CharacterSet.whitespaces) }
            .filter { !$0.isEmpty }
        guard !suffixes.isEmpty else { return }

        let compiledRules = set.rules.compactMap { rule -> CompiledMITMRule? in
            guard let op = compile(rule.operation, suffix: set.name) else { return nil }
            return CompiledMITMRule(phase: rule.phase, operation: op)
        }

        for suffix in suffixes {
            let labels = suffix.split(separator: ".").map(String.init).reversed()
            var node = root
            for label in labels {
                if let child = node.children[label] {
                    node = child
                } else {
                    let child = TrieNode()
                    node.children[label] = child
                    node = child
                }
            }

            if node.ruleSet == nil { setCount += 1 }
            node.ruleSet = CompiledMITMRuleSet(
                id: set.id,
                domainSuffix: suffix,
                rewriteTarget: set.rewriteTarget,
                rules: compiledRules
            )
        }
    }

    /// Returns `true` when the hostname is covered by any rule set. Empty
    /// input always returns `false`.
    func matches(_ host: String) -> Bool {
        set(for: host) != nil
    }

    /// Returns the most-specific rule set that covers ``host``, or nil
    /// if no set applies. Walks the label trie greedily; the deepest
    /// terminal reached during descent is the most-specific match.
    func set(for host: String) -> CompiledMITMRuleSet? {
        guard !host.isEmpty, setCount > 0 else { return nil }
        var node = root
        var deepest: CompiledMITMRuleSet? = nil
        for label in host.lowercased().split(separator: ".").reversed() {
            guard let child = node.children[String(label)] else { break }
            node = child
            if let set = node.ruleSet {
                deepest = set
            }
        }
        return deepest
    }

    /// Convenience for the rewriters: rules from the most-specific set
    /// matching ``host``, filtered to ``phase`` and stored insertion order.
    /// Empty when no set matches.
    func rules(for host: String, phase: MITMPhase) -> [CompiledMITMRule] {
        guard let set = set(for: host) else { return [] }
        return set.rules.filter { $0.phase == phase }
    }

    /// Convenience for ``LWIPTCPConnection`` and ``MITMSession``: the
    /// upstream redirect for a host, if any.
    func rewriteTarget(for host: String) -> MITMRewriteTarget? {
        set(for: host)?.rewriteTarget
    }

    // MARK: - Compilation

    private func compile(_ operation: MITMOperation, suffix: String) -> CompiledMITMOperation? {
        switch operation {
        case .urlReplace(let pattern, let replacement):
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
                logger.warning("[MITM] urlReplace pattern failed to compile (suffix=\(suffix)): \(pattern)")
                return nil
            }
            return .urlReplace(regex: regex, replacement: replacement)
        case .headerAdd(let name, let value):
            return .headerAdd(name: name, value: value)
        case .headerDelete(let name):
            return .headerDelete(nameLower: name.lowercased())
        case .headerReplace(let pattern, let name, let value):
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
                logger.warning("[MITM] headerReplace pattern failed to compile (suffix=\(suffix)): \(pattern)")
                return nil
            }
            return .headerReplace(regex: regex, name: name, value: value)
        case .bodyScript(let scriptBase64):
            guard let raw = Data(base64Encoded: scriptBase64) else {
                logger.warning("[MITM] bodyScript invalid base64 (suffix=\(suffix))")
                return nil
            }
            guard let source = String(data: raw, encoding: .utf8) else {
                logger.warning("[MITM] bodyScript source not valid UTF-8 (suffix=\(suffix))")
                return nil
            }
            return .bodyScript(source: source)
        }
    }
}
