//
//  MITMHostMatcher.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

final class MITMHostMatcher {

    private final class TrieNode {
        var children: [String: TrieNode] = [:]
        var present = false
    }

    private var trieRoot = TrieNode()
    private var keywords: [String] = []
    private(set) var ruleCount = 0

    /// Whether any rules have been loaded. Used by the lwIP path so the no-op
    /// case stays at a single bool check.
    var hasRules: Bool { ruleCount > 0 }

    func reset() {
        trieRoot = TrieNode()
        keywords.removeAll()
        ruleCount = 0
    }

    /// Replaces the in-memory rule set with the JSON shape persisted by
    /// ``MITMStore``. Caller should clear or rebuild on the lwIP queue.
    ///
    /// JSON shape:
    /// ```
    /// { "enabled": Bool, "rules": [{"type": Int, "value": String}] }
    /// ```
    /// `type` reuses the routing-side ``DomainRuleType`` raw values:
    /// `domainSuffix = 2`, `domainKeyword = 3`. IP-CIDR types are ignored —
    /// MITM is SNI-based and has no meaning for raw IP selectors.
    func load(from data: Data) {
        reset()

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rules = json["rules"] as? [[String: Any]] else {
            logger.debug("[MITM] No matcher rules to load")
            return
        }

        for rule in rules {
            guard let rawType = rule["type"] as? Int,
                  let type = DomainRuleType(rawValue: rawType),
                  let value = rule["value"] as? String,
                  !value.isEmpty else { continue }
            let lowered = value.lowercased()
            switch type {
            case .domainSuffix:
                insertSuffix(lowered)
                ruleCount += 1
            case .domainKeyword:
                if !keywords.contains(lowered) {
                    keywords.append(lowered)
                    ruleCount += 1
                }
            case .ipCIDR, .ipCIDR6:
                continue
            }
        }

        logger.debug("[MITM] Loaded \(ruleCount) matcher rules")
    }

    /// Returns `true` iff the hostname matches any loaded suffix or keyword
    /// rule. Empty input always returns `false`.
    func matches(_ host: String) -> Bool {
        guard !host.isEmpty else { return false }
        let lowered = host.lowercased()
        if suffixMatches(lowered) { return true }
        return keywords.contains(where: { lowered.contains($0) })
    }

    // MARK: - Internals

    private func insertSuffix(_ suffix: String) {
        var node = trieRoot
        for label in suffix.split(separator: ".").reversed() {
            let key = String(label)
            if let child = node.children[key] {
                node = child
            } else {
                let child = TrieNode()
                node.children[key] = child
                node = child
            }
        }
        node.present = true
    }

    private func suffixMatches(_ host: String) -> Bool {
        var node = trieRoot
        for label in host.split(separator: ".").reversed() {
            guard let child = node.children[String(label)] else { return false }
            node = child
            if node.present { return true }
        }
        return false
    }
}
