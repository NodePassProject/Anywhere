//
//  DomainRouter.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "DomainRouter")

enum RouteAction {
    case direct
    case reject
    case proxy(UUID)
}

class DomainRouter {

    // MARK: - Tier model
    //
    // Each rule source owns its own set of matching structures, so cross-source
    // priority is enforced by the order tiers are queried, not by trie insert
    // order. Within a tier, suffix rules win over keyword rules; deepest suffix
    // and longest CIDR prefix still win, but that competition is now scoped to
    // a single source.
    //
    // Priority (highest first): User > ADBlock > Built-in > Country Bypass.

    private final class TrieNode {
        var children: [String: TrieNode] = [:]
        var action: RouteAction?
    }

    private struct KeywordRule {
        let pattern: String
        let action: RouteAction
        let patternLength: Int

        init(pattern: String, action: RouteAction) {
            self.pattern = pattern
            self.action = action
            self.patternLength = pattern.utf8.count
        }
    }

    private struct TierMatchers {
        var trieRoot = TrieNode()
        var keywordRules: [KeywordRule] = []
        var ipv4Trie = CIDRTrie()
        var ipv6Trie = CIDRTrie()
        var domainRuleCount = 0
        var ipRuleCount = 0

        var isEmpty: Bool { domainRuleCount == 0 && ipRuleCount == 0 }

        mutating func insertSuffix(_ suffix: String, action: RouteAction) {
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
            node.action = action
            domainRuleCount += 1
        }

        mutating func insertKeyword(_ pattern: String, action: RouteAction) {
            guard !pattern.isEmpty else { return }
            let rule = KeywordRule(pattern: pattern, action: action)
            if let index = keywordRules.firstIndex(where: { $0.pattern == pattern }) {
                keywordRules[index] = rule
            } else {
                keywordRules.append(rule)
            }
            domainRuleCount += 1
        }

        mutating func insertIPv4(network: UInt32, prefixLen: Int, action: RouteAction) {
            ipv4Trie.insert(network: network, prefixLen: prefixLen, action: action)
            ipRuleCount += 1
        }

        mutating func insertIPv6(network: [UInt8], prefixLen: Int, action: RouteAction) {
            ipv6Trie.insert(network: network, prefixLen: prefixLen, action: action)
            ipRuleCount += 1
        }

        func lookupDomain(_ domain: String) -> RouteAction? {
            lookupSuffix(domain) ?? lookupKeyword(domain)
        }

        private func lookupSuffix(_ domain: String) -> RouteAction? {
            var node = trieRoot
            var deepestAction: RouteAction? = nil
            for label in domain.split(separator: ".").reversed() {
                guard let child = node.children[String(label)] else { break }
                node = child
                if let action = node.action { deepestAction = action }
            }
            return deepestAction
        }

        private func lookupKeyword(_ domain: String) -> RouteAction? {
            var bestAction: RouteAction? = nil
            var bestLength = -1
            for rule in keywordRules where domain.contains(rule.pattern) {
                if rule.patternLength >= bestLength {
                    bestAction = rule.action
                    bestLength = rule.patternLength
                }
            }
            return bestAction
        }
    }

    // Tiers in priority order — first hit wins.
    private enum Tier: Int, CaseIterable {
        case user = 0
        case adBlock = 1
        case builtIn = 2
        case bypass = 3
    }

    private var tiers: [TierMatchers] = Tier.allCases.map { _ in TierMatchers() }

    // Proxy configurations for rule-assigned proxies
    private var configurationMap: [UUID: ProxyConfiguration] = [:]

    // MARK: - Loading

    /// Clears all routing rules and configurations.
    /// Used when switching to global mode to ensure no stale rules affect routing.
    func reset() {
        tiers = Tier.allCases.map { _ in TierMatchers() }
        configurationMap.removeAll()
    }

    /// Reads routing configuration from App Group UserDefaults and compiles rules
    /// into per-tier matching structures.
    func loadRoutingConfiguration() {
        reset()

        guard let data = AWCore.getRoutingData(),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            logger.debug("[DomainRouter] No routing data available")
            return
        }

        // Configurations (tier-independent)
        if let configurations = json["configs"] as? [String: Any] {
            for (key, value) in configurations {
                guard let configurationId = UUID(uuidString: key),
                      let configurationDict = value as? [String: Any] else { continue }
                if let configuration = ProxyConfiguration.parse(from: configurationDict) {
                    configurationMap[configurationId] = configuration
                }
            }
        }

        // Tiered rule loading. Each tier reads from its own array.
        if let entries = json["userRules"] as? [[String: Any]] {
            loadRuleEntries(entries, into: .user)
        }
        if let entries = json["adBlockRules"] as? [[String: Any]] {
            loadRuleEntries(entries, into: .adBlock)
        }
        if let entries = json["builtInRules"] as? [[String: Any]] {
            loadRuleEntries(entries, into: .builtIn)
        }
        if let entries = json["bypassRules"] as? [[String: Any]] {
            loadBypassEntries(entries, into: .bypass)
        }

        logger.debug("[DomainRouter] Loaded tiers — user: \(self.tiers[Tier.user.rawValue].domainRuleCount)+\(self.tiers[Tier.user.rawValue].ipRuleCount), adBlock: \(self.tiers[Tier.adBlock.rawValue].domainRuleCount)+\(self.tiers[Tier.adBlock.rawValue].ipRuleCount), builtIn: \(self.tiers[Tier.builtIn.rawValue].domainRuleCount)+\(self.tiers[Tier.builtIn.rawValue].ipRuleCount), bypass: \(self.tiers[Tier.bypass.rawValue].domainRuleCount)+\(self.tiers[Tier.bypass.rawValue].ipRuleCount); \(self.configurationMap.count) configurations")
    }

    private func loadRuleEntries(_ entries: [[String: Any]], into tier: Tier) {
        for rule in entries {
            guard let actionStr = rule["action"] as? String else { continue }

            let action: RouteAction
            if actionStr == "direct" {
                action = .direct
            } else if actionStr == "reject" {
                action = .reject
            } else if actionStr == "proxy",
                      let configurationIdStr = rule["configId"] as? String,
                      let configurationId = UUID(uuidString: configurationIdStr) {
                action = .proxy(configurationId)
            } else {
                continue
            }

            if let domainRules = rule["domainRules"] as? [[String: Any]] {
                for dr in domainRules {
                    guard let type = Self.parseRuleType(dr["type"]),
                          let value = dr["value"] as? String else { continue }
                    let lowered = value.lowercased()
                    switch type {
                    case .domainSuffix:
                        tiers[tier.rawValue].insertSuffix(lowered, action: action)
                    case .domainKeyword:
                        tiers[tier.rawValue].insertKeyword(lowered, action: action)
                    case .ipCIDR, .ipCIDR6:
                        break
                    }
                }
            }

            if let ipRules = rule["ipRules"] as? [[String: Any]] {
                for ir in ipRules {
                    guard let type = Self.parseRuleType(ir["type"]),
                          let value = ir["value"] as? String else { continue }
                    switch type {
                    case .ipCIDR:
                        if let parsed = Self.parseIPv4CIDR(value) {
                            tiers[tier.rawValue].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
                        }
                    case .ipCIDR6:
                        if let parsed = Self.parseIPv6CIDR(value) {
                            tiers[tier.rawValue].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
                        }
                    case .domainSuffix, .domainKeyword:
                        break
                    }
                }
            }
        }
    }

    /// Bypass rules use a flat {type, value} shape with an implicit `.direct` action.
    private func loadBypassEntries(_ entries: [[String: Any]], into tier: Tier) {
        for rule in entries {
            guard let type = Self.parseRuleType(rule["type"]),
                  let value = rule["value"] as? String else { continue }
            switch type {
            case .domainSuffix:
                tiers[tier.rawValue].insertSuffix(value.lowercased(), action: .direct)
            case .domainKeyword:
                tiers[tier.rawValue].insertKeyword(value.lowercased(), action: .direct)
            case .ipCIDR:
                if let parsed = Self.parseIPv4CIDR(value) {
                    tiers[tier.rawValue].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, action: .direct)
                }
            case .ipCIDR6:
                if let parsed = Self.parseIPv6CIDR(value) {
                    tiers[tier.rawValue].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, action: .direct)
                }
            }
        }
    }

    // MARK: - Matching (public API)

    /// Whether any routing rules have been loaded across any tier.
    var hasRules: Bool {
        tiers.contains { !$0.isEmpty }
    }

    /// Matches a domain by walking tiers in priority order. First hit wins.
    func matchDomain(_ domain: String) -> RouteAction? {
        guard !domain.isEmpty else { return nil }
        let lowered = domain.lowercased()
        for tier in tiers {
            if let action = tier.lookupDomain(lowered) { return action }
        }
        return nil
    }

    /// Matches an IP address against per-tier CIDR tries in priority order.
    func matchIP(_ ip: String) -> RouteAction? {
        guard !ip.isEmpty else { return nil }

        if ip.contains(":") {
            var addr = in6_addr()
            guard inet_pton(AF_INET6, ip, &addr) == 1 else { return nil }
            return withUnsafeBytes(of: &addr) { raw in
                let buf = raw.bindMemory(to: UInt8.self)
                for tier in tiers {
                    if let action = tier.ipv6Trie.lookup(buf) { return action }
                }
                return nil
            }
        } else {
            guard let ip32 = Self.parseIPv4(ip) else { return nil }
            for tier in tiers {
                if let action = tier.ipv4Trie.lookup(ip32) { return action }
            }
            return nil
        }
    }

    /// Resolves a RouteAction to a ProxyConfiguration.
    /// Returns nil for .direct/.reject or when the configuration UUID is not found.
    func resolveConfiguration(action: RouteAction) -> ProxyConfiguration? {
        switch action {
        case .direct, .reject:
            return nil
        case .proxy(let id):
            return configurationMap[id]
        }
    }

    // MARK: - CIDR Parsing

    private static func parseRuleType(_ rawValue: Any?) -> RoutingRuleType? {
        guard let rawValue = rawValue as? Int else { return nil }
        return RoutingRuleType(rawValue: rawValue)
    }

    /// Parses "A.B.C.D/prefix" into (network, prefixLen) with host bits zeroed.
    private static func parseIPv4CIDR(_ cidr: String) -> (network: UInt32, prefixLen: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLen = Int(parts[1]),
              prefixLen >= 0, prefixLen <= 32,
              let ip = parseIPv4(String(parts[0])) else { return nil }
        let mask: UInt32 = prefixLen == 0 ? 0 : ~UInt32(0) << (32 - prefixLen)
        return (network: ip & mask, prefixLen: prefixLen)
    }

    /// Parses a dotted-quad IPv4 string to host-order UInt32.
    private static func parseIPv4(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            result = result << 8 | UInt32(byte)
        }
        return result
    }

    /// Parses "addr/prefix" IPv6 CIDR into (network bytes, prefix length).
    private static func parseIPv6CIDR(_ cidr: String) -> (network: [UInt8], prefixLen: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLen = Int(parts[1]),
              prefixLen >= 0, prefixLen <= 128 else { return nil }

        var addr = in6_addr()
        guard inet_pton(AF_INET6, String(parts[0]), &addr) == 1 else { return nil }

        var network = withUnsafeBytes(of: &addr) { Array($0.bindMemory(to: UInt8.self)) }
        // Zero host bits
        for i in 0..<16 {
            let bitPos = i * 8
            if bitPos >= prefixLen {
                network[i] = 0
            } else if bitPos + 8 > prefixLen {
                let keep = prefixLen - bitPos
                network[i] &= ~UInt8(0) << (8 - keep)
            }
        }
        return (network: network, prefixLen: prefixLen)
    }
}

// MARK: - CIDR Binary Trie
//
// Binary trie for longest-prefix-match on IP addresses.
// Each bit of the address selects a child (0 = left, 1 = right).
// One trie per tier; cross-tier priority is handled by DomainRouter.
// Lookup walks all address bits, tracking the deepest match — O(W) where
// W = address width (32 for IPv4, 128 for IPv6), independent of rule count.

struct CIDRTrie {
    private final class Node {
        var left: Node?       // bit 0
        var right: Node?      // bit 1
        var action: RouteAction?
    }

    private var root = Node()

    /// Inserts a CIDR rule. More-specific prefixes override less-specific ones.
    mutating func insert(network: UInt32, prefixLen: Int, action: RouteAction) {
        let node = walkOrCreate(network, depth: prefixLen)
        node.action = action
    }

    /// Inserts a CIDR rule from IPv6 network bytes.
    mutating func insert(network: [UInt8], prefixLen: Int, action: RouteAction) {
        let node = walkOrCreateIPv6(network, depth: prefixLen)
        node.action = action
    }

    /// Looks up an IPv4 address. Returns the deepest action along the path. O(32).
    func lookup(_ ip: UInt32) -> RouteAction? {
        var node = root
        var deepestAction: RouteAction? = node.action

        for i in 0..<32 {
            let bit = (ip >> (31 - i)) & 1
            guard let next = bit == 0 ? node.left : node.right else { break }
            node = next
            if let action = node.action { deepestAction = action }
        }

        return deepestAction
    }

    /// Looks up an IPv6 address from a byte buffer. O(128).
    func lookup(_ bytes: UnsafeBufferPointer<UInt8>) -> RouteAction? {
        var node = root
        var deepestAction: RouteAction? = node.action

        for i in 0..<128 {
            let bit = (bytes[i >> 3] >> (7 - (i & 7))) & 1
            guard let next = bit == 0 ? node.left : node.right else { break }
            node = next
            if let action = node.action { deepestAction = action }
        }

        return deepestAction
    }

    // MARK: - Private

    private func walkOrCreate(_ network: UInt32, depth: Int) -> Node {
        var node = root
        for i in 0..<depth {
            let bit = (network >> (31 - i)) & 1
            if bit == 0 {
                if node.left == nil { node.left = Node() }
                node = node.left!
            } else {
                if node.right == nil { node.right = Node() }
                node = node.right!
            }
        }
        return node
    }

    private func walkOrCreateIPv6(_ network: [UInt8], depth: Int) -> Node {
        var node = root
        for i in 0..<depth {
            let bit = (network[i >> 3] >> (7 - (i & 7))) & 1
            if bit == 0 {
                if node.left == nil { node.left = Node() }
                node = node.left!
            } else {
                if node.right == nil { node.right = Node() }
                node = node.right!
            }
        }
        return node
    }
}
