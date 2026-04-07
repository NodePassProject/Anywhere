//
//  DomainRouter.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = TunnelLogger(category: "DomainRouter")

enum RouteAction {
    case direct
    case reject
    case proxy(UUID)
}

class DomainRouter {

    // MARK: - Suffix Trie (reverse-label)
    //
    // All domain filters are normalized to suffix rules.
    // Domains are split into labels and reversed: "www.google.com" → ["com","google","www"].
    // Walking the trie from root matches progressively more-specific suffixes.
    // Bypass country rules are loaded first as .direct, then user rules overwrite.

    private final class TrieNode {
        var children: [String: TrieNode] = [:]
        var userAction: RouteAction?
    }

    private var trieRoot = TrieNode()

    // MARK: - IP CIDR Binary Tries
    //
    // Binary tries for longest-prefix-match on IP addresses.
    // Bypass country rules are inserted first as .direct, then user rules overwrite.
    // Lookup is O(32) for IPv4, O(128) for IPv6 — constant regardless of rule count.

    private var ipv4Trie = CIDRTrie()
    private var ipv6Trie = CIDRTrie()

    // Proxy configurations for rule-assigned proxies
    private var configurationMap: [UUID: ProxyConfiguration] = [:]

    // Counts for hasRules (user rules only)
    private var domainRuleCount = 0
    private var ipRuleCount = 0

    // MARK: - Loading

    /// Reads routing configuration from App Group UserDefaults and compiles rules.
    /// Bypass country rules are loaded first as `.direct`, then user rules overwrite.
    func loadRoutingConfiguration() {
        // Clear all matching structures
        trieRoot = TrieNode()
        domainRuleCount = 0
        ipRuleCount = 0

        ipv4Trie = CIDRTrie()
        ipv6Trie = CIDRTrie()
        configurationMap.removeAll()

        guard let data = AWCore.userDefaults.data(forKey: TunnelConstants.UserDefaultsKey.routingData),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            logger.debug("[DomainRouter] No routing data available")
            return
        }

        // Load bypass country rules first — user rules will overwrite on conflict
        var bypassDomainRuleCount = 0
        var bypassIPRuleCount = 0
        if let bypassRules = json["bypassRules"] as? [[String: Any]] {
            for rule in bypassRules {
                guard let type = Self.parseRuleType(rule["type"]),
                      let value = rule["value"] as? String else { continue }
                switch type {
                case .domainSuffix:
                    trieInsert(value.lowercased(), action: .direct)
                    bypassDomainRuleCount += 1
                case .ipCIDR:
                    if let parsed = Self.parseIPv4CIDR(value) {
                        ipv4Trie.insert(network: parsed.network, prefixLen: parsed.prefixLen, action: .direct)
                        bypassIPRuleCount += 1
                    }
                case .ipCIDR6:
                    if let parsed = Self.parseIPv6CIDR(value) {
                        ipv6Trie.insert(network: parsed.network, prefixLen: parsed.prefixLen, action: .direct)
                        bypassIPRuleCount += 1
                    }
                }
            }
        }
        if bypassDomainRuleCount > 0 || bypassIPRuleCount > 0 {
            logger.debug("[DomainRouter] Loaded \(bypassDomainRuleCount) bypass country domain rules, \(bypassIPRuleCount) IP rules")
        }

        // Parse configurations
        if let configurations = json["configs"] as? [String: Any] {
            for (key, value) in configurations {
                guard let configurationId = UUID(uuidString: key),
                      let configurationDict = value as? [String: Any] else { continue }
                if let configuration = ProxyConfiguration.parse(from: configurationDict) {
                    configurationMap[configurationId] = configuration
                }
            }
        }

        // Parse user rules — these overwrite bypass rules on the same node
        guard let rules = json["rules"] as? [[String: Any]] else {
            logger.warning("[VPN] Routing data malformed: missing rules")
            return
        }
        for rule in rules {
            guard let actionStr = rule["action"] as? String else { continue }

            let action: RouteAction
            if actionStr == "direct" {
                action = .direct
            } else if actionStr == "reject" {
                action = .reject
            } else if actionStr == "proxy", let configurationIdStr = rule["configId"] as? String, let configurationId = UUID(uuidString: configurationIdStr) {
                action = .proxy(configurationId)
            } else {
                continue
            }

            // Domain rules
            if let domainRules = rule["domainRules"] as? [[String: Any]] {
                for dr in domainRules {
                    guard let type = Self.parseRuleType(dr["type"]),
                          let value = dr["value"] as? String else { continue }
                    let lowered = value.lowercased()

                    switch type {
                    case .domainSuffix:
                        trieInsert(lowered, action: action)
                        domainRuleCount += 1
                    case .ipCIDR, .ipCIDR6:
                        break
                    }
                }
            }

            // IP CIDR rules
            if let ipRules = rule["ipRules"] as? [[String: Any]] {
                for ir in ipRules {
                    guard let type = Self.parseRuleType(ir["type"]),
                          let value = ir["value"] as? String else { continue }

                    switch type {
                    case .ipCIDR:
                        if let parsed = Self.parseIPv4CIDR(value) {
                            ipv4Trie.insert(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
                            ipRuleCount += 1
                        }
                    case .ipCIDR6:
                        if let parsed = Self.parseIPv6CIDR(value) {
                            ipv6Trie.insert(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
                            ipRuleCount += 1
                        }
                    case .domainSuffix:
                        break
                    }
                }
            }
        }

        logger.debug("[DomainRouter] Loaded \(self.domainRuleCount) domain rules, \(self.ipRuleCount) IP rules, \(self.configurationMap.count) configurations")
    }

    // MARK: - Domain Matching (public API)

    /// Whether any user routing rules have been loaded.
    var hasRules: Bool {
        domainRuleCount > 0 || ipRuleCount > 0
    }

    /// Matches a domain against the suffix trie.
    func matchDomain(_ domain: String) -> RouteAction? {
        guard !domain.isEmpty else { return nil }
        return trieLookup(domain)
    }

    /// Matches an IP address against CIDR rules via binary trie.
    /// O(32) for IPv4, O(128) for IPv6 — constant regardless of rule count.
    func matchIP(_ ip: String) -> RouteAction? {
        guard !ip.isEmpty else { return nil }

        if ip.contains(":") {
            var addr = in6_addr()
            guard inet_pton(AF_INET6, ip, &addr) == 1 else { return nil }
            return withUnsafeBytes(of: &addr) { raw in
                ipv6Trie.lookup(raw.bindMemory(to: UInt8.self))
            }
        } else {
            guard let ip32 = Self.parseIPv4(ip) else { return nil }
            return ipv4Trie.lookup(ip32)
        }
    }

    /// Resolves a RouteAction to a ProxyConfiguration.
    /// Returns nil for .direct or when the configuration UUID is not found.
    func resolveConfiguration(action: RouteAction) -> ProxyConfiguration? {
        switch action {
        case .direct, .reject:
            return nil
        case .proxy(let id):
            return configurationMap[id]
        }
    }

    // MARK: - Suffix Trie (private)

    /// Inserts a suffix rule into the trie, overwriting any existing action.
    private func trieInsert(_ suffix: String, action: RouteAction) {
        let node = trieWalkOrCreate(suffix)
        node.userAction = action
    }

    /// Walks (or creates) the trie path for a domain suffix, returning the leaf node.
    private func trieWalkOrCreate(_ suffix: String) -> TrieNode {
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
        return node
    }

    /// Looks up a domain in the suffix trie. Returns the deepest action along the path.
    private func trieLookup(_ domain: String) -> RouteAction? {
        var node = trieRoot
        var deepestAction: RouteAction? = nil

        for label in domain.split(separator: ".").reversed() {
            guard let child = node.children[String(label)] else { break }
            node = child
            if let action = node.userAction {
                deepestAction = action
            }
        }

        return deepestAction
    }

    // MARK: - CIDR Parsing

    /// Accepts the new integer format and older string payloads during migration.
    private static func parseRuleType(_ rawValue: Any?) -> DomainRuleType? {
        if let rawValue = rawValue as? Int {
            return DomainRuleType(rawValue: rawValue)
        }
        guard let legacy = rawValue as? String else { return nil }
        switch legacy {
        case "ipCIDR":
            return .ipCIDR
        case "ipCIDR6":
            return .ipCIDR6
        case "domain", "domainKeyword", "domainSuffix":
            return .domainSuffix
        default:
            return nil
        }
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
// Bypass country rules are inserted first as .direct, then user rules overwrite.
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
