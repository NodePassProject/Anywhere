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

    // MARK: - Domain Match Result

    /// Result of a unified domain lookup covering both user rules and country bypass.
    struct DomainMatch {
        var userAction: RouteAction?
        var isBypass: Bool
        static let none = DomainMatch(userAction: nil, isBypass: false)
    }

    /// Result of a unified IP lookup covering both user rules and country bypass.
    struct IPMatch {
        var userAction: RouteAction?
        var isBypass: Bool
        static let none = IPMatch(userAction: nil, isBypass: false)
    }

    // MARK: - Suffix Trie (reverse-label)
    //
    // All domain filters are normalized to suffix rules.
    // Domains are split into labels and reversed: "www.google.com" → ["com","google","www"].
    // Walking the trie from root matches progressively more-specific suffixes.
    // Each node stores the deepest user action and/or a bypass flag at that suffix boundary.

    private final class TrieNode {
        var children: [String: TrieNode] = [:]
        var userAction: RouteAction?
        var isBypass: Bool = false
    }

    private var trieRoot = TrieNode()

    // MARK: - IP CIDR Binary Tries
    //
    // Binary tries for longest-prefix-match on IP addresses.
    // Both user actions and bypass flags are stored in a single trie per protocol,
    // mirroring the domain suffix trie design. User actions at the most-specific
    // (deepest) matching prefix take precedence over bypass flags.
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
    /// Clears all structures — must be called before ``loadBypassCountryRules()``.
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

        // Parse rules
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
                        trieInsert(lowered, userAction: action)
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
                            ipv4Trie.insert(network: parsed.network, prefixLen: parsed.prefixLen, userAction: action)
                            ipRuleCount += 1
                        }
                    case .ipCIDR6:
                        if let parsed = Self.parseIPv6CIDR(value) {
                            ipv6Trie.insert(network: parsed.network, prefixLen: parsed.prefixLen, userAction: action)
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

    /// Reads bypass country rules from App Group UserDefaults and adds them
    /// to the shared domain structures and IP rule tables.
    /// Must be called after ``loadRoutingConfiguration()``.
    func loadBypassCountryRules() {
        var domainRuleCount = 0
        var bypassIPRuleCount = 0

        if let data = AWCore.userDefaults.data(forKey: TunnelConstants.UserDefaultsKey.bypassCountryDomainRules),
           let rules = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
            for rule in rules {
                guard let type = Self.parseRuleType(rule["type"]),
                      let value = rule["value"] as? String else { continue }
                let lowered = value.lowercased()
                switch type {
                case .domainSuffix:
                    trieInsertBypass(lowered)
                    domainRuleCount += 1
                case .ipCIDR:
                    if let parsed = Self.parseIPv4CIDR(value) {
                        ipv4Trie.insertBypass(network: parsed.network, prefixLen: parsed.prefixLen)
                        bypassIPRuleCount += 1
                    }
                case .ipCIDR6:
                    if let parsed = Self.parseIPv6CIDR(value) {
                        ipv6Trie.insertBypass(network: parsed.network, prefixLen: parsed.prefixLen)
                        bypassIPRuleCount += 1
                    }
                }
            }
        }

        if domainRuleCount > 0 || bypassIPRuleCount > 0 {
            logger.debug("[DomainRouter] Loaded \(domainRuleCount) bypass country domain rules, \(bypassIPRuleCount) IP rules")
        }
    }

    // MARK: - Domain Matching (public API)

    /// Whether any user routing rules have been loaded.
    var hasRules: Bool {
        domainRuleCount > 0 || ipRuleCount > 0
    }

    /// Unified domain matching via the suffix trie.
    /// User suffix rules take absolute precedence over country bypass suffixes.
    func matchDomain(_ domain: String) -> DomainMatch {
        guard !domain.isEmpty else { return .none }
        let suffix = trieLookup(domain)
        return DomainMatch(userAction: suffix.userAction, isBypass: suffix.userAction == nil && suffix.isBypass)
    }

    /// Matches an IP address against user and bypass CIDR rules via binary trie.
    /// Longest-prefix user action takes precedence; bypass is a fallback.
    /// O(32) for IPv4, O(128) for IPv6 — constant regardless of rule count.
    func matchIP(_ ip: String) -> IPMatch {
        guard !ip.isEmpty else { return .none }

        if ip.contains(":") {
            var addr = in6_addr()
            guard inet_pton(AF_INET6, ip, &addr) == 1 else { return .none }
            let result = withUnsafeBytes(of: &addr) { raw in
                ipv6Trie.lookup(raw.bindMemory(to: UInt8.self))
            }
            return IPMatch(userAction: result.userAction,
                           isBypass: result.userAction == nil && result.isBypass)
        } else {
            guard let ip32 = Self.parseIPv4(ip) else { return .none }
            let result = ipv4Trie.lookup(ip32)
            return IPMatch(userAction: result.userAction,
                           isBypass: result.userAction == nil && result.isBypass)
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

    /// Inserts a user suffix rule into the trie.
    private func trieInsert(_ suffix: String, userAction: RouteAction) {
        let node = trieWalkOrCreate(suffix)
        node.userAction = userAction
    }

    /// Inserts a bypass suffix rule into the trie.
    private func trieInsertBypass(_ suffix: String) {
        let node = trieWalkOrCreate(suffix)
        node.isBypass = true
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

    /// Looks up a domain in the suffix trie. Returns the deepest user action and
    /// whether any bypass node was encountered along the path.
    private func trieLookup(_ domain: String) -> (userAction: RouteAction?, isBypass: Bool) {
        var node = trieRoot
        var deepestUserAction: RouteAction? = nil
        var foundBypass = false

        for label in domain.split(separator: ".").reversed() {
            guard let child = node.children[String(label)] else { break }
            node = child
            if let action = node.userAction {
                deepestUserAction = action
            }
            if node.isBypass {
                foundBypass = true
            }
        }

        return (deepestUserAction, foundBypass)
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
// Nodes along the path may carry a user action and/or bypass flag.
// Lookup walks all address bits, tracking the deepest match — O(W) where
// W = address width (32 for IPv4, 128 for IPv6), independent of rule count.

struct CIDRTrie {
    private final class Node {
        var left: Node?       // bit 0
        var right: Node?      // bit 1
        var userAction: RouteAction?
        var isBypass: Bool = false
    }

    private var root = Node()

    /// Inserts a user CIDR rule. More-specific prefixes override less-specific ones.
    mutating func insert(network: UInt32, prefixLen: Int, userAction: RouteAction) {
        let node = walkOrCreate(network, depth: prefixLen)
        node.userAction = userAction
    }

    /// Inserts a user CIDR rule from IPv6 network bytes.
    mutating func insert(network: [UInt8], prefixLen: Int, userAction: RouteAction) {
        let node = walkOrCreateIPv6(network, depth: prefixLen)
        node.userAction = userAction
    }

    /// Inserts a bypass CIDR rule for IPv4.
    mutating func insertBypass(network: UInt32, prefixLen: Int) {
        let node = walkOrCreate(network, depth: prefixLen)
        node.isBypass = true
    }

    /// Inserts a bypass CIDR rule from IPv6 network bytes.
    mutating func insertBypass(network: [UInt8], prefixLen: Int) {
        let node = walkOrCreateIPv6(network, depth: prefixLen)
        node.isBypass = true
    }

    /// Looks up an IPv4 address. Returns the deepest user action and whether
    /// any bypass node was found along the path. O(32).
    func lookup(_ ip: UInt32) -> (userAction: RouteAction?, isBypass: Bool) {
        var node = root
        var deepestUserAction: RouteAction? = node.userAction
        var foundBypass = node.isBypass

        for i in 0..<32 {
            let bit = (ip >> (31 - i)) & 1
            guard let next = bit == 0 ? node.left : node.right else { break }
            node = next
            if let action = node.userAction { deepestUserAction = action }
            if node.isBypass { foundBypass = true }
        }

        return (deepestUserAction, foundBypass)
    }

    /// Looks up an IPv6 address from a byte buffer. O(128).
    func lookup(_ bytes: UnsafeBufferPointer<UInt8>) -> (userAction: RouteAction?, isBypass: Bool) {
        var node = root
        var deepestUserAction: RouteAction? = node.userAction
        var foundBypass = node.isBypass

        for i in 0..<128 {
            let bit = (bytes[i >> 3] >> (7 - (i & 7))) & 1
            guard let next = bit == 0 ? node.left : node.right else { break }
            node = next
            if let action = node.userAction { deepestUserAction = action }
            if node.isBypass { foundBypass = true }
        }

        return (deepestUserAction, foundBypass)
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
