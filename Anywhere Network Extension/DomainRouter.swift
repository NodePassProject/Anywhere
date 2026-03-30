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

    // Compiled IP CIDR rules (network & mask pre-computed at load time)
    private var ipv4CIDRRules: [(network: UInt32, mask: UInt32, action: RouteAction)] = []
    private var ipv6CIDRRules: [(network: [UInt8], prefixLen: Int, action: RouteAction)] = []
    private var bypassIPv4CIDRRules: [(network: UInt32, mask: UInt32)] = []
    private var bypassIPv6CIDRRules: [(network: [UInt8], prefixLen: Int)] = []

    // Proxy configurations for rule-assigned proxies
    private var configurationMap: [UUID: ProxyConfiguration] = [:]

    // Count for hasRules (user domain rules only)
    private var domainRuleCount = 0

    // MARK: - Loading

    /// Reads routing configuration from App Group UserDefaults and compiles rules.
    /// Clears all structures — must be called before ``loadBypassCountryRules()``.
    func loadRoutingConfiguration() {
        // Clear all domain matching structures
        trieRoot = TrieNode()
        domainRuleCount = 0

        ipv4CIDRRules.removeAll()
        ipv6CIDRRules.removeAll()
        bypassIPv4CIDRRules.removeAll()
        bypassIPv6CIDRRules.removeAll()
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
        var ipRuleCount = 0

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
                            ipv4CIDRRules.append((network: parsed.network, mask: parsed.mask, action: action))
                            ipRuleCount += 1
                        }
                    case .ipCIDR6:
                        if let parsed = Self.parseIPv6CIDR(value) {
                            ipv6CIDRRules.append((network: parsed.network, prefixLen: parsed.prefixLen, action: action))
                            ipRuleCount += 1
                        }
                    case .domainSuffix:
                        break
                    }
                }
            }
        }

        logger.debug("[DomainRouter] Loaded \(self.domainRuleCount) domain rules, \(ipRuleCount) IP rules, \(self.configurationMap.count) configurations")
    }

    /// Reads bypass country rules from App Group UserDefaults and adds them
    /// to the shared domain structures and IP rule tables.
    /// Must be called after ``loadRoutingConfiguration()``.
    func loadBypassCountryRules() {
        var domainRuleCount = 0
        var ipRuleCount = 0

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
                        bypassIPv4CIDRRules.append((network: parsed.network, mask: parsed.mask))
                        ipRuleCount += 1
                    }
                case .ipCIDR6:
                    if let parsed = Self.parseIPv6CIDR(value) {
                        bypassIPv6CIDRRules.append((network: parsed.network, prefixLen: parsed.prefixLen))
                        ipRuleCount += 1
                    }
                }
            }
        }

        if domainRuleCount > 0 || ipRuleCount > 0 {
            logger.debug("[DomainRouter] Loaded \(domainRuleCount) bypass country domain rules, \(ipRuleCount) IP rules")
        }
    }

    // MARK: - Domain Matching (public API)

    /// Whether any user routing rules have been loaded.
    var hasRules: Bool {
        domainRuleCount > 0 || !ipv4CIDRRules.isEmpty || !ipv6CIDRRules.isEmpty
    }

    /// Unified domain matching via the suffix trie.
    /// User suffix rules take absolute precedence over country bypass suffixes.
    func matchDomain(_ domain: String) -> DomainMatch {
        guard !domain.isEmpty else { return .none }
        let suffix = trieLookup(domain)
        return DomainMatch(userAction: suffix.userAction, isBypass: suffix.userAction == nil && suffix.isBypass)
    }

    /// Matches an IP address against user and bypass CIDR rules.
    /// User rules take absolute precedence over country bypass.
    func matchIP(_ ip: String) -> IPMatch {
        guard !ip.isEmpty else { return .none }

        if ip.contains(":") {
            // IPv6
            var addr = in6_addr()
            guard inet_pton(AF_INET6, ip, &addr) == 1 else { return .none }
            return withUnsafeBytes(of: &addr) { raw -> IPMatch in
                let bytes = raw.bindMemory(to: UInt8.self)
                guard bytes.count == 16 else { return .none }
                for rule in ipv6CIDRRules {
                    if Self.ipv6Matches(bytes: bytes, network: rule.network, prefixLen: rule.prefixLen) {
                        return IPMatch(userAction: rule.action, isBypass: false)
                    }
                }
                for rule in bypassIPv6CIDRRules {
                    if Self.ipv6Matches(bytes: bytes, network: rule.network, prefixLen: rule.prefixLen) {
                        return IPMatch(userAction: nil, isBypass: true)
                    }
                }
                return .none
            }
        } else {
            // IPv4
            guard let ip32 = Self.parseIPv4(ip) else { return .none }
            for rule in ipv4CIDRRules {
                if (ip32 & rule.mask) == rule.network {
                    return IPMatch(userAction: rule.action, isBypass: false)
                }
            }
            for rule in bypassIPv4CIDRRules {
                if (ip32 & rule.mask) == rule.network {
                    return IPMatch(userAction: nil, isBypass: true)
                }
            }
            return .none
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

    /// Parses "A.B.C.D/prefix" into (network, mask) with host bits zeroed.
    private static func parseIPv4CIDR(_ cidr: String) -> (network: UInt32, mask: UInt32)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 0, prefix <= 32,
              let ip = parseIPv4(String(parts[0])) else { return nil }
        let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
        return (network: ip & mask, mask: mask)
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

    /// Checks if IPv6 address bytes match a CIDR rule.
    private static func ipv6Matches(bytes: UnsafeBufferPointer<UInt8>, network: [UInt8], prefixLen: Int) -> Bool {
        var remaining = prefixLen
        for i in 0..<16 {
            if remaining <= 0 { return true }
            if remaining >= 8 {
                if bytes[i] != network[i] { return false }
                remaining -= 8
            } else {
                let mask = ~UInt8(0) << (8 - remaining)
                return (bytes[i] & mask) == network[i]
            }
        }
        return true
    }
}
