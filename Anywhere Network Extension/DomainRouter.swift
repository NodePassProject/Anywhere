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

    // MARK: - Suffix Trie (reverse-label)
    //
    // Domains are split into labels and reversed: "www.google.com" → ["com","google","www"].
    // Walking the trie from root matches progressively more-specific suffixes.
    // Each node stores the deepest user action and/or a bypass flag at that suffix boundary.

    private final class TrieNode {
        var children: [String: TrieNode] = [:]
        var userAction: RouteAction?
        var isBypass: Bool = false
    }

    private var trieRoot = TrieNode()

    // Exact domain matches (O(1) hash lookup, checked before the trie)
    private var exactDomains: [String: RouteAction] = [:]
    private var bypassExactDomains: Set<String> = []

    // MARK: - Aho-Corasick Keyword Matcher
    //
    // All keyword patterns (user + bypass) are compiled into a single automaton.
    // Matching scans the domain string once, O(m), and reports any keyword hit.

    private struct ACState {
        var goto: [UInt8: Int] = [:]
        var failure: Int = 0
        var userAction: RouteAction?
        var isBypass: Bool = false
        var outputLink: Int = -1   // nearest match state reachable via failure chain
    }

    private var acStates: [ACState] = [ACState()]   // state 0 = root
    private var acBuilt = false

    // Compiled IP CIDR rules (network & mask pre-computed at load time)
    private var ipv4CIDRRules: [(network: UInt32, mask: UInt32, action: RouteAction)] = []
    private var ipv6CIDRRules: [(network: [UInt8], prefixLen: Int, action: RouteAction)] = []

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
        exactDomains.removeAll()
        bypassExactDomains.removeAll()
        acStates = [ACState()]
        acBuilt = false
        domainRuleCount = 0

        ipv4CIDRRules.removeAll()
        ipv6CIDRRules.removeAll()
        configurationMap.removeAll()

        guard let data = AWCore.userDefaults.data(forKey: "routingData"),
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
            if let domainRules = rule["domainRules"] as? [[String: String]] {
                for dr in domainRules {
                    guard let typeStr = dr["type"], let value = dr["value"] else { continue }
                    let lowered = value.lowercased()

                    switch typeStr {
                    case "domain":
                        exactDomains[lowered] = action
                        domainRuleCount += 1
                    case "domainSuffix":
                        trieInsert(lowered, userAction: action)
                        domainRuleCount += 1
                    case "domainKeyword":
                        acAddPattern(lowered, userAction: action)
                        domainRuleCount += 1
                    default:
                        break
                    }
                }
            }

            // IP CIDR rules
            if let ipRules = rule["ipRules"] as? [[String: String]] {
                for ir in ipRules {
                    guard let typeStr = ir["type"], let value = ir["value"] else { continue }

                    switch typeStr {
                    case "ipCIDR":
                        if let parsed = Self.parseIPv4CIDR(value) {
                            ipv4CIDRRules.append((network: parsed.network, mask: parsed.mask, action: action))
                            ipRuleCount += 1
                        }
                    case "ipCIDR6":
                        if let parsed = Self.parseIPv6CIDR(value) {
                            ipv6CIDRRules.append((network: parsed.network, prefixLen: parsed.prefixLen, action: action))
                            ipRuleCount += 1
                        }
                    default:
                        break
                    }
                }
            }
        }

        logger.debug("[DomainRouter] Loaded \(self.domainRuleCount) domain rules, \(ipRuleCount) IP rules, \(self.configurationMap.count) configurations")
    }

    /// Reads bypass country domain rules from App Group UserDefaults and adds them
    /// to the shared trie / Aho-Corasick structures. Builds the keyword automaton.
    /// Must be called after ``loadRoutingConfiguration()``.
    func loadBypassCountryRules() {
        var count = 0

        if let data = AWCore.userDefaults.data(forKey: "bypassCountryDomainRules"),
           let rules = try? JSONSerialization.jsonObject(with: data) as? [[String: String]] {
            for rule in rules {
                guard let typeStr = rule["type"], let value = rule["value"] else { continue }
                let lowered = value.lowercased()
                switch typeStr {
                case "domain":
                    bypassExactDomains.insert(lowered)
                    count += 1
                case "domainSuffix":
                    trieInsertBypass(lowered)
                    count += 1
                case "domainKeyword":
                    acAddPattern(lowered, isBypass: true)
                    count += 1
                default:
                    break
                }
            }
        }

        // Build the Aho-Corasick automaton after all patterns (user + bypass) are inserted
        acBuild()

        if count > 0 {
            logger.debug("[DomainRouter] Loaded \(count) bypass country domain rules")
        }
    }

    // MARK: - Domain Matching (public API)

    /// Whether any user routing rules have been loaded.
    var hasRules: Bool {
        domainRuleCount > 0 || !ipv4CIDRRules.isEmpty || !ipv6CIDRRules.isEmpty
    }

    /// Unified domain matching: checks exact → suffix trie → Aho-Corasick keywords.
    /// User rules take absolute precedence over country bypass.
    func matchDomain(_ domain: String) -> DomainMatch {
        guard !domain.isEmpty else { return .none }

        // 1. Exact match (O(1) hash lookup)
        if let action = exactDomains[domain] {
            return DomainMatch(userAction: action, isBypass: false)
        }

        // 2. Suffix match via reverse-label trie (O(k), k = label count ≈ 2-4)
        let suffix = trieLookup(domain)
        if let action = suffix.userAction {
            return DomainMatch(userAction: action, isBypass: false)
        }

        // 3. Keyword match via Aho-Corasick (O(m), m = domain length)
        let keyword = acMatch(domain)
        if let action = keyword.userAction {
            return DomainMatch(userAction: action, isBypass: false)
        }

        // 4. No user rule matched — check bypass from all three sources
        let isBypass = bypassExactDomains.contains(domain) || suffix.isBypass || keyword.isBypass
        return DomainMatch(userAction: nil, isBypass: isBypass)
    }

    /// Matches an IP address against IP CIDR rules. Returns nil if no rule matches.
    func matchIP(_ ip: String) -> RouteAction? {
        guard !ip.isEmpty else { return nil }

        if ip.contains(":") {
            // IPv6
            var addr = in6_addr()
            guard inet_pton(AF_INET6, ip, &addr) == 1 else { return nil }
            return withUnsafeBytes(of: &addr) { raw -> RouteAction? in
                let bytes = raw.bindMemory(to: UInt8.self)
                guard bytes.count == 16 else { return nil }
                for rule in ipv6CIDRRules {
                    if Self.ipv6Matches(bytes: bytes, network: rule.network, prefixLen: rule.prefixLen) {
                        return rule.action
                    }
                }
                return nil
            }
        } else {
            // IPv4
            guard let ip32 = Self.parseIPv4(ip) else { return nil }
            for rule in ipv4CIDRRules {
                if (ip32 & rule.mask) == rule.network {
                    return rule.action
                }
            }
            return nil
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

    // MARK: - Aho-Corasick (private)

    /// Inserts a keyword pattern into the automaton (before ``acBuild()``).
    /// Set `userAction` for user rules, `isBypass` for country bypass, or both.
    private func acAddPattern(_ pattern: String, userAction: RouteAction? = nil, isBypass: Bool = false) {
        var state = 0
        for byte in pattern.utf8 {
            if let next = acStates[state].goto[byte] {
                state = next
            } else {
                let newState = acStates.count
                acStates.append(ACState())
                acStates[state].goto[byte] = newState
                state = newState
            }
        }
        if let action = userAction {
            acStates[state].userAction = action
        }
        if isBypass {
            acStates[state].isBypass = true
        }
    }

    /// Computes failure links and output links (BFS). Must be called once after
    /// all patterns have been inserted.
    private func acBuild() {
        guard acStates.count > 1 else {
            acBuilt = true
            return
        }

        var queue: [Int] = []

        // Depth-1 states: failure → root
        for (_, nextState) in acStates[0].goto {
            acStates[nextState].failure = 0
            acStates[nextState].outputLink = -1
            queue.append(nextState)
        }

        var head = 0
        while head < queue.count {
            let current = queue[head]
            head += 1

            for (byte, nextState) in acStates[current].goto {
                // Compute failure link for nextState
                var f = acStates[current].failure
                while f != 0 && acStates[f].goto[byte] == nil {
                    f = acStates[f].failure
                }
                let failTarget = acStates[f].goto[byte] ?? 0
                acStates[nextState].failure = (failTarget == nextState) ? 0 : failTarget

                // Compute output link (nearest match state via failure chain)
                let fs = acStates[nextState].failure
                if acStates[fs].userAction != nil || acStates[fs].isBypass {
                    acStates[nextState].outputLink = fs
                } else {
                    acStates[nextState].outputLink = acStates[fs].outputLink
                }

                queue.append(nextState)
            }
        }
        acBuilt = true
    }

    /// Scans the domain through the automaton and returns the first user keyword
    /// action found and whether any bypass keyword matched.
    private func acMatch(_ domain: String) -> (userAction: RouteAction?, isBypass: Bool) {
        guard acBuilt, acStates.count > 1 else { return (nil, false) }

        var state = 0
        var resultUserAction: RouteAction? = nil
        var resultBypass = false

        for byte in domain.utf8 {
            // Follow failure links until we find a goto or reach root
            while state != 0 && acStates[state].goto[byte] == nil {
                state = acStates[state].failure
            }
            state = acStates[state].goto[byte] ?? 0

            // Check this state and all output-linked states for matches
            var check = state
            while check > 0 {
                if resultUserAction == nil, let action = acStates[check].userAction {
                    resultUserAction = action
                }
                if !resultBypass && acStates[check].isBypass {
                    resultBypass = true
                }
                if resultUserAction != nil && resultBypass { break }
                check = acStates[check].outputLink
                guard check > 0 else { break }
            }

            if resultUserAction != nil && resultBypass { break }
        }

        return (resultUserAction, resultBypass)
    }

    // MARK: - CIDR Parsing

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
