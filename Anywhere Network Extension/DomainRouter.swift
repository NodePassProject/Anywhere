//
//  DomainRouter.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "DomainRouter")

enum RouteAction {
    case direct
    case reject
    case proxy(UUID)
}

class DomainRouter {

    // Compiled domain rules
    private var exactDomains: [String: RouteAction] = [:]
    private var suffixRules: [(suffix: String, dotSuffix: String, action: RouteAction)] = []
    private var keywordRules: [(keyword: String, action: RouteAction)] = []

    // Compiled IP CIDR rules (network & mask pre-computed at load time)
    private var ipv4CIDRRules: [(network: UInt32, mask: UInt32, action: RouteAction)] = []
    private var ipv6CIDRRules: [(network: [UInt8], prefixLen: Int, action: RouteAction)] = []

    // Proxy configurations for rule-assigned proxies
    private var configurationMap: [UUID: ProxyConfiguration] = [:]

    /// Reads routing configuration from App Group UserDefaults and compiles rules.
    func loadRoutingConfiguration() {
        exactDomains.removeAll()
        suffixRules.removeAll()
        keywordRules.removeAll()
        ipv4CIDRRules.removeAll()
        ipv6CIDRRules.removeAll()
        configurationMap.removeAll()

        guard let data = AWCore.userDefaults.data(forKey: "routingData"),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            logger.info("[DomainRouter] No routing data available")
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
            logger.warning("[DomainRouter] routing.json has no 'rules' array")
            return
        }
        var ruleCount = 0

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
                        ruleCount += 1
                    case "domainSuffix":
                        suffixRules.append((suffix: lowered, dotSuffix: "." + lowered, action: action))
                        ruleCount += 1
                    case "domainKeyword":
                        keywordRules.append((keyword: lowered, action: action))
                        ruleCount += 1
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

        logger.info("[DomainRouter] Loaded \(ruleCount) domain rules, \(ipRuleCount) IP rules, \(self.configurationMap.count) configurations")
    }

    /// Whether any routing rules have been loaded.
    var hasRules: Bool {
        !exactDomains.isEmpty || !suffixRules.isEmpty || !keywordRules.isEmpty
            || !ipv4CIDRRules.isEmpty || !ipv6CIDRRules.isEmpty
    }

    /// Matches a domain against routing rules. Returns nil if no rule matches.
    /// The domain must already be lowercased (all rule values are stored lowercased at load time).
    func matchDomain(_ domain: String) -> RouteAction? {
        guard !domain.isEmpty else { return nil }

        // 1. Exact match (O(1))
        if let action = exactDomains[domain] {
            return action
        }

        // 2. Suffix match
        for rule in suffixRules {
            if domain == rule.suffix || domain.hasSuffix(rule.dotSuffix) {
                return rule.action
            }
        }

        // 3. Keyword match
        for rule in keywordRules {
            if domain.contains(rule.keyword) {
                return rule.action
            }
        }

        return nil
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
