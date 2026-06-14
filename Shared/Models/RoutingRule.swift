//
//  RoutingRule.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

enum RoutingRuleType: Int, Codable {
    case ipCIDR = 0     // IPv4 CIDR match
    case ipCIDR6 = 1    // IPv6 CIDR match
    case domainSuffix = 2   // Domain suffix match
    case domainKeyword = 3  // Domain substring match
}

extension RoutingRuleType {
    /// Localized human-readable name.
    var displayLabel: String {
        switch self {
        case .domainSuffix: return String(localized: "Domain Suffix")
        case .domainKeyword: return String(localized: "Domain Keyword")
        case .ipCIDR: return String(localized: "IPv4 CIDR")
        case .ipCIDR6: return String(localized: "IPv6 CIDR")
        }
    }

    /// SF Symbol representing the rule type.
    var iconName: String {
        switch self {
        case .domainSuffix: return "globe"
        case .domainKeyword: return "magnifyingglass"
        case .ipCIDR, .ipCIDR6: return "network"
        }
    }

    /// Canonicalizes a user-entered value: a bare IP gains a `/32` (IPv4) or `/128` (IPv6) suffix.
    func normalized(_ value: String) -> String {
        switch self {
        case .ipCIDR:
            if !value.contains("/") {
                return value + "/32"
            }
            return value
        case .ipCIDR6:
            if !value.contains("/") {
                return value + "/128"
            }
            return value
        case .domainSuffix, .domainKeyword:
            return value
        }
    }
}

struct RoutingRule: Codable, Equatable, Identifiable {
    let id = UUID()
    let type: RoutingRuleType
    let value: String

    private enum CodingKeys: String, CodingKey {
        case type, value
    }

    static func == (lhs: RoutingRule, rhs: RoutingRule) -> Bool {
        lhs.type == rhs.type && lhs.value == rhs.value
    }
}

/// On-disk layout of the routing payload the host writes and the Network
/// Extension reads.
///
/// All integers little-endian. Layout:
/// ```
/// magic       "ARB1"              4 bytes
/// configLen   UInt32              byte length of the configs JSON blob
/// configBytes [configLen]         {"<uuid>": {…}, …} (sortedKeys), or "{}"
/// entryCount  UInt32
/// entries     entryCount × Entry
///
/// Entry:
///   tier      UInt8               0 user · 1 adBlock · 2 builtIn · 3 bypass
///   action    UInt8               0 direct · 1 reject · 2 proxy
///   configId  [16]                raw UUID bytes — present iff action == proxy
///   ruleCount UInt32
///   rules     ruleCount × Rule
///
/// Rule:
///   type      UInt8               RoutingRuleType raw value
///   valueLen  UInt16              UTF-8 byte length
///   value     [valueLen]          UTF-8 domain/CIDR (folded to lowercase on read)
/// ```
enum RoutingBinaryFormat {
    static let magic: [UInt8] = [0x41, 0x52, 0x42, 0x31]  // "ARB1"

    enum Tier: UInt8 { case user = 0, adBlock = 1, builtIn = 2, bypass = 3 }
    enum Action: UInt8 { case direct = 0, reject = 1, proxy = 2 }
}
