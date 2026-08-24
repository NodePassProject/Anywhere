//
//  RoutingRule.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated enum RoutingRuleType: Int, Codable {
    case ipCIDR = 0
    case ipCIDR6 = 1
    case domainSuffix = 2
    case domainKeyword = 3
}

extension RoutingRuleType {
    var displayLabel: String {
        switch self {
        case .domainSuffix: return String(localized: "Domain Suffix")
        case .domainKeyword: return String(localized: "Domain Keyword")
        case .ipCIDR: return String(localized: "IPv4 CIDR")
        case .ipCIDR6: return String(localized: "IPv6 CIDR")
        }
    }
    
    var iconName: String {
        switch self {
        case .domainSuffix: return "globe"
        case .domainKeyword: return "magnifyingglass"
        case .ipCIDR, .ipCIDR6: return "network"
        }
    }
    
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

nonisolated struct RoutingRule: Codable, Equatable, Identifiable {
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
/// magic       "ARB2"              4 bytes
/// configLen   UInt32              byte length of the configs JSON blob
/// configBytes [configLen]         {"<uuid>": {…}, …} (sortedKeys), or "{}"
/// entryCount  UInt32
/// entries     entryCount × Entry
///
/// Entry:
///   tier      UInt8               0 adBlock · 1 builtIn · 2 user · 3 neutral · 4 bypass
///   action    UInt8               0 default · 1 direct · 2 reject · 3 proxy
///   configId  [16]                raw UUID bytes — present iff action == proxy
///   ruleCount UInt32
///   rules     ruleCount × Rule
///
/// Rule:
///   type      UInt8               RoutingRuleType raw value
///   valueLen  UInt16              UTF-8 byte length
///   value     [valueLen]          UTF-8 domain/CIDR (folded to lowercase on read)
/// ```
nonisolated enum RoutingBinaryFormat {
    static let magic: [UInt8] = [0x41, 0x52, 0x42, 0x32]  // "ARB2"

    enum Tier: UInt8 { case adBlock = 0, builtIn = 1, user = 2, neutral = 3, bypass = 4 }
    enum Action: UInt8 { case `default` = 0, direct = 1, reject = 2, proxy = 3 }
}
