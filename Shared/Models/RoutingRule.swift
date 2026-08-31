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
///   action    UInt8               0 fallback · 1 defaultProxy · 2 direct · 3 reject · 4 proxy
///   configId  [16]                raw UUID bytes — present iff action == proxy
///   ruleCount UInt32
///   rules     ruleCount × Rule
///
/// Rule:
///   type      UInt8               RoutingRuleType raw value
///   valueLen  UInt16              UTF-8 byte length
///   value     [valueLen]          UTF-8 domain/CIDR (folded to lowercase on read)
///
/// nameCount   UInt32              equals entryCount
/// names       nameCount × Name
///
/// Name:
///   valueLen  UInt16              UTF-8 byte length
///   value     [valueLen]          rule set name, truncated to 64 characters
/// ```
///
nonisolated enum RoutingBinaryFormat {
    enum Version { case v1, v2 }

    static let magic: [UInt8] = [0x41, 0x52, 0x42, 0x32]  // "ARB2"
    enum Tier: UInt8 { case adBlock = 0, builtIn = 1, user = 2, neutral = 3, bypass = 4 }
    enum Action: UInt8 {
        case fallback = 0
        case defaultProxy = 1
        case direct = 2
        case reject = 3
        case proxy = 4
    }
    
    static let legacyMagic: [UInt8] = [0x41, 0x52, 0x42, 0x31]  // "ARB1"
    enum LegacyTier: UInt8 {
        case user = 0, adBlock = 1, builtIn = 2, bypass = 3

        var current: Tier {
            switch self {
            case .user: .user
            case .adBlock: .adBlock
            case .builtIn: .builtIn
            case .bypass: .bypass
            }
        }
    }
    enum LegacyAction: UInt8 {
        case direct = 0, reject = 1, proxy = 2
    }
}
