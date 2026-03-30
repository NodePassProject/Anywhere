//
//  DomainRule.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

enum DomainRuleType: Int, Codable {
    case ipCIDR = 0     // IPv4 CIDR match
    case ipCIDR6 = 1    // IPv6 CIDR match
    case domainSuffix = 2   // Domain suffix match

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let rawValue = try? container.decode(Int.self),
           let type = Self(rawValue: rawValue) {
            self = type
            return
        }

        // Temporary compatibility path while older string-based payloads age out.
        let legacy = try container.decode(String.self)
        switch legacy {
        case "ipCIDR":
            self = .ipCIDR
        case "ipCIDR6":
            self = .ipCIDR6
        case "domain", "domainKeyword", "domainSuffix":
            self = .domainSuffix
        default:
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unknown domain rule type: \(legacy)")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

struct DomainRule: Codable {
    let type: DomainRuleType
    let value: String   // domain suffix or CIDR notation
}
