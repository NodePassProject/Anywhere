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
