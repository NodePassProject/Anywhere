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
    case domainKeyword = 3  // Domain substring match
}

struct DomainRule: Codable, Equatable {
    let type: DomainRuleType
    let value: String   // domain suffix or CIDR notation
}
