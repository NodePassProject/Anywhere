//
//  DomainRule.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

enum DomainRuleType: String, Codable {
    case domain         // DOMAIN — exact match
    case domainSuffix   // DOMAIN-SUFFIX — suffix match
    case domainKeyword  // DOMAIN-KEYWORD — substring match
    case ipCIDR         // IP-CIDR — IPv4 CIDR match
    case ipCIDR6        // IP-CIDR6 — IPv6 CIDR match
}

struct DomainRule: Codable {
    let type: DomainRuleType
    let value: String   // lowercased at parse time (domains), or CIDR notation (IPs)
}
