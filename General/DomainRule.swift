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
}

struct DomainRule: Codable {
    let type: DomainRuleType
    let value: String   // lowercased at parse time
}
