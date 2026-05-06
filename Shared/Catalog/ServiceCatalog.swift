//
//  ServiceCatalog.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/1/26.
//

import Foundation

struct ServiceCatalog {
    let supportedServices: [String]

    func rules(for service: String) -> [RoutingRule] {
        RoutingRulesDatabase.shared.loadRules(for: service)
    }

    static func load() -> ServiceCatalog {
        let services = RoutingRulesDatabase.shared.loadStringArray("supportedServices")
        return ServiceCatalog(supportedServices: services)
    }
}
