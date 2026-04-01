//
//  ServiceCatalog.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/1/26.
//

import Foundation
import os.log

private let serviceCatalogLogger = Logger(subsystem: "com.argsment.Anywhere", category: "ServiceCatalog")

struct ServiceCatalog: Decodable {
    let supportedServices: [String]
    let rulesByService: [String: [DomainRule]]

    func rules(for service: String) -> [DomainRule] {
        rulesByService[service] ?? []
    }

    static func load(bundle: Bundle = .main) -> ServiceCatalog {
        let resourceName = "Service"
        let resourceDescription = "\(resourceName).json"

        guard let url = bundle.url(forResource: resourceName, withExtension: "json") else {
            serviceCatalogLogger.error("[ServiceCatalog] Bundle resource '\(resourceDescription, privacy: .public)' not found")
            return .empty
        }
        guard let data = try? Data(contentsOf: url) else {
            serviceCatalogLogger.error("[ServiceCatalog] Failed to read '\(resourceDescription, privacy: .public)'")
            return .empty
        }
        guard let catalog = try? JSONDecoder().decode(Self.self, from: data) else {
            serviceCatalogLogger.error("[ServiceCatalog] Failed to decode '\(resourceDescription, privacy: .public)'")
            return .empty
        }
        return catalog
    }

    private static let empty = ServiceCatalog(
        supportedServices: [],
        rulesByService: [:]
    )
}
