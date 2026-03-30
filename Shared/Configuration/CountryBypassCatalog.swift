//
//  CountryBypassCatalog.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation
import os.log

private let countryBypassLogger = Logger(subsystem: "com.argsment.Anywhere", category: "CountryBypassCatalog")

struct CountryBypassCatalog: Decodable {
    let supportedCountryCodes: [String]
    let languageToCountry: [String: String]
    let rulesByCountryCode: [String: [DomainRule]]

    static let shared = load()

    func suggestedCountryCode(for locale: Locale = .current) -> String? {
        guard let languageCode = locale.language.languageCode?.identifier else {
            return nil
        }
        return languageToCountry[languageCode]
    }

    func rules(for countryCode: String) -> [DomainRule] {
        rulesByCountryCode[countryCode] ?? []
    }

    private static func load(bundle: Bundle = .main) -> CountryBypassCatalog {
        let resourceName = "Country"
        let resourceDescription = "\(resourceName).json"

        guard let url = bundle.url(forResource: resourceName, withExtension: "json") else {
            countryBypassLogger.error("[CountryBypassCatalog] Bundle resource '\(resourceDescription, privacy: .public)' not found")
            return .empty
        }
        guard let data = try? Data(contentsOf: url) else {
            countryBypassLogger.error("[CountryBypassCatalog] Failed to read '\(resourceDescription, privacy: .public)'")
            return .empty
        }
        guard let catalog = try? JSONDecoder().decode(Self.self, from: data) else {
            countryBypassLogger.error("[CountryBypassCatalog] Failed to decode '\(resourceDescription, privacy: .public)'")
            return .empty
        }
        return catalog
    }

    private static let empty = CountryBypassCatalog(
        supportedCountryCodes: [],
        languageToCountry: [:],
        rulesByCountryCode: [:]
    )
}
