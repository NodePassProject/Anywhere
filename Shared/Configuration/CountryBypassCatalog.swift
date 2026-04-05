//
//  CountryBypassCatalog.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

struct CountryBypassCatalog {
    let supportedCountryCodes: [String]
    private let languageToCountry: [String: String]

    static let shared = load()

    func suggestedCountryCode(for locale: Locale = .current) -> String? {
        guard let languageCode = locale.language.languageCode?.identifier else {
            return nil
        }
        return languageToCountry[languageCode]
    }

    func rules(for countryCode: String) -> [DomainRule] {
        RulesDatabase.shared.loadRules(for: countryCode)
    }

    private static func load() -> CountryBypassCatalog {
        CountryBypassCatalog(
            supportedCountryCodes: RulesDatabase.shared.loadStringArray("supportedCountryCodes"),
            languageToCountry: RulesDatabase.shared.loadStringDictionary("languageToCountry")
        )
    }
}
