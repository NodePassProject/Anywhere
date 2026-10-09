//
//  Module.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation

nonisolated struct ModuleRoutingRuleSet: Codable, Equatable, Identifiable {
    static let maxRuleCount = CustomRoutingRuleSet.maxRuleCount

    var id: UUID
    var name: String
    var rules: [RoutingRule]

    init(id: UUID = UUID(), name: String, rules: [RoutingRule] = []) {
        self.id = id
        self.name = name
        self.rules = rules
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, rules
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        rules = try container.decodeSkippingInvalid([RoutingRule].self, forKey: .rules)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(rules, forKey: .rules)
    }
}

nonisolated struct ModuleMITMRuleSet: Codable, Equatable, Identifiable {
    static let maxRuleCount = MITMRuleSet.maxRuleCount
    static let maxParameterCount = MITMRuleSet.maxParameterCount

    var id: UUID
    var name: String
    var enabled: Bool
    var domainSuffixes: [String]
    var rules: [MITMRule]
    var parameters: [MITMParameter]
    var parameterValues: [String: String]

    init(
        id: UUID = UUID(),
        name: String,
        enabled: Bool = true,
        domainSuffixes: [String] = [],
        rules: [MITMRule] = [],
        parameters: [MITMParameter] = [],
        parameterValues: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.domainSuffixes = domainSuffixes
        self.rules = rules
        self.parameters = parameters
        self.parameterValues = parameterValues
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, enabled, domainSuffixes, rules, parameters, parameterValues
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        domainSuffixes = try c.decodeIfPresent([String].self, forKey: .domainSuffixes) ?? []
        rules = try c.decodeSkippingInvalid([MITMRule].self, forKey: .rules)
        parameters = (try? c.decodeSkippingInvalid([MITMParameter].self, forKey: .parameters)) ?? []
        parameterValues = (try? c.decodeIfPresent([String: String].self, forKey: .parameterValues)) ?? [:]
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(enabled, forKey: .enabled)
        try c.encode(domainSuffixes, forKey: .domainSuffixes)
        try c.encode(rules, forKey: .rules)
        if !parameters.isEmpty { try c.encode(parameters, forKey: .parameters) }
        if !parameterValues.isEmpty { try c.encode(parameterValues, forKey: .parameterValues) }
    }
    
    func asMITMRuleSet(name: String? = nil, enabled: Bool? = nil) -> MITMRuleSet {
        MITMRuleSet(
            id: id,
            name: name ?? self.name,
            enabled: enabled ?? self.enabled,
            domainSuffixes: domainSuffixes,
            rules: rules,
            parameters: parameters,
            parameterValues: parameterValues
        )
    }
}

nonisolated struct Module: Codable, Equatable, Identifiable, SoftDeletable {
    static let maxRuleSetCount = 64
    static let maxIconBytes = 64 * 1024
    static let maxEncodedBytes = SyncStore.maxSyncedPayloadBytes

    let id: UUID
    var name: String
    var enabled: Bool
    var subscriptionURL: URL?
    var iconLight: Data?
    var iconDark: Data?
    var routingRuleSets: [ModuleRoutingRuleSet]
    var mitmRuleSets: [ModuleMITMRuleSet]
    var updatedAt: Date
    var deletedAt: Date? = nil

    init(
        id: UUID = UUID(),
        name: String,
        enabled: Bool = true,
        subscriptionURL: URL? = nil,
        iconLight: Data? = nil,
        iconDark: Data? = nil,
        routingRuleSets: [ModuleRoutingRuleSet] = [],
        mitmRuleSets: [ModuleMITMRuleSet] = [],
        updatedAt: Date = .now
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.subscriptionURL = subscriptionURL
        self.iconLight = iconLight
        self.iconDark = iconDark
        self.routingRuleSets = routingRuleSets
        self.mitmRuleSets = mitmRuleSets
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, enabled, subscriptionURL, iconLight, iconDark
        case routingRuleSets, mitmRuleSets, updatedAt, deletedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        subscriptionURL = try c.decodeIfPresent(URL.self, forKey: .subscriptionURL)
        iconLight = try c.decodeIfPresent(Data.self, forKey: .iconLight)
        iconDark = try c.decodeIfPresent(Data.self, forKey: .iconDark)
        routingRuleSets = (try? c.decodeSkippingInvalid([ModuleRoutingRuleSet].self, forKey: .routingRuleSets)) ?? []
        mitmRuleSets = (try? c.decodeSkippingInvalid([ModuleMITMRuleSet].self, forKey: .mitmRuleSets)) ?? []
        deletedAt = try c.decodeIfPresent(Date.self, forKey: .deletedAt)
        updatedAt = try c.decodeIfPresent(Date.self, forKey: .updatedAt) ?? deletedAt ?? .distantPast
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(enabled, forKey: .enabled)
        try c.encodeIfPresent(subscriptionURL, forKey: .subscriptionURL)
        try c.encodeIfPresent(iconLight, forKey: .iconLight)
        try c.encodeIfPresent(iconDark, forKey: .iconDark)
        try c.encode(routingRuleSets, forKey: .routingRuleSets)
        try c.encode(mitmRuleSets, forKey: .mitmRuleSets)
        try c.encode(updatedAt, forKey: .updatedAt)
        try c.encodeIfPresent(deletedAt, forKey: .deletedAt)
    }

    var isSubscribed: Bool { subscriptionURL != nil }

    var ruleSetCount: Int { routingRuleSets.count + mitmRuleSets.count }

    func routingRuleSet(id: UUID) -> ModuleRoutingRuleSet? {
        routingRuleSets.first { $0.id == id }
    }

    func mitmRuleSet(id: UUID) -> ModuleMITMRuleSet? {
        mitmRuleSets.first { $0.id == id }
    }
    
    func qualifiedName(for ruleSetName: String) -> String {
        "\(name) · \(ruleSetName)"
    }

    static func validSubscriptionURL(from rawValue: String) -> URL? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.path.lowercased().hasSuffix(".amod") else { return nil }
        return url
    }
    
    func encodedByteCount() -> Int? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try? encoder.encode(self).count
    }
    
    func validateLimits() throws(ModuleImportError) {
        guard ruleSetCount > 0 else { throw .empty }
        guard ruleSetCount <= Self.maxRuleSetCount else { throw .tooLarge }
        for ruleSet in routingRuleSets where ruleSet.rules.count > ModuleRoutingRuleSet.maxRuleCount {
            throw .tooLarge
        }
        for ruleSet in mitmRuleSets {
            guard ruleSet.rules.count <= ModuleMITMRuleSet.maxRuleCount,
                  ruleSet.parameters.count <= ModuleMITMRuleSet.maxParameterCount else { throw .tooLarge }
        }
        guard let bytes = encodedByteCount(), bytes <= Self.maxEncodedBytes else { throw .tooLarge }
    }
}

nonisolated struct ModuleContent {
    var name: String
    var iconLight: Data?
    var iconDark: Data?
    var routingRuleSets: [ModuleRoutingRuleSet]
    var routingSeeds: [UUID: String]
    var mitmRuleSets: [ModuleMITMRuleSet]

    init(
        name: String = "",
        iconLight: Data? = nil,
        iconDark: Data? = nil,
        routingRuleSets: [ModuleRoutingRuleSet] = [],
        routingSeeds: [UUID: String] = [:],
        mitmRuleSets: [ModuleMITMRuleSet] = []
    ) {
        self.name = name
        self.iconLight = iconLight
        self.iconDark = iconDark
        self.routingRuleSets = routingRuleSets
        self.routingSeeds = routingSeeds
        self.mitmRuleSets = mitmRuleSets
    }

    var ruleSetCount: Int { routingRuleSets.count + mitmRuleSets.count }

    func makeModule(name: String, subscriptionURL: URL? = nil) -> Module {
        Module(
            name: name,
            subscriptionURL: subscriptionURL,
            iconLight: iconLight,
            iconDark: iconDark,
            routingRuleSets: routingRuleSets,
            mitmRuleSets: mitmRuleSets
        )
    }
}

nonisolated enum ModuleImportError: LocalizedError {
    case missingSubscriptionURL
    case invalidStatusCode(Int)
    case undecodableBody
    case empty
    case tooLarge
    case moduleRemoved

    var errorDescription: String? {
        switch self {
        case .missingSubscriptionURL:
            return "This module has no subscription URL."
        case .invalidStatusCode(let code):
            return "HTTP \(code)"
        case .undecodableBody:
            return String(localized: "Unknown content.")
        case .empty:
            return String(localized: "Module contains no rule sets.")
        case .tooLarge:
            return String(localized: "Module is too large.")
        case .moduleRemoved:
            return String(localized: "Module was removed.")
        }
    }
}
