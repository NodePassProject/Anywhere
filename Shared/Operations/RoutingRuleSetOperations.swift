//
//  RoutingRuleSetOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct RoutingRuleSetOperations {
    let store: RoutingRuleSetStore
    let exporter: RoutingExportScheduler

    // MARK: - Assignments

    func updateAssignment(_ ruleSet: RoutingRuleSet, configurationId: String?) {
        store.updateAssignment(ruleSet, configurationId: configurationId)
        exporter.schedule()
    }

    func resetAssignments() {
        store.resetAssignments()
        exporter.schedule()
    }

    func setBypassCountryCode(_ code: String) {
        store.bypassCountryCode = code
        exporter.schedule()
    }

    // MARK: - Custom Rule Sets

    @discardableResult
    func addCustomRuleSet(name: String) -> CustomRoutingRuleSet {
        let ruleSet = store.addCustomRuleSet(name: name)
        exporter.schedule()
        return ruleSet
    }

    func addCustomRuleSet(_ ruleSet: CustomRoutingRuleSet, initialAssignment: String? = nil) {
        store.addCustomRuleSet(ruleSet, initialAssignment: initialAssignment)
        exporter.schedule()
    }

    func removeCustomRuleSet(_ id: UUID) {
        store.removeCustomRuleSet(id)
        exporter.schedule()
    }

    func updateCustomRuleSet(_ id: UUID, name: String? = nil, rules: [RoutingRule]? = nil, icons: (light: Data?, dark: Data?)? = nil) {
        store.updateCustomRuleSet(id, name: name, rules: rules, icons: icons)
        exporter.schedule()
    }

    func reorderCustomRuleSets(_ ordered: [CustomRoutingRuleSet]) {
        store.reorderCustomRuleSets(ordered)
        exporter.schedule()
    }

    // MARK: - Subscription Refresh

    func refresh(_ id: UUID) async throws {
        guard let url = store.customRuleSet(for: id)?.subscriptionURL else {
            throw CustomRoutingRuleSetRefreshError.missingSubscriptionURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw CustomRoutingRuleSetRefreshError.invalidStatusCode(http.statusCode)
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw CustomRoutingRuleSetRefreshError.undecodableBody
        }

        let parsed = RoutingRuleSetParser.parse(body)
        guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
            throw CustomRoutingRuleSetRefreshError.tooManyRules
        }

        guard let current = store.customRuleSet(for: id),
              current.rules != parsed.rules
                || current.iconLight != parsed.iconLight
                || current.iconDark != parsed.iconDark
        else { return }
        updateCustomRuleSet(id, rules: parsed.rules, icons: (parsed.iconLight, parsed.iconDark))
    }
}

nonisolated enum CustomRoutingRuleSetRefreshError: LocalizedError {
    case missingSubscriptionURL
    case invalidStatusCode(Int)
    case undecodableBody
    case tooManyRules

    var errorDescription: String? {
        switch self {
        case .missingSubscriptionURL:
            return "This rule set has no subscription URL."
        case .invalidStatusCode(let code):
            return "HTTP \(code)"
        case .undecodableBody:
            return String(localized: "Unknown content.")
        case .tooManyRules:
            return String(localized: "Rule set is too large.")
        }
    }
}
