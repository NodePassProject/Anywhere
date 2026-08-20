//
//  MITMRuleSetOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct MITMRuleSetOperations {
    let store: MITMRuleSetStore

    func setEnabled(_ enabled: Bool) {
        store.enabled = enabled
    }

    // MARK: - Rule Set CRUD

    func addRuleSet(_ ruleSet: MITMRuleSet) { store.addRuleSet(ruleSet) }

    func updateRuleSet(_ id: UUID, domainSuffixes: [String], rules: [MITMRule]) {
        store.updateRuleSet(id, domainSuffixes: domainSuffixes, rules: rules)
    }

    func setRuleSet(_ id: UUID, enabled: Bool) {
        store.setRuleSet(id, enabled: enabled)
    }

    func setParameterValue(_ id: UUID, name: String, value: String) {
        store.setParameterValue(id, name: name, value: value)
    }

    func removeRuleSets(atOffsets offsets: IndexSet) { store.removeRuleSets(atOffsets: offsets) }
    func removeRuleSet(id: UUID) { store.removeRuleSet(id: id) }

    func moveRuleSets(fromOffsets source: IndexSet, toOffset destination: Int) {
        store.moveRuleSets(fromOffsets: source, toOffset: destination)
    }

    // MARK: - Subscription Refresh

    @discardableResult
    func refresh(id: UUID) async throws -> MITMRuleSet {
        guard let url = store.ruleSet(id: id)?.subscriptionURL else {
            throw MITMRuleSetRefreshError.missingSubscriptionURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw MITMRuleSetRefreshError.invalidStatusCode(http.statusCode)
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw MITMRuleSetRefreshError.undecodableBody
        }

        let parsed = MITMRuleSetParser.parse(body)
        guard parsed.rules.count <= MITMRuleSet.maxRuleCount else {
            throw MITMRuleSetRefreshError.tooManyRules
        }
        guard let updated = store.applyRefreshedContent(
            domainSuffixes: parsed.domainSuffixes,
            rules: parsed.rules,
            parameters: parsed.parameters,
            iconLight: parsed.iconLight,
            iconDark: parsed.iconDark,
            to: id
        ) else {
            throw MITMRuleSetRefreshError.ruleSetRemoved
        }
        return updated
    }
}
