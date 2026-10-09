//
//  MITMRuleSetOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct MITMRuleSetOperations {
    let mitmRuleSetStore: MITMRuleSetStore
    let mitmExportScheduler: MITMExportScheduler

    func setEnabled(_ enabled: Bool) {
        mitmRuleSetStore.enabled = enabled
        mitmExportScheduler.schedule()
    }

    // MARK: - Rule Set CRUD

    func addRuleSet(_ ruleSet: MITMRuleSet) {
        mitmRuleSetStore.addRuleSet(ruleSet)
        mitmExportScheduler.schedule()
    }

    func updateRuleSet(_ id: UUID, domainSuffixes: [String], rules: [MITMRule]) {
        mitmRuleSetStore.updateRuleSet(id, domainSuffixes: domainSuffixes, rules: rules)
        mitmExportScheduler.schedule()
    }

    func setRuleSet(_ id: UUID, enabled: Bool) {
        mitmRuleSetStore.setRuleSet(id, enabled: enabled)
        mitmExportScheduler.schedule()
    }

    func setParameterValue(_ id: UUID, name: String, value: String) {
        mitmRuleSetStore.setParameterValue(id, name: name, value: value)
        mitmExportScheduler.schedule()
    }

    func removeRuleSets(atOffsets offsets: IndexSet) {
        mitmRuleSetStore.removeRuleSets(atOffsets: offsets)
        mitmExportScheduler.schedule()
    }

    func removeRuleSet(id: UUID) {
        mitmRuleSetStore.removeRuleSet(id: id)
        mitmExportScheduler.schedule()
    }

    func moveRuleSets(fromOffsets source: IndexSet, toOffset destination: Int) {
        mitmRuleSetStore.moveRuleSets(fromOffsets: source, toOffset: destination)
        mitmExportScheduler.schedule()
    }

    // MARK: - Subscription Refresh

    @discardableResult
    func refresh(id: UUID) async throws -> MITMRuleSet {
        guard let url = mitmRuleSetStore.ruleSet(id: id)?.subscriptionURL else {
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
        guard let updated = mitmRuleSetStore.applyRefreshedContent(
            domainSuffixes: parsed.domainSuffixes,
            rules: parsed.rules,
            parameters: parsed.parameters,
            iconLight: parsed.iconLight,
            iconDark: parsed.iconDark,
            to: id
        ) else {
            throw MITMRuleSetRefreshError.ruleSetRemoved
        }
        mitmExportScheduler.schedule()
        return updated
    }
}
