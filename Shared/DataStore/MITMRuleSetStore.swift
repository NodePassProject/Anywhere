//
//  MITMRuleSetStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import Combine
import SwiftUI

@MainActor
final class MITMRuleSetStore: ObservableObject {
    static let shared = MITMRuleSetStore()

    @Published var enabled: Bool {
        didSet {
            guard enabled != oldValue else { return }
            save()
        }
    }

    @Published private(set) var ruleSets: [MITMRuleSet]

    private init() {
        let snapshot = MITMSnapshot.load()
        self.enabled = snapshot.enabled
        self.ruleSets = snapshot.ruleSets
    }

    // MARK: - Rule set CRUD

    func addRuleSet(_ ruleSet: MITMRuleSet) {
        ruleSets.append(ruleSet)
        save()
    }

    func updateRuleSet(_ ruleSet: MITMRuleSet) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        ruleSets[index] = ruleSet
        save()
    }

    /// Flips a single set's ``MITMRuleSet/enabled`` flag and persists, so the
    /// toggle takes effect immediately — including for read-only subscribed
    /// sets, which never go through the draft-based editor's `save()`.
    func setRuleSet(_ id: UUID, enabled: Bool) {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }) else { return }
        guard ruleSets[index].enabled != enabled else { return }
        ruleSets[index].enabled = enabled
        save()
    }

    func removeRuleSets(atOffsets offsets: IndexSet) {
        ruleSets.remove(atOffsets: offsets)
        save()
    }

    func removeRuleSet(id: UUID) {
        ruleSets.removeAll { $0.id == id }
        save()
    }

    func moveRuleSets(fromOffsets source: IndexSet, toOffset destination: Int) {
        ruleSets.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Per-set rule CRUD

    /// Looks up a rule set by id. Returns nil if it was removed after the
    /// caller last read it, such as while an editor sheet is still on screen.
    func ruleSet(id: UUID) -> MITMRuleSet? {
        ruleSets.first(where: { $0.id == id })
    }

    func addRule(_ rule: MITMRule, toRuleSet ruleSetID: UUID) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        ruleSets[index].rules.append(rule)
        save()
    }

    func updateRule(_ rule: MITMRule, inRuleSet ruleSetID: UUID) {
        guard let setIndex = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        guard let ruleIndex = ruleSets[setIndex].rules.firstIndex(where: { $0.id == rule.id }) else {
            return
        }
        ruleSets[setIndex].rules[ruleIndex] = rule
        save()
    }

    func removeRules(atOffsets offsets: IndexSet, inRuleSet ruleSetID: UUID) {
        guard let setIndex = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        ruleSets[setIndex].rules.remove(atOffsets: offsets)
        save()
    }

    func moveRules(
        fromOffsets source: IndexSet,
        toOffset destination: Int,
        inRuleSet ruleSetID: UUID
    ) {
        guard let setIndex = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        ruleSets[setIndex].rules.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Subscription

    /// Fetches the subscription URL, parses the response as an `.amrs` rule
    /// set, and replaces the subscribed set's domain suffixes, rewrite
    /// target, and rules in place. The set's ``MITMRuleSet/id`` (its
    /// ``MITMScriptStore`` scope key) and user-given ``MITMRuleSet/name``
    /// are preserved across refreshes so the scope and any rename stick.
    /// Returns the updated set so callers can refresh their view state
    /// without a second main-actor lookup.
    @discardableResult
    func refreshRuleSet(id: UUID) async throws -> MITMRuleSet {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }),
              let url = ruleSets[index].subscriptionURL else {
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
        ruleSets[index].domainSuffixes = parsed.domainSuffixes
        ruleSets[index].rewriteTarget = parsed.rewriteTarget
        ruleSets[index].rules = parsed.rules
        save()
        return ruleSets[index]
    }

    // MARK: - Persistence

    private func save() {
        MITMSnapshot(enabled: enabled, ruleSets: ruleSets).save()
    }
}

enum MITMRuleSetRefreshError: LocalizedError {
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
