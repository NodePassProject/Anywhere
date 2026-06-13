//
//  MITMRuleSetStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
final class MITMRuleSetStore {
    static let shared = MITMRuleSetStore()

    var enabled: Bool {
        didSet {
            guard enabled != oldValue else { return }
            save()
        }
    }

    private(set) var ruleSets: [MITMRuleSet]
    private var tombstones: [MITMRuleSet] = []

    private init() {
        let snapshot = MITMSnapshot.load()
        self.enabled = snapshot.enabled
        let split = Tombstone.split(snapshot.ruleSets)
        self.ruleSets = split.live
        self.tombstones = split.tombstones
    }

    func reload() {
        let snapshot = MITMSnapshot.load()
        enabled = snapshot.enabled
        let split = Tombstone.split(snapshot.ruleSets)
        ruleSets = split.live
        tombstones = split.tombstones
    }

    // MARK: - Rule set CRUD

    func addRuleSet(_ ruleSet: MITMRuleSet) {
        tombstones.removeAll { $0.id == ruleSet.id }
        ruleSets.append(ruleSet)
        save()
    }

    func updateRuleSet(_ ruleSet: MITMRuleSet) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        ruleSets[index] = ruleSet
        save()
    }

    /// Flips one set's enabled flag and persists immediately — covers read-only
    /// subscribed sets, which never go through the draft-based editor.
    func setRuleSet(_ id: UUID, enabled: Bool) {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }) else { return }
        guard ruleSets[index].enabled != enabled else { return }
        ruleSets[index].enabled = enabled
        save()
    }

    func removeRuleSets(atOffsets offsets: IndexSet) {
        recordTombstones(offsets.map { ruleSets[$0] })
        ruleSets.remove(atOffsets: offsets)
        save()
    }

    func removeRuleSet(id: UUID) {
        if let removed = ruleSets.first(where: { $0.id == id }) {
            recordTombstones([removed])
        }
        ruleSets.removeAll { $0.id == id }
        save()
    }

    func moveRuleSets(fromOffsets source: IndexSet, toOffset destination: Int) {
        ruleSets.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Per-set rule CRUD

    func ruleSet(id: UUID) -> MITMRuleSet? {
        ruleSets.first(where: { $0.id == id })
    }

    func addRule(_ rule: MITMRule, toRuleSet ruleSetID: UUID) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        // Cap like the subscription path: every rule is recompiled on reload and
        // evaluated per request head, so an unbounded set stalls the data path.
        guard ruleSets[index].rules.count < MITMRuleSet.maxRuleCount else { return }
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

    /// Fetches and parses the subscription as `.amrs`, replacing the set's
    /// suffixes and rules in place; `id` and `name` are preserved so the
    /// script-store scope and any rename stick. Returns the updated set.
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
        // Re-resolve after the await: a delete/move during the fetch could have
        // shifted or removed the set, leaving the pre-await `index` stale.
        guard let writeIndex = ruleSets.firstIndex(where: { $0.id == id }) else {
            throw MITMRuleSetRefreshError.ruleSetRemoved
        }
        ruleSets[writeIndex].domainSuffixes = parsed.domainSuffixes
        ruleSets[writeIndex].rules = parsed.rules
        save()
        return ruleSets[writeIndex]
    }

    // MARK: - Persistence
    
    private func recordTombstones(_ removed: [MITMRuleSet]) {
        guard !removed.isEmpty else { return }
        let now = Date.now
        let ids = Set(removed.map { $0.id })
        tombstones.removeAll { ids.contains($0.id) }
        for item in removed {
            var tomb = item
            tomb.deletedAt = now
            tombstones.append(tomb)
        }
    }

    private func save() {
        MITMSnapshot(enabled: enabled, ruleSets: ruleSets + tombstones).save()
    }
}

enum MITMRuleSetRefreshError: LocalizedError {
    case missingSubscriptionURL
    case invalidStatusCode(Int)
    case undecodableBody
    case tooManyRules
    case ruleSetRemoved

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
        case .ruleSetRemoved:
            return String(localized: "Rule set was removed.")
        }
    }
}
