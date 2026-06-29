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
    
    @ObservationIgnored private var loadedBlob: Data?

    private init() {
        let data = JSONBlobStore.shared.load(.mitm)
        loadedBlob = data
        let snapshot = MITMSnapshot.decode(from: data)
        self.enabled = snapshot.enabled
        let split = Tombstone.split(snapshot.ruleSets)
        self.ruleSets = split.live
        self.tombstones = split.tombstones
        // Ensure the NE-facing binary exists on first launch and post-migration,
        // before any edit. Diff-guarded, so a no-op when already current.
        MITMSnapshot(enabled: snapshot.enabled, ruleSets: split.live).exportBinaryToAppGroup()
    }
    
    func reload() async {
        let previous = loadedBlob
        let outcome = await Task.detached(priority: .utility) {
            () -> (data: Data?, snapshot: MITMSnapshot)? in
            let data = JSONBlobStore.shared.load(.mitm)
            guard data != previous else { return nil }
            return (data, MITMSnapshot.decode(from: data))
        }.value
        guard let outcome else { return }
        loadedBlob = outcome.data
        let split = Tombstone.split(outcome.snapshot.ruleSets)
        ruleSets = split.live
        tombstones = split.tombstones
        enabled = outcome.snapshot.enabled
        // Refresh the NE-facing binary so a cloud-synced change is picked up on
        // the next extension (re)start.
        MITMSnapshot(enabled: outcome.snapshot.enabled, ruleSets: split.live).exportBinaryToAppGroup()
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

    /// Persists immediately — covers read-only subscribed sets, which never go
    /// through the draft-based editor.
    func setRuleSet(_ id: UUID, enabled: Bool) {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }) else { return }
        guard ruleSets[index].enabled != enabled else { return }
        ruleSets[index].enabled = enabled
        save()
    }

    /// Sets one parameter value (persists immediately, works for subscribed sets).
    /// A value equal to the default clears the override, so it keeps following the default.
    func setParameterValue(_ id: UUID, name: String, value: String) {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }),
              let definition = ruleSets[index].parameters.first(where: { $0.name == name })
        else { return }
        if definition.defaultValue == value {
            guard ruleSets[index].parameterValues[name] != nil else { return }
            ruleSets[index].parameterValues.removeValue(forKey: name)
        } else {
            guard ruleSets[index].parameterValues[name] != value else { return }
            ruleSets[index].parameterValues[name] = value
        }
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

    /// Replaces the set's suffixes and rules in place; `id` and `name` are
    /// preserved so the script-store scope and any rename stick.
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
        // Preserve user overrides across the refresh (see mergedParameterValues).
        let previousValues = ruleSets[writeIndex].parameterValues
        ruleSets[writeIndex].domainSuffixes = parsed.domainSuffixes
        ruleSets[writeIndex].rules = parsed.rules
        ruleSets[writeIndex].parameters = parsed.parameters
        ruleSets[writeIndex].parameterValues = Self.mergedParameterValues(
            definitions: parsed.parameters,
            previousValues: previousValues
        )
        save()
        return ruleSets[writeIndex]
    }

    /// Carries user overrides forward onto a refreshed definition set, dropping any
    /// whose parameter vanished or whose value is no longer one of a picker's options.
    private static func mergedParameterValues(
        definitions: [MITMParameter],
        previousValues: [String: String]
    ) -> [String: String] {
        var merged: [String: String] = [:]
        for definition in definitions {
            guard let value = previousValues[definition.name],
                  definition.accepts(value) else { continue }
            merged[definition.name] = value
        }
        return merged
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
