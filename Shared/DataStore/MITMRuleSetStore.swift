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
            AWCore.setMITMEnabled(enabled)
            MITMSnapshot(ruleSets: ruleSets).exportBinaryToAppGroup()
            AWNotificationCenter.notifyMITMChanged()
        }
    }

    private(set) var ruleSets: [MITMRuleSet]
    private var tombstones: [MITMRuleSet] = []
    
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0

    private init() {
        let data = JSONBlobStore.shared.load(.mitm)
        loadedBlob = data
        let snapshot = MITMSnapshot.decode(from: data)
        // One-time migration: older builds kept the master toggle inside the synced blob.
        // Seed the device-local default from it so upgrading doesn't silently turn MITM off.
        if !AWCore.hasMITMEnabled() {
            AWCore.setMITMEnabled(MITMSnapshot.legacyEnabled(in: data))
        }
        self.enabled = AWCore.getMITMEnabled()
        let split = Tombstone.split(snapshot.ruleSets)
        self.ruleSets = split.live
        self.tombstones = split.tombstones
        // Ensure the NE-facing binary exists on first launch and post-migration,
        // before any edit. Diff-guarded, so a no-op when already current.
        MITMSnapshot(ruleSets: split.live).exportBinaryToAppGroup()
    }
    
    func reload() async {
        while true {
            let previous = loadedBlob
            let epoch = mutationEpoch
            let outcome = await Task.detached(priority: .utility) {
                () -> (data: Data?, snapshot: MITMSnapshot)? in
                let data = JSONBlobStore.shared.load(.mitm)
                guard data != previous else { return nil }
                return (data, MITMSnapshot.decode(from: data))
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
            let split = Tombstone.split(outcome.snapshot.ruleSets)
            ruleSets = split.live
            tombstones = split.tombstones
            MITMSnapshot(ruleSets: split.live).exportBinaryToAppGroup()
            return
        }
    }

    // MARK: - Rule set CRUD

    func addRuleSet(_ ruleSet: MITMRuleSet) {
        let tombstone = tombstones.first { $0.id == ruleSet.id }
        tombstones.removeAll { $0.id == ruleSet.id }
        var stamped = ruleSet
        stamped.updatedAt = SyncStamp.after(tombstone)
        ruleSets.append(stamped)
        save()
    }

    func updateRuleSet(_ id: UUID, domainSuffixes: [String], rules: [MITMRule]) {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }) else { return }
        guard ruleSets[index].domainSuffixes != domainSuffixes || ruleSets[index].rules != rules else { return }
        ruleSets[index].domainSuffixes = domainSuffixes
        ruleSets[index].rules = rules
        ruleSets[index].updatedAt = SyncStamp.after(ruleSets[index])
        save()
    }

    func setRuleSet(_ id: UUID, enabled: Bool) {
        guard let index = ruleSets.firstIndex(where: { $0.id == id }) else { return }
        guard ruleSets[index].enabled != enabled else { return }
        ruleSets[index].enabled = enabled
        ruleSets[index].updatedAt = SyncStamp.after(ruleSets[index])
        save()
    }
    
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
        ruleSets[index].updatedAt = SyncStamp.after(ruleSets[index])
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
        guard ruleSets[index].rules.count < MITMRuleSet.maxRuleCount else { return }
        ruleSets[index].rules.append(rule)
        ruleSets[index].updatedAt = SyncStamp.after(ruleSets[index])
        save()
    }

    func updateRule(_ rule: MITMRule, inRuleSet ruleSetID: UUID) {
        guard let setIndex = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        guard let ruleIndex = ruleSets[setIndex].rules.firstIndex(where: { $0.id == rule.id }) else {
            return
        }
        ruleSets[setIndex].rules[ruleIndex] = rule
        ruleSets[setIndex].updatedAt = SyncStamp.after(ruleSets[setIndex])
        save()
    }

    func removeRules(atOffsets offsets: IndexSet, inRuleSet ruleSetID: UUID) {
        guard let setIndex = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        ruleSets[setIndex].rules.remove(atOffsets: offsets)
        ruleSets[setIndex].updatedAt = SyncStamp.after(ruleSets[setIndex])
        save()
    }
    
    func moveRules(
        fromOffsets source: IndexSet,
        toOffset destination: Int,
        inRuleSet ruleSetID: UUID
    ) {
        guard let setIndex = ruleSets.firstIndex(where: { $0.id == ruleSetID }) else { return }
        ruleSets[setIndex].rules.move(fromOffsets: source, toOffset: destination)
        ruleSets[setIndex].updatedAt = SyncStamp.after(ruleSets[setIndex])
        save()
    }

    // MARK: - Subscription
    
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
        guard let writeIndex = ruleSets.firstIndex(where: { $0.id == id }) else {
            throw MITMRuleSetRefreshError.ruleSetRemoved
        }
        let previousValues = ruleSets[writeIndex].parameterValues
        ruleSets[writeIndex].domainSuffixes = parsed.domainSuffixes
        ruleSets[writeIndex].rules = parsed.rules
        ruleSets[writeIndex].parameters = parsed.parameters
        ruleSets[writeIndex].parameterValues = Self.mergedParameterValues(
            definitions: parsed.parameters,
            previousValues: previousValues
        )
        ruleSets[writeIndex].updatedAt = SyncStamp.after(ruleSets[writeIndex])
        save()
        return ruleSets[writeIndex]
    }
    
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
            tomb.domainSuffixes = []
            tomb.rules = []
            tomb.parameters = []
            tomb.parameterValues = [:]
            tombstones.append(tomb)
        }
    }

    private func save() {
        mutationEpoch += 1
        MITMSnapshot(ruleSets: ruleSets + tombstones).save()
    }
}

nonisolated enum MITMRuleSetRefreshError: LocalizedError {
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
