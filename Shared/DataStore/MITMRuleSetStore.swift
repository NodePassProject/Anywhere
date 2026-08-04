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
    
    @ObservationIgnored private let blobStore: JSONBlobStore
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0

    init(blobStore: JSONBlobStore) {
        self.blobStore = blobStore
        let data = blobStore.load(.mitm)
        loadedBlob = data
        let snapshot = MITMSnapshot.decode(from: data)
        if !AWCore.hasMITMEnabled() {
            AWCore.setMITMEnabled(MITMSnapshot.legacyEnabled(in: data))
        }
        self.enabled = AWCore.getMITMEnabled()
        let split = Tombstone.split(snapshot.ruleSets)
        self.ruleSets = split.live
        self.tombstones = split.tombstones
        MITMSnapshot(ruleSets: split.live).exportBinaryToAppGroup()
    }
    
    func reload() async {
        while true {
            let previous = loadedBlob
            let epoch = mutationEpoch
            let outcome = await Task.detached(priority: .utility) {
                [blobStore] () -> (data: Data?, snapshot: MITMSnapshot)? in
                let data = blobStore.load(.mitm)
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
    func applyRefreshedContent(
        domainSuffixes: [String],
        rules: [MITMRule],
        parameters: [MITMParameter],
        to id: UUID
    ) -> MITMRuleSet? {
        guard let writeIndex = ruleSets.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        let previousValues = ruleSets[writeIndex].parameterValues
        ruleSets[writeIndex].domainSuffixes = domainSuffixes
        ruleSets[writeIndex].rules = rules
        ruleSets[writeIndex].parameters = parameters
        ruleSets[writeIndex].parameterValues = Self.mergedParameterValues(
            definitions: parameters,
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
        MITMSnapshot(ruleSets: ruleSets + tombstones).save(to: blobStore)
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
