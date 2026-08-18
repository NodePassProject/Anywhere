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

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    init(syncStore: SyncStore) {
        self.syncStore = syncStore
        let items = syncStore.loadItems(.mitm)
        loadedItems = items
        var ruleSets = SyncCodec.decodeItems(MITMRuleSet.self, key: .mitm, payloads: items)
        if items.isEmpty || !AWCore.hasMITMEnabled() {
            let legacyBlob = syncStore.legacyNewestBlobData(.mitm)
            if items.isEmpty {
                ruleSets = MITMSnapshot.decode(from: legacyBlob).ruleSets
            }
            if !AWCore.hasMITMEnabled() {
                AWCore.setMITMEnabled(MITMSnapshot.legacyEnabled(in: legacyBlob))
            }
        }
        self.enabled = AWCore.getMITMEnabled()
        let split = Tombstone.split(ruleSets)
        self.ruleSets = split.live
        self.tombstones = split.tombstones
        MITMSnapshot(ruleSets: split.live).exportBinaryToAppGroup()
    }

    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], ruleSets: [MITMRuleSet])? in
                let items = syncStore.loadItems(.mitm)
                guard items != previous else { return nil }
                return (items, SyncCodec.decodeItems(MITMRuleSet.self, key: .mitm, payloads: items))
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            let split = Tombstone.split(outcome.ruleSets)
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
        iconLight: Data?,
        iconDark: Data?,
        to id: UUID
    ) -> MITMRuleSet? {
        guard let writeIndex = ruleSets.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        let previousValues = ruleSets[writeIndex].parameterValues
        ruleSets[writeIndex].domainSuffixes = domainSuffixes
        ruleSets[writeIndex].rules = rules
        ruleSets[writeIndex].parameters = parameters
        ruleSets[writeIndex].iconLight = iconLight
        ruleSets[writeIndex].iconDark = iconDark
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
            tomb.iconLight = nil
            tomb.iconDark = nil
            tombstones.append(tomb)
        }
    }

    private func save() {
        mutationEpoch += 1
        let live = ruleSets
        syncStore.save(.mitm, items: SyncCodec.encodeItems(live + tombstones), order: SyncCodec.order(of: live))
        MITMSnapshot(ruleSets: live).exportBinaryToAppGroup()
        AWNotificationCenter.notifyMITMChanged()
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
