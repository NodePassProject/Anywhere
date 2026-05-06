//
//  MITMRuleSetStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
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

    // MARK: - Persistence

    private func save() {
        MITMSnapshot(enabled: enabled, ruleSets: ruleSets).save()
    }
}
