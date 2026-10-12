//
//  ModuleStore.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
final class ModuleStore {
    private(set) var modules: [Module] = []
    private var tombstones: [Module] = []
    
    private(set) var routingRuleSetAssignments: [String: String]

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    init(syncStore: SyncStore) {
        self.syncStore = syncStore
        routingRuleSetAssignments = AWCore.getModuleRoutingRuleSetAssignments()
        let items = syncStore.loadItems(.modules)
        loadedItems = items
        let split = Self.decodeSplit(from: items)
        modules = split.live
        tombstones = split.tombstones
        pruneAssignments()
    }

    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], live: [Module], tombstones: [Module])? in
                let items = syncStore.loadItems(.modules)
                guard items != previous else { return nil }
                let split = Self.decodeSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            modules = outcome.live
            tombstones = outcome.tombstones
            pruneAssignments()
            return
        }
    }

    // MARK: - Lookup

    func module(id: UUID) -> Module? {
        modules.first { $0.id == id }
    }

    func routingRuleSet(_ ruleSetId: UUID, in moduleId: UUID) -> ModuleRoutingRuleSet? {
        module(id: moduleId)?.routingRuleSet(id: ruleSetId)
    }

    func mitmRuleSet(_ ruleSetId: UUID, in moduleId: UUID) -> ModuleMITMRuleSet? {
        module(id: moduleId)?.mitmRuleSet(id: ruleSetId)
    }

    // MARK: - Module CRUD

    func add(_ module: Module, routingSeeds: [UUID: String] = [:]) {
        let tombstone = tombstones.first { $0.id == module.id }
        tombstones.removeAll { $0.id == module.id }
        var stamped = module
        stamped.updatedAt = SyncStamp.after(tombstone)
        modules.append(stamped)
        save()

        var assignments = routingRuleSetAssignments
        for (ruleSetId, assignment) in routingSeeds where module.routingRuleSet(id: ruleSetId) != nil {
            assignments[ruleSetId.uuidString] = assignment
        }
        replaceAssignments(assignments)
    }

    func remove(id: UUID) {
        guard let index = modules.firstIndex(where: { $0.id == id }) else { return }
        let removed = modules.remove(at: index)
        recordTombstone(removed)
        save()
        pruneAssignments()
    }

    func remove(atOffsets offsets: IndexSet) {
        let ids = offsets.map { modules[$0].id }
        for id in ids {
            remove(id: id)
        }
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        modules.move(fromOffsets: source, toOffset: destination)
        save()
    }

    func rename(id: UUID, name: String) {
        mutate(id: id) { module in
            guard module.name != name else { return false }
            module.name = name
            return true
        }
    }

    func setEnabled(id: UUID, enabled: Bool) {
        mutate(id: id) { module in
            guard module.enabled != enabled else { return false }
            module.enabled = enabled
            return true
        }
    }
    
    @discardableResult
    private func mutate(id: UUID, _ apply: (inout Module) -> Bool) -> Module? {
        guard let index = modules.firstIndex(where: { $0.id == id }) else { return nil }
        var module = modules[index]
        guard apply(&module) else { return modules[index] }
        module.updatedAt = SyncStamp.after(modules[index])
        modules[index] = module
        save()
        return module
    }

    // MARK: - Routing rule sets

    func addRoutingRuleSet(_ ruleSet: ModuleRoutingRuleSet, to moduleId: UUID) {
        mutate(id: moduleId) { module in
            guard module.ruleSetCount < Module.maxRuleSetCount else { return false }
            module.routingRuleSets.append(ruleSet)
            return true
        }
    }

    func updateRoutingRuleSet(_ ruleSetId: UUID, in moduleId: UUID, name: String? = nil, rules: [RoutingRule]? = nil) {
        mutate(id: moduleId) { module in
            guard let index = module.routingRuleSets.firstIndex(where: { $0.id == ruleSetId }) else { return false }
            var changed = false
            if let name, module.routingRuleSets[index].name != name {
                module.routingRuleSets[index].name = name
                changed = true
            }
            if let rules, module.routingRuleSets[index].rules != rules {
                module.routingRuleSets[index].rules = rules
                changed = true
            }
            return changed
        }
    }

    func removeRoutingRuleSets(atOffsets offsets: IndexSet, in moduleId: UUID) {
        guard !offsets.isEmpty else { return }
        mutate(id: moduleId) { module in
            module.routingRuleSets.remove(atOffsets: offsets)
            return true
        }
        pruneAssignments()
    }

    func moveRoutingRuleSets(fromOffsets source: IndexSet, toOffset destination: Int, in moduleId: UUID) {
        mutate(id: moduleId) { module in
            module.routingRuleSets.move(fromOffsets: source, toOffset: destination)
            return true
        }
    }

    // MARK: - MITM rule sets

    func addMITMRuleSet(_ ruleSet: ModuleMITMRuleSet, to moduleId: UUID) {
        mutate(id: moduleId) { module in
            guard module.ruleSetCount < Module.maxRuleSetCount else { return false }
            module.mitmRuleSets.append(ruleSet)
            return true
        }
    }

    func updateMITMRuleSet(_ ruleSetId: UUID, in moduleId: UUID, domainSuffixes: [String], rules: [MITMRule]) {
        mutate(id: moduleId) { module in
            guard let index = module.mitmRuleSets.firstIndex(where: { $0.id == ruleSetId }) else { return false }
            guard module.mitmRuleSets[index].domainSuffixes != domainSuffixes
                    || module.mitmRuleSets[index].rules != rules else { return false }
            module.mitmRuleSets[index].domainSuffixes = domainSuffixes
            module.mitmRuleSets[index].rules = rules
            return true
        }
    }

    func setMITMRuleSet(_ ruleSetId: UUID, in moduleId: UUID, enabled: Bool) {
        mutate(id: moduleId) { module in
            guard let index = module.mitmRuleSets.firstIndex(where: { $0.id == ruleSetId }),
                  module.mitmRuleSets[index].enabled != enabled else { return false }
            module.mitmRuleSets[index].enabled = enabled
            return true
        }
    }
    
    func setMITMParameterValue(in moduleId: UUID, name: String, value: String) {
        mutate(id: moduleId) { module in
            var changed = false
            for index in module.mitmRuleSets.indices {
                guard let definition = module.mitmRuleSets[index].parameters.first(where: { $0.name == name })
                else { continue }
                if definition.defaultValue == value {
                    guard module.mitmRuleSets[index].parameterValues[name] != nil else { continue }
                    module.mitmRuleSets[index].parameterValues.removeValue(forKey: name)
                } else {
                    guard module.mitmRuleSets[index].parameterValues[name] != value else { continue }
                    module.mitmRuleSets[index].parameterValues[name] = value
                }
                changed = true
            }
            return changed
        }
    }

    func removeMITMRuleSets(atOffsets offsets: IndexSet, in moduleId: UUID) {
        guard !offsets.isEmpty else { return }
        mutate(id: moduleId) { module in
            module.mitmRuleSets.remove(atOffsets: offsets)
            return true
        }
    }

    func moveMITMRuleSets(fromOffsets source: IndexSet, toOffset destination: Int, in moduleId: UUID) {
        mutate(id: moduleId) { module in
            module.mitmRuleSets.move(fromOffsets: source, toOffset: destination)
            return true
        }
    }

    // MARK: - Routing assignments

    func routingAssignment(for ruleSetId: UUID) -> String? {
        routingRuleSetAssignments[ruleSetId.uuidString]
    }

    func setAssignment(_ configurationId: String?, for ruleSetId: UUID) {
        var assignments = routingRuleSetAssignments
        assignments[ruleSetId.uuidString] = configurationId
        replaceAssignments(assignments)
    }
    
    func clearOrphanedAssignments(availableIds: Set<String>) -> [String] {
        var assignments = routingRuleSetAssignments
        var affected: [String] = []
        for module in modules {
            for ruleSet in module.routingRuleSets {
                let key = ruleSet.id.uuidString
                guard let assigned = assignments[key],
                      assigned != "PROXY",
                      assigned != "DIRECT",
                      assigned != "REJECT",
                      !availableIds.contains(assigned) else { continue }
                assignments.removeValue(forKey: key)
                affected.append(module.qualifiedName(for: ruleSet.name))
            }
        }
        replaceAssignments(assignments)
        return affected
    }
    
    private func pruneAssignments() {
        replaceAssignments(routingRuleSetAssignments)
    }

    private func replaceAssignments(_ proposed: [String: String]) {
        let live = Set(modules.flatMap { module in module.routingRuleSets.map { $0.id.uuidString } })
        let next = proposed.filter { live.contains($0.key) }
        guard next != routingRuleSetAssignments else { return }
        routingRuleSetAssignments = next
        AWCore.setModuleRoutingRuleSetAssignments(next)
    }

    // MARK: - Subscription
    
    @discardableResult
    func applyRefreshedContent(_ content: ModuleContent, to id: UUID) -> Module? {
        guard let index = modules.firstIndex(where: { $0.id == id }) else { return nil }
        let previous = modules[index]

        let previousRouting = Dictionary(grouping: previous.routingRuleSets, by: \.name)
        var routingCursor: [String: Int] = [:]
        var seeds: [UUID: String] = [:]
        let routingRuleSets = content.routingRuleSets.map { incoming -> ModuleRoutingRuleSet in
            var merged = incoming
            let cursor = routingCursor[incoming.name, default: 0]
            if let group = previousRouting[incoming.name], cursor < group.count {
                merged.id = group[cursor].id
                routingCursor[incoming.name] = cursor + 1
            } else if let seed = content.routingSeeds[incoming.id] {
                seeds[incoming.id] = seed
            }
            return merged
        }

        let previousMITM = Dictionary(grouping: previous.mitmRuleSets, by: \.name)
        var mitmCursor: [String: Int] = [:]
        let mitmRuleSets = content.mitmRuleSets.map { incoming -> ModuleMITMRuleSet in
            var merged = incoming
            let cursor = mitmCursor[incoming.name, default: 0]
            if let group = previousMITM[incoming.name], cursor < group.count {
                let old = group[cursor]
                merged.id = old.id
                merged.enabled = old.enabled
                merged.parameterValues = MITMRuleSetStore.mergedParameterValues(
                    definitions: incoming.parameters,
                    previousValues: old.parameterValues
                )
                mitmCursor[incoming.name] = cursor + 1
            }
            return merged
        }

        var module = previous
        module.description = content.description
        module.iconLight = content.iconLight
        module.iconDark = content.iconDark
        module.routingRuleSets = routingRuleSets
        module.mitmRuleSets = mitmRuleSets
        guard module != previous else { return previous }
        module.updatedAt = SyncStamp.after(previous)
        modules[index] = module
        save()

        var assignments = routingRuleSetAssignments
        for (ruleSetId, assignment) in seeds {
            assignments[ruleSetId.uuidString] = assignment
        }
        replaceAssignments(assignments)
        return module
    }

    // MARK: - Export
    
    var exportedMITMRuleSets: [MITMRuleSet] {
        modules.filter(\.enabled).flatMap { module in
            module.mitmRuleSets.map { ruleSet in
                ruleSet.asMITMRuleSet(name: module.qualifiedName(for: ruleSet.name))
            }
        }
    }

    // MARK: - Persistence

    nonisolated private static func decodeSplit(from items: [Data]) -> (live: [Module], tombstones: [Module]) {
        Tombstone.split(SyncCodec.decodeItems(Module.self, key: .modules, payloads: items))
    }

    private func recordTombstone(_ module: Module) {
        var tomb = Module(id: module.id, name: module.name, updatedAt: module.updatedAt)
        tomb.deletedAt = .now
        tombstones.removeAll { $0.id == module.id }
        tombstones.append(tomb)
    }

    private func save() {
        mutationEpoch += 1
        syncStore.save(
            .modules,
            items: SyncCodec.encodeItems(modules + tombstones),
            order: SyncCodec.order(of: modules)
        )
    }
}
