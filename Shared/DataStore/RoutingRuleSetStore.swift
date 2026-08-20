//
//  RoutingRuleSetStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Observation

nonisolated struct RoutingRuleSet: Identifiable, Equatable {
    let id: String   // built-in: name, custom: UUID string
    let name: String
    var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, "REJECT" = block, UUID string = proxy
    var isCustom: Bool = false
}

nonisolated struct CustomRoutingRuleSet: Codable, Identifiable, Equatable, SoftDeletable {
    static let maxRuleCount = 100000

    let id: UUID
    var name: String
    var rules: [RoutingRule]
    var subscriptionURL: URL?
    var iconLight: Data?
    var iconDark: Data?
    var updatedAt: Date
    var deletedAt: Date? = nil

    init(name: String, rules: [RoutingRule] = [], subscriptionURL: URL? = nil, iconLight: Data? = nil, iconDark: Data? = nil) {
        self.id = UUID()
        self.name = name
        self.rules = rules
        self.subscriptionURL = subscriptionURL
        self.iconLight = iconLight
        self.iconDark = iconDark
        self.updatedAt = .now
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, rules, subscriptionURL, iconLight, iconDark, deletedAt, updatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(UUID.self, forKey: .id)
        self.name = try container.decode(String.self, forKey: .name)
        self.rules = try container.decodeSkippingInvalid([RoutingRule].self, forKey: .rules)
        self.subscriptionURL = try container.decodeIfPresent(URL.self, forKey: .subscriptionURL)
        self.iconLight = try container.decodeIfPresent(Data.self, forKey: .iconLight)
        self.iconDark = try container.decodeIfPresent(Data.self, forKey: .iconDark)
        self.updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? deletedAt ?? .distantPast
        self.deletedAt = try container.decodeIfPresent(Date.self, forKey: .deletedAt)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(rules, forKey: .rules)
        try container.encodeIfPresent(subscriptionURL, forKey: .subscriptionURL)
        try container.encodeIfPresent(iconLight, forKey: .iconLight)
        try container.encodeIfPresent(iconDark, forKey: .iconDark)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encodeIfPresent(deletedAt, forKey: .deletedAt)
    }

    static func validSubscriptionURL(from rawValue: String) -> URL? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.path.lowercased().hasSuffix(".arrs") else { return nil }
        return url
    }
}

@MainActor
@Observable
class RoutingRuleSetStore {
    private(set) var ruleSets: [RoutingRuleSet] = []
    private(set) var customRuleSets: [CustomRoutingRuleSet] = []
    private var customTombstones: [CustomRoutingRuleSet] = []

    var bypassCountryCode: String {
        didSet {
            guard bypassCountryCode != oldValue else { return }
            AWCore.setBypassCountryCode(bypassCountryCode)
        }
    }

    var adBlockRuleSet: RoutingRuleSet? {
        ruleSets.first(where: { $0.id == "ADBlock" })
    }
    var builtInServiceRuleSets: [RoutingRuleSet] {
        ruleSets.filter { $0.id != "ADBlock" }
    }

    nonisolated private static let builtIn: [String] = {
        serviceCatalog.supportedServices + ["ADBlock"]
    }()

    nonisolated private static let serviceCatalog = ServiceCatalog.load()

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    init(syncStore: SyncStore) {
        self.syncStore = syncStore
        bypassCountryCode = AWCore.getBypassCountryCode()
        let assignments = AWCore.getRuleSetAssignments()

        let items = syncStore.loadItems(.customRuleSets)
        loadedItems = items
        let split = Self.decodeCustomSplit(from: items)
        customRuleSets = split.live
        customTombstones = split.tombstones

        rebuildRuleSets(assignments: assignments)
    }
    
    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], live: [CustomRoutingRuleSet], tombstones: [CustomRoutingRuleSet])? in
                let items = syncStore.loadItems(.customRuleSets)
                guard items != previous else { return nil }
                let split = Self.decodeCustomSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            customRuleSets = outcome.live
            customTombstones = outcome.tombstones
            rebuildRuleSets()
            return
        }
    }

    private func rebuildRuleSets(assignments: [String: String]? = nil) {
        let assignmentsDict = assignments ?? AWCore.getRuleSetAssignments()

        var sets = Self.builtIn.map { name in
            RoutingRuleSet(id: name, name: name, assignedConfigurationId: assignmentsDict[name])
        }
        
        let insertionIndex = sets.firstIndex(where: { $0.id == "ADBlock" }) ?? sets.endIndex
        for (offset, custom) in customRuleSets.enumerated() {
            let id = custom.id.uuidString
            sets.insert(RoutingRuleSet(
                id: id,
                name: custom.name,
                assignedConfigurationId: assignmentsDict[id],
                isCustom: true
            ), at: insertionIndex + offset)
        }

        ruleSets = sets
    }

    // MARK: - Assignment

    func updateAssignment(_ ruleSet: RoutingRuleSet, configurationId: String?) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        guard ruleSets[index].assignedConfigurationId != configurationId else { return }
        ruleSets[index].assignedConfigurationId = configurationId
        saveAssignments()
    }

    func resetAssignments() {
        for builtInServiceRuleSet in builtInServiceRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == builtInServiceRuleSet.id }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        for customRuleSet in customRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == customRuleSet.id.uuidString }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        saveAssignments()
    }
    
    func clearOrphanedAssignments(availableIds: Set<String>) -> [String] {
        var affected: [String] = []
        for (index, ruleSet) in ruleSets.enumerated() {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  assignedId != "DIRECT",
                  assignedId != "REJECT",
                  !availableIds.contains(assignedId) else { continue }
            ruleSets[index].assignedConfigurationId = nil
            affected.append(ruleSet.name)
        }
        if !affected.isEmpty {
            saveAssignments()
        }
        return affected
    }

    // MARK: - Custom Rule Set CRUD

    func addCustomRuleSet(name: String) -> CustomRoutingRuleSet {
        let ruleSet = CustomRoutingRuleSet(name: name)
        addCustomRuleSet(ruleSet)
        return ruleSet
    }
    
    func addCustomRuleSet(_ ruleSet: CustomRoutingRuleSet, initialAssignment: String? = nil) {
        let tombstone = customTombstones.first { $0.id == ruleSet.id }
        customTombstones.removeAll { $0.id == ruleSet.id }
        var stamped = ruleSet
        stamped.updatedAt = SyncStamp.after(tombstone)
        customRuleSets.append(stamped)
        saveCustomRuleSets()
        if let initialAssignment {
            var assignments = AWCore.getRuleSetAssignments()
            assignments[ruleSet.id.uuidString] = initialAssignment
            AWCore.setRuleSetAssignments(assignments)
        }
        rebuildRuleSets()
    }

    func removeCustomRuleSet(_ id: UUID) {
        if let removed = customRuleSets.first(where: { $0.id == id }) {
            recordTombstone(removed)
        }
        customRuleSets.removeAll { $0.id == id }
        saveCustomRuleSets()

        var assignments = AWCore.getRuleSetAssignments()
        assignments.removeValue(forKey: id.uuidString)
        AWCore.setRuleSetAssignments(assignments)

        rebuildRuleSets()
    }

    func updateCustomRuleSet(_ id: UUID, name: String? = nil, rules: [RoutingRule]? = nil, icons: (light: Data?, dark: Data?)? = nil) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }) else { return }
        if let name { customRuleSets[index].name = name }
        if let rules { customRuleSets[index].rules = rules }
        if let icons {
            customRuleSets[index].iconLight = icons.light
            customRuleSets[index].iconDark = icons.dark
        }
        customRuleSets[index].updatedAt = SyncStamp.after(customRuleSets[index])
        saveCustomRuleSets()
        rebuildRuleSets()
    }
    
    func reorderCustomRuleSets(_ ordered: [CustomRoutingRuleSet]) {
        guard Set(ordered.map(\.id)) == Set(customRuleSets.map(\.id)) else { return }
        customRuleSets = ordered
        saveCustomRuleSets()
        rebuildRuleSets()
    }
    
    func customRuleSet(for id: UUID) -> CustomRoutingRuleSet? {
        customRuleSets.first { $0.id == id }
    }

    // MARK: - Rules
    
    nonisolated static func loadRules(for name: String) -> [RoutingRule] {
        if name != "ADBlock" {
            return serviceCatalog.rules(for: name)
        }
        return RoutingRulesDatabase.shared.loadRules(for: name)
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dictionary = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { ruleSet in
            ruleSet.assignedConfigurationId.map { (ruleSet.id, $0) }
        })
        AWCore.setRuleSetAssignments(dictionary)
    }
    
    nonisolated private static func decodeCustomSplit(from items: [Data]) -> (live: [CustomRoutingRuleSet], tombstones: [CustomRoutingRuleSet]) {
        Tombstone.split(SyncCodec.decodeItems(CustomRoutingRuleSet.self, key: .customRuleSets, payloads: items))
    }

    private func recordTombstone(_ ruleSet: CustomRoutingRuleSet) {
        var tomb = ruleSet
        tomb.deletedAt = .now
        tomb.rules = []
        tomb.iconLight = nil
        tomb.iconDark = nil
        customTombstones.removeAll { $0.id == ruleSet.id }
        customTombstones.append(tomb)
    }

    private func saveCustomRuleSets() {
        mutationEpoch += 1
        syncStore.save(
            .customRuleSets,
            items: SyncCodec.encodeItems(customRuleSets + customTombstones),
            order: SyncCodec.order(of: customRuleSets)
        )
    }
}
