//
//  RoutingRuleSetStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine

private let logger = AnywhereLogger(category: "RoutingRuleSetStore")

struct RoutingRuleSet: Identifiable, Equatable {
    let id: String   // built-in: name, custom: UUID string
    let name: String
    var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, "REJECT" = block, UUID string = proxy
    var isCustom: Bool = false
}

struct CustomRoutingRuleSet: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var rules: [RoutingRule]

    init(name: String, rules: [RoutingRule] = []) {
        self.id = UUID()
        self.name = name
        self.rules = rules
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, rules
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.name = try c.decode(String.self, forKey: .name)
        // A single corrupt rule shouldn't take down the whole set.
        self.rules = try c.decodeSkippingInvalid([RoutingRule].self, forKey: .rules)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(rules, forKey: .rules)
    }
}

@MainActor
class RoutingRuleSetStore: ObservableObject {
    static let shared = RoutingRuleSetStore()

    @Published private(set) var ruleSets: [RoutingRuleSet] = []
    @Published private(set) var customRuleSets: [CustomRoutingRuleSet] = []

    var adBlockRuleSet: RoutingRuleSet? {
        ruleSets.first(where: { $0.name == "ADBlock" })
    }
    var builtInServiceRuleSets: [RoutingRuleSet] {
        ruleSets.filter { $0.name != "Direct" && $0.name != "ADBlock" }
    }

    /// Bundled ruleset names: Direct + supported services + ADBlock.
    private static let builtIn: [String] = {
        ["Direct"] + serviceCatalog.supportedServices + ["ADBlock"]
    }()

    private static let serviceCatalog = ServiceCatalog.load()

    private static let defaultAssignments: [String: String] = ["Direct": "DIRECT"]

    private init() {
        let assignments = AWCore.getRuleSetAssignments()

        // Load custom rulesets
        if let data = JSONBlobStore.shared.load(.customRuleSets),
           let decoded = JSONDecoder().decodeSkippingInvalid([CustomRoutingRuleSet].self, from: data) {
            customRuleSets = decoded
        }

        rebuildRuleSets(assignments: assignments)
    }

    private func rebuildRuleSets(assignments: [String: String]? = nil) {
        let assignmentsDict = assignments ?? AWCore.getRuleSetAssignments()

        var sets = Self.builtIn.map { name in
            RoutingRuleSet(id: name, name: name, assignedConfigurationId: assignmentsDict[name] ?? Self.defaultAssignments[name])
        }

        // Insert custom rule sets before ADBlock so that ADBlock retains
        // highest priority.  Desired trie-overwrite order (lowest → highest):
        // Country Bypass → Direct → Services → User/Custom → ADBlock
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

    /// Resets any rule set assignments that reference UUIDs (configuration or chain)
    /// not in `availableIds`. Returns the names of affected rule sets, or empty.
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
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        rebuildRuleSets()
        return ruleSet
    }

    func addCustomRuleSet(_ ruleSet: CustomRoutingRuleSet) {
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func removeCustomRuleSet(_ id: UUID) {
        customRuleSets.removeAll { $0.id == id }
        saveCustomRuleSets()

        // Remove assignment for this custom ruleset
        var assignments = AWCore.getRuleSetAssignments()
        assignments.removeValue(forKey: id.uuidString)
        AWCore.setRuleSetAssignments(assignments)

        rebuildRuleSets()
    }

    func updateCustomRuleSet(_ id: UUID, name: String? = nil, rules: [RoutingRule]? = nil) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }) else { return }
        if let name { customRuleSets[index].name = name }
        if let rules { customRuleSets[index].rules = rules }
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func addRule(to customRuleSetId: UUID, rule: RoutingRule) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        customRuleSets[index].rules.append(rule)
        saveCustomRuleSets()
    }

    func addRules(to customRuleSetId: UUID, rules: [RoutingRule]) {
        guard !rules.isEmpty,
              let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        customRuleSets[index].rules.append(contentsOf: rules)
        saveCustomRuleSets()
    }

    func removeRules(from customRuleSetId: UUID, at indices: [Int]) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        for i in indices.sorted().reversed() {
            customRuleSets[index].rules.remove(at: i)
        }
        saveCustomRuleSets()
    }

    func customRuleSet(for id: UUID) -> CustomRoutingRuleSet? {
        customRuleSets.first { $0.id == id }
    }

    // MARK: - Rules

    /// Loads rules for a given built-in rule set name. Thread-safe – no instance state accessed.
    /// All built-in rules are stored in the bundled Rules.db SQLite database.
    static func loadRules(for name: String) -> [RoutingRule] {
        if name != "Direct" && name != "ADBlock" {
            return serviceCatalog.rules(for: name)
        }
        return RoutingRulesDatabase.shared.loadRules(for: name)
    }

    // MARK: - App Group Sync

    func syncToAppGroup(configurations: [ProxyConfiguration], chains: [ProxyChain], serializeConfiguration: @escaping @Sendable (ProxyConfiguration) -> [String: Any]) async {
        // Snapshot main-actor state
        let snapshot = ruleSets
        let customSnapshot = customRuleSets

        // Pre-resolve each rule set's assigned target on the main actor — chain composites
        // are constructed here so the detached worker only sees Sendable lookup data.
        var resolvedTargets: [String: ProxyConfiguration] = [:]
        for ruleSet in snapshot {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  let id = UUID(uuidString: assignedId) else { continue }
            if let direct = configurations.first(where: { $0.id == id }) {
                resolvedTargets[assignedId] = direct
            } else if let chain = chains.first(where: { $0.id == id }),
                      let composite = chain.resolveComposite(from: configurations) {
                resolvedTargets[assignedId] = composite
            }
        }

        await Task.detached {
            var routingRules: [[String: Any]] = []
            var configurationsDict: [String: Any] = [:]

            for ruleSet in snapshot {
                guard let assignedId = ruleSet.assignedConfigurationId else { continue }

                // Load rules: custom rulesets use captured data, built-in use database
                let domainRules: [RoutingRule]
                if ruleSet.isCustom,
                   let customId = UUID(uuidString: ruleSet.id),
                   let custom = customSnapshot.first(where: { $0.id == customId }) {
                    domainRules = custom.rules
                } else {
                    domainRules = await Self.loadRules(for: ruleSet.name)
                }
                guard !domainRules.isEmpty else { continue }

                let domainRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .domainSuffix, .domainKeyword:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .ipCIDR, .ipCIDR6:
                        return nil
                    }
                }
                let ipRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .ipCIDR, .ipCIDR6:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .domainSuffix, .domainKeyword:
                        return nil
                    }
                }
                var ruleEntry: [String: Any] = ["domainRules": domainRulesArray]
                if !ipRulesArray.isEmpty {
                    ruleEntry["ipRules"] = ipRulesArray
                }

                if assignedId == "DIRECT" {
                    ruleEntry["action"] = "direct"
                } else if assignedId == "REJECT" {
                    ruleEntry["action"] = "reject"
                } else if let configuration = resolvedTargets[assignedId] {
                    ruleEntry["action"] = "proxy"
                    ruleEntry["configId"] = assignedId
                    var serialized = serializeConfiguration(configuration)
                    if let resolvedIP = VPNViewModel.resolveServerAddress(configuration.serverAddress) {
                        serialized["resolvedIP"] = resolvedIP
                    }
                    configurationsDict[assignedId] = serialized
                } else {
                    continue
                }

                routingRules.append(ruleEntry)
            }

            // Fetch bypass country rules
            var bypassRules: [[String: Any]] = []
            let countryCode = AWCore.getBypassCountryCode()
            if !countryCode.isEmpty {
                let rules = await CountryBypassCatalog.shared.rules(for: countryCode)
                bypassRules = rules.map {
                    ["type": $0.type.rawValue, "value": $0.value]
                }
            }

            var routing: [String: Any] = ["rules": routingRules, "configs": configurationsDict]
            if !bypassRules.isEmpty {
                routing["bypassRules"] = bypassRules
            }

            if let data = try? JSONSerialization.data(withJSONObject: routing) {
                AWCore.setRoutingData(data)
            }

            AWCore.notifyRoutingChanged()
        }.value
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dict = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { rs in
            rs.assignedConfigurationId.map { (rs.id, $0) }
        })
        AWCore.setRuleSetAssignments(dict)
    }

    private func saveCustomRuleSets() {
        if let data = try? JSONEncoder().encode(customRuleSets) {
            JSONBlobStore.shared.save(.customRuleSets, data: data)
        }
    }
}
