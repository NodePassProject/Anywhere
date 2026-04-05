//
//  RuleSetStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere", category: "RuleSetStore")

// MARK: - Custom Rule Set

struct CustomRuleSet: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var rules: [DomainRule]

    init(name: String, rules: [DomainRule] = []) {
        self.id = UUID()
        self.name = name
        self.rules = rules
    }
}

@MainActor
class RuleSetStore: ObservableObject {
    static let shared = RuleSetStore()

    struct RuleSet: Identifiable, Equatable {
        let id: String   // built-in: name, custom: UUID string
        let name: String
        var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, "REJECT" = block, UUID string = proxy
        var isCustom: Bool = false
    }

    @Published private(set) var ruleSets: [RuleSet] = []
    @Published private(set) var customRuleSets: [CustomRuleSet] = []

    var adBlockRuleSet: RuleSet? {
        ruleSets.first(where: { $0.name == "ADBlock" })
    }
    var routingRuleSets: [RuleSetStore.RuleSet] {
        ruleSets.filter { $0.name != "Direct" && $0.name != "ADBlock" }
    }

    private static let assignmentsKey = "ruleSetAssignments"
    private static let customRuleSetsKey = "customRuleSets"

    /// Bundled ruleset names: Direct + supported services + ADBlock.
    private static let builtIn: [String] = {
        ["Direct"] + serviceCatalog.supportedServices + ["ADBlock"]
    }()

    private static let serviceCatalog = ServiceCatalog.load()

    private static let defaultAssignments: [String: String] = ["Direct": "DIRECT"]

    private init() {
        let assignments = AWCore.userDefaults.dictionary(forKey: Self.assignmentsKey) as? [String: String] ?? [:]

        // Load custom rulesets
        if let data = AWCore.userDefaults.data(forKey: Self.customRuleSetsKey),
           let decoded = try? JSONDecoder().decode([CustomRuleSet].self, from: data) {
            customRuleSets = decoded
        }

        rebuildRuleSets(assignments: assignments)
    }

    private func rebuildRuleSets(assignments: [String: String]? = nil) {
        let assignmentsDict: [String: String]
        if let assignments {
            assignmentsDict = assignments
        } else {
            assignmentsDict = AWCore.userDefaults.dictionary(forKey: Self.assignmentsKey) as? [String: String] ?? [:]
        }

        var sets = Self.builtIn.map { name in
            RuleSet(id: name, name: name, assignedConfigurationId: assignmentsDict[name] ?? Self.defaultAssignments[name])
        }

        for custom in customRuleSets {
            let id = custom.id.uuidString
            sets.append(RuleSet(
                id: id,
                name: custom.name,
                assignedConfigurationId: assignmentsDict[id],
                isCustom: true
            ))
        }

        ruleSets = sets
    }

    // MARK: - Assignment

    func updateAssignment(_ ruleSet: RuleSet, configurationId: String?) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        ruleSets[index].assignedConfigurationId = configurationId
        saveAssignments()
    }

    func resetAssignments() {
        for routingRuleSet in routingRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == routingRuleSet.id }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        saveAssignments()
    }

    /// Resets any rule set assignments that reference configuration UUIDs not in `availableConfigIds`.
    /// Returns the names of affected rule sets, or empty if nothing changed.
    func clearOrphanedAssignments(availableConfigIds: Set<String>) -> [String] {
        var affected: [String] = []
        for (index, ruleSet) in ruleSets.enumerated() {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  assignedId != "DIRECT",
                  assignedId != "REJECT",
                  !availableConfigIds.contains(assignedId) else { continue }
            ruleSets[index].assignedConfigurationId = nil
            affected.append(ruleSet.name)
        }
        if !affected.isEmpty {
            saveAssignments()
        }
        return affected
    }

    // MARK: - Custom Rule Set CRUD

    func addCustomRuleSet(name: String) -> CustomRuleSet {
        let ruleSet = CustomRuleSet(name: name)
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        rebuildRuleSets()
        return ruleSet
    }

    func removeCustomRuleSet(_ id: UUID) {
        customRuleSets.removeAll { $0.id == id }
        saveCustomRuleSets()

        // Remove assignment for this custom ruleset
        var assignments = AWCore.userDefaults.dictionary(forKey: Self.assignmentsKey) as? [String: String] ?? [:]
        assignments.removeValue(forKey: id.uuidString)
        AWCore.userDefaults.set(assignments, forKey: Self.assignmentsKey)

        rebuildRuleSets()
    }

    func updateCustomRuleSet(_ id: UUID, name: String? = nil, rules: [DomainRule]? = nil) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }) else { return }
        if let name { customRuleSets[index].name = name }
        if let rules { customRuleSets[index].rules = rules }
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func addRule(to customRuleSetId: UUID, rule: DomainRule) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        customRuleSets[index].rules.append(rule)
        saveCustomRuleSets()
    }

    func removeRules(from customRuleSetId: UUID, at indices: [Int]) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        for i in indices.sorted().reversed() {
            customRuleSets[index].rules.remove(at: i)
        }
        saveCustomRuleSets()
    }

    func customRuleSet(for id: UUID) -> CustomRuleSet? {
        customRuleSets.first { $0.id == id }
    }

    // MARK: - Rules

    /// Loads rules for a given built-in rule set name. Thread-safe – no instance state accessed.
    /// All built-in rules are stored in the bundled Rules.db SQLite database.
    nonisolated static func loadRules(for name: String) -> [DomainRule] {
        if name != "Direct" && name != "ADBlock" {
            return serviceCatalog.rules(for: name)
        }
        return RulesDatabase.shared.loadRules(for: name)
    }

    // MARK: - App Group Sync

    func syncToAppGroup(configurations: [ProxyConfiguration], serializeConfiguration: @escaping @Sendable (ProxyConfiguration) -> [String: Any]) async {
        // Snapshot main-actor state
        let snapshot = ruleSets
        let customSnapshot = customRuleSets
        let configs = configurations

        await Task.detached {
            var routingRules: [[String: Any]] = []
            var configurationsDict: [String: Any] = [:]

            for ruleSet in snapshot {
                guard let assignedId = ruleSet.assignedConfigurationId else { continue }

                // Load rules: custom rulesets use captured data, built-in use database
                let domainRules: [DomainRule]
                if ruleSet.isCustom,
                   let customId = UUID(uuidString: ruleSet.id),
                   let custom = customSnapshot.first(where: { $0.id == customId }) {
                    domainRules = custom.rules
                } else {
                    domainRules = Self.loadRules(for: ruleSet.name)
                }
                guard !domainRules.isEmpty else { continue }

                let domainRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .domainSuffix:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .ipCIDR, .ipCIDR6:
                        return nil
                    }
                }
                let ipRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .ipCIDR, .ipCIDR6:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .domainSuffix:
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
                } else if let configurationUUID = UUID(uuidString: assignedId),
                          let configuration = configs.first(where: { $0.id == configurationUUID }) {
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

            let routing: [String: Any] = ["rules": routingRules, "configs": configurationsDict]

            if let data = try? JSONSerialization.data(withJSONObject: routing) {
                AWCore.userDefaults.set(data, forKey: "routingData")
            }

            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFNotificationName("com.argsment.Anywhere.routingChanged" as CFString),
                nil, nil, true
            )
        }.value
    }

    // MARK: - Bypass Country

    /// Serializes the bypass country's rules to App Group UserDefaults
    /// so the Network Extension can match both domains and IPs for country-based bypass.
    func syncBypassCountryRules(countryCode: String? = nil) async {
        var effectiveCountryCode: String
        if let countryCode {
            effectiveCountryCode = countryCode
        } else {
            if let countryCode = AWCore.userDefaults.string(forKey: "bypassCountryCode") {
                effectiveCountryCode = countryCode
            } else {
                AWCore.userDefaults.removeObject(forKey: "bypassCountryDomainRules")
                return
            }
        }
        await Task.detached {
            let rules = await CountryBypassCatalog.shared.rules(for: effectiveCountryCode)
            let serializedRules: [[String: Any]] = rules.map {
                ["type": $0.type.rawValue, "value": $0.value]
            }
            if serializedRules.isEmpty {
                AWCore.userDefaults.removeObject(forKey: "bypassCountryDomainRules")
                return
            }
            if let data = try? JSONSerialization.data(withJSONObject: serializedRules) {
                AWCore.userDefaults.set(data, forKey: "bypassCountryDomainRules")
            }
        }.value
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dict = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { rs in
            rs.assignedConfigurationId.map { (rs.id, $0) }
        })
        AWCore.userDefaults.set(dict, forKey: Self.assignmentsKey)
    }

    private func saveCustomRuleSets() {
        if let data = try? JSONEncoder().encode(customRuleSets) {
            AWCore.userDefaults.set(data, forKey: Self.customRuleSetsKey)
        }
    }
}
