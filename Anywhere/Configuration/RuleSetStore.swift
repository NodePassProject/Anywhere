//
//  RuleSetStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere", category: "RuleSetStore")

@Observable @MainActor
class RuleSetStore {
    static let shared = RuleSetStore()

    struct RuleSet: Identifiable {
        let id: String   // = name
        let name: String
        var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, UUID string = proxy
    }

    private(set) var ruleSets: [RuleSet] = []

    /// Bundled ruleset names (must match JSON filenames in Resources/).
    private static let builtIn = ["Telegram"]
    private static let assignmentsKey = "ruleSetAssignments"

    private init() {
        let assignments = APCore.userDefaults.dictionary(forKey: Self.assignmentsKey) as? [String: String] ?? [:]
        ruleSets = Self.builtIn.map { name in
            RuleSet(id: name, name: name, assignedConfigurationId: assignments[name])
        }
    }

    // MARK: - Assignment

    func updateAssignment(_ ruleSet: RuleSet, configurationId: String?) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        ruleSets[index].assignedConfigurationId = configurationId
        saveAssignments()
    }

    /// Resets any rule set assignments that reference configuration UUIDs not in `availableConfigIds`.
    /// Returns the names of affected rule sets, or empty if nothing changed.
    func clearOrphanedAssignments(availableConfigIds: Set<String>) -> [String] {
        var affected: [String] = []
        for (index, ruleSet) in ruleSets.enumerated() {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  assignedId != "DIRECT",
                  !availableConfigIds.contains(assignedId) else { continue }
            ruleSets[index].assignedConfigurationId = nil
            affected.append(ruleSet.name)
        }
        if !affected.isEmpty {
            saveAssignments()
        }
        return affected
    }

    // MARK: - Rules

    /// Loads rules from the app bundle.
    func loadRules(for name: String) -> [DomainRule] {
        guard let url = Bundle.main.url(forResource: name, withExtension: "json") else {
            logger.error("[RuleSetStore] Bundle resource '\(name, privacy: .public).json' not found")
            return []
        }
        guard let data = try? Data(contentsOf: url) else {
            logger.error("[RuleSetStore] Failed to read '\(name, privacy: .public).json'")
            return []
        }
        guard let rules = try? JSONDecoder().decode([DomainRule].self, from: data) else {
            logger.error("[RuleSetStore] Failed to decode '\(name, privacy: .public).json'")
            return []
        }
        return rules
    }

    // MARK: - App Group Sync

    func syncToAppGroup(configurations: [VLESSConfiguration], serializeConfiguration: (VLESSConfiguration) -> [String: Any]) {
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: APCore.suiteName) else { return }
        let routingURL = containerURL.appendingPathComponent("routing.json")

        var routingRules: [[String: Any]] = []
        var configurationsDict: [String: Any] = [:]

        for ruleSet in ruleSets {
            guard let assignedId = ruleSet.assignedConfigurationId else { continue }
            let domainRules = loadRules(for: ruleSet.name)
            guard !domainRules.isEmpty else { continue }

            let domainRulesArray: [[String: String]] = domainRules.map {
                ["type": $0.type.rawValue, "value": $0.value]
            }
            var ruleEntry: [String: Any] = ["domainRules": domainRulesArray]

            if assignedId == "DIRECT" {
                ruleEntry["action"] = "direct"
            } else if let configurationUUID = UUID(uuidString: assignedId),
                      let configuration = configurations.first(where: { $0.id == configurationUUID }) {
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

        logger.info("[RuleSetStore] Writing routing.json: \(routingRules.count) rules, \(configurationsDict.count) configurations")

        do {
            let data = try JSONSerialization.data(withJSONObject: routing, options: [.sortedKeys])
            try data.write(to: routingURL, options: .atomic)
        } catch {
            logger.error("[RuleSetStore] Failed to write routing.json: \(error.localizedDescription, privacy: .public)")
        }

        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.routingChanged" as CFString),
            nil, nil, true
        )
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dict = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { rs in
            rs.assignedConfigurationId.map { (rs.name, $0) }
        })
        APCore.userDefaults.set(dict, forKey: Self.assignmentsKey)
    }
}
