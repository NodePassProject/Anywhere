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

@MainActor
class RuleSetStore: ObservableObject {
    static let shared = RuleSetStore()

    struct RuleSet: Identifiable, Equatable {
        let id: String   // = name
        let name: String
        var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, "REJECT" = block, UUID string = proxy
    }

    @Published private(set) var ruleSets: [RuleSet] = []
    var adBlockRuleSet: RuleSet? {
        ruleSets.first(where: { $0.name == "ADBlock" })
    }
    var routingRuleSets: [RuleSetStore.RuleSet] {
        ruleSets.filter { $0.name != "Direct" && $0.name != "ADBlock" }
    }

    /// Bundled ruleset names (must match JSON filenames in Resources/).
    private static let builtIn = ["Direct", "Telegram", "Netflix", "YouTube", "Disney+", "TikTok", "ChatGPT", "Claude", "Gemini", "ADBlock"]
    private static let assignmentsKey = "ruleSetAssignments"

    private static let defaultAssignments: [String: String] = ["Direct": "DIRECT"]

    private init() {
        let assignments = AWCore.userDefaults.dictionary(forKey: Self.assignmentsKey) as? [String: String] ?? [:]
        ruleSets = Self.builtIn.map { name in
            RuleSet(id: name, name: name, assignedConfigurationId: assignments[name] ?? Self.defaultAssignments[name])
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

    // MARK: - Rules

    /// Loads rules from the app bundle. Thread-safe – no instance state accessed.
    nonisolated static func loadRules(for name: String) -> [DomainRule] {
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

    func syncToAppGroup(configurations: [ProxyConfiguration], serializeConfiguration: @escaping @Sendable (ProxyConfiguration) -> [String: Any]) async {
        // Snapshot main-actor state
        let snapshot = ruleSets
        let configs = configurations

        await Task.detached {
            var routingRules: [[String: Any]] = []
            var configurationsDict: [String: Any] = [:]

            for ruleSet in snapshot {
                guard let assignedId = ruleSet.assignedConfigurationId else { continue }

                let domainRules = Self.loadRules(for: ruleSet.name)
                guard !domainRules.isEmpty else { continue }

                let domainRulesArray: [[String: String]] = domainRules.compactMap {
                    switch $0.type {
                    case .domain, .domainSuffix, .domainKeyword:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .ipCIDR, .ipCIDR6:
                        return nil
                    }
                }
                let ipRulesArray: [[String: String]] = domainRules.compactMap {
                    switch $0.type {
                    case .ipCIDR, .ipCIDR6:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .domain, .domainSuffix, .domainKeyword:
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

    /// Serializes the bypass country's domain rules to App Group UserDefaults
    /// so the Network Extension can match domains for country-based bypass.
    func syncBypassCountryRules() async {
        let code = AWCore.userDefaults.string(forKey: "bypassCountryCode") ?? ""
        if code.isEmpty {
            AWCore.userDefaults.removeObject(forKey: "bypassCountryDomainRules")
            return
        }
        await Task.detached {
            let rules = Self.loadRules(for: code)
            let domainRulesArray: [[String: String]] = rules.compactMap {
                switch $0.type {
                case .domain, .domainSuffix, .domainKeyword:
                    return ["type": $0.type.rawValue, "value": $0.value]
                case .ipCIDR, .ipCIDR6:
                    return nil
                }
            }
            if domainRulesArray.isEmpty {
                AWCore.userDefaults.removeObject(forKey: "bypassCountryDomainRules")
                return
            }
            if let data = try? JSONSerialization.data(withJSONObject: domainRulesArray) {
                AWCore.userDefaults.set(data, forKey: "bypassCountryDomainRules")
            }
        }.value
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dict = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { rs in
            rs.assignedConfigurationId.map { (rs.name, $0) }
        })
        AWCore.userDefaults.set(dict, forKey: Self.assignmentsKey)
    }
}
