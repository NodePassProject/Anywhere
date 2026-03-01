//
//  DomainRouter.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "DomainRouter")

enum RouteAction {
    case direct
    case proxy(UUID)
}

class DomainRouter {

    // Compiled rules
    private var exactDomains: [String: RouteAction] = [:]
    private var suffixRules: [(suffix: String, action: RouteAction)] = []
    private var keywordRules: [(keyword: String, action: RouteAction)] = []

    // Proxy configurations for rule-assigned proxies
    private var configurationMap: [UUID: VLESSConfiguration] = [:]

    /// Reads routing.json from the App Group container and compiles rules.
    func loadRoutingConfiguration() {
        exactDomains.removeAll()
        suffixRules.removeAll()
        keywordRules.removeAll()
        configurationMap.removeAll()

        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.argsment.Anywhere") else {
            logger.error("[DomainRouter] App Group container not available")
            return
        }

        let routingURL = containerURL.appendingPathComponent("routing.json")
        guard let data = try? Data(contentsOf: routingURL),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            logger.info("[DomainRouter] No routing.json or invalid format")
            return
        }

        // Parse configurations
        if let configurations = json["configs"] as? [String: Any] {
            for (key, value) in configurations {
                guard let configurationId = UUID(uuidString: key),
                      let configurationDict = value as? [String: Any] else { continue }
                if let configuration = VLESSConfiguration.parse(from: configurationDict) {
                    configurationMap[configurationId] = configuration
                }
            }
        }

        // Parse rules
        guard let rules = json["rules"] as? [[String: Any]] else {
            logger.warning("[DomainRouter] routing.json has no 'rules' array")
            return
        }
        var ruleCount = 0

        for rule in rules {
            guard let actionStr = rule["action"] as? String,
                  let domainRules = rule["domainRules"] as? [[String: String]] else { continue }

            let action: RouteAction
            if actionStr == "direct" {
                action = .direct
            } else if actionStr == "proxy", let configurationIdStr = rule["configId"] as? String, let configurationId = UUID(uuidString: configurationIdStr) {
                action = .proxy(configurationId)
            } else {
                continue
            }

            for dr in domainRules {
                guard let typeStr = dr["type"], let value = dr["value"] else { continue }
                let lowered = value.lowercased()

                switch typeStr {
                case "domain":
                    exactDomains[lowered] = action
                    ruleCount += 1
                case "domainSuffix":
                    suffixRules.append((suffix: lowered, action: action))
                    ruleCount += 1
                case "domainKeyword":
                    keywordRules.append((keyword: lowered, action: action))
                    ruleCount += 1
                default:
                    break
                }
            }
        }

        logger.info("[DomainRouter] Loaded \(ruleCount) rules, \(self.configurationMap.count) configurations")
    }

    /// Whether any routing rules have been loaded.
    var hasRules: Bool {
        !exactDomains.isEmpty || !suffixRules.isEmpty || !keywordRules.isEmpty
    }

    /// Matches a domain against routing rules. Returns nil if no rule matches.
    func matchDomain(_ domain: String) -> RouteAction? {
        let lowered = domain.lowercased()
        guard !lowered.isEmpty else { return nil }

        // 1. Exact match (O(1))
        if let action = exactDomains[lowered] {
            return action
        }

        // 2. Suffix match
        for rule in suffixRules {
            if lowered == rule.suffix || lowered.hasSuffix("." + rule.suffix) {
                return rule.action
            }
        }

        // 3. Keyword match
        for rule in keywordRules {
            if lowered.contains(rule.keyword) {
                return rule.action
            }
        }

        return nil
    }

    /// Resolves a RouteAction to a VLESSConfiguration.
    /// Returns nil for .direct or when the configuration UUID is not found.
    func resolveConfiguration(action: RouteAction) -> VLESSConfiguration? {
        switch action {
        case .direct:
            return nil
        case .proxy(let id):
            return configurationMap[id]
        }
    }
}
