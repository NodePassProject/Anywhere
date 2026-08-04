//
//  Refreshers.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation

// MARK: - Subscriptions

@MainActor
final class SubscriptionRefresher {
    private let subscriptionStore: SubscriptionStore
    private let configurationStore: ConfigurationStore

    init(subscriptionStore: SubscriptionStore, configurationStore: ConfigurationStore) {
        self.subscriptionStore = subscriptionStore
        self.configurationStore = configurationStore
    }
    
    func refresh(_ subscription: Subscription) async throws {
        let subscriptionId = subscription.id
        let url = subscriptionStore.subscriptions.first { $0.id == subscriptionId }?.url ?? subscription.url
        let result = try await SubscriptionFetcher.fetch(url: url)

        guard let current = subscriptionStore.subscriptions.first(where: { $0.id == subscriptionId }) else { return }

        let oldConfigurations = configurationStore.configurations(for: current)
        var oldByName: [String: [ProxyConfiguration]] = [:]
        for old in oldConfigurations {
            oldByName[old.name, default: []].append(old)
        }
        var oldNameCursor: [String: Int] = [:]

        var newConfigurations: [ProxyConfiguration] = []
        for configuration in result.configurations {
            let name = configuration.name
            let cursor = oldNameCursor[name, default: 0]
            let id: UUID
            if let group = oldByName[name], cursor < group.count {
                id = group[cursor].id
                oldNameCursor[name] = cursor + 1
            } else {
                id = configuration.id
            }
            newConfigurations.append(ProxyConfiguration(
                id: id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscriptionId,
                outbound: configuration.outbound
            ))
        }

        configurationStore.replaceConfigurations(for: subscriptionId, with: newConfigurations)
        subscriptionStore.applyRefreshResult(result, to: subscriptionId)
    }
}

// MARK: - Custom Routing Rule Sets

@MainActor
final class CustomRuleSetRefresher {
    private let ruleSetStore: RoutingRuleSetStore

    init(ruleSetStore: RoutingRuleSetStore) {
        self.ruleSetStore = ruleSetStore
    }

    func refresh(_ id: UUID) async throws {
        guard let url = ruleSetStore.customRuleSet(for: id)?.subscriptionURL else {
            throw CustomRoutingRuleSetRefreshError.missingSubscriptionURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw CustomRoutingRuleSetRefreshError.invalidStatusCode(http.statusCode)
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw CustomRoutingRuleSetRefreshError.undecodableBody
        }

        let parsed = RoutingRuleSetParser.parse(body)
        guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
            throw CustomRoutingRuleSetRefreshError.tooManyRules
        }

        guard let current = ruleSetStore.customRuleSet(for: id),
              current.rules != parsed.rules else { return }
        ruleSetStore.updateCustomRuleSet(id, rules: parsed.rules)
    }
}

nonisolated enum CustomRoutingRuleSetRefreshError: LocalizedError {
    case missingSubscriptionURL
    case invalidStatusCode(Int)
    case undecodableBody
    case tooManyRules

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
        }
    }
}

// MARK: - MITM Rule Sets

@MainActor
final class MITMRuleSetRefresher {
    private let ruleSetStore: MITMRuleSetStore

    init(ruleSetStore: MITMRuleSetStore) {
        self.ruleSetStore = ruleSetStore
    }

    @discardableResult
    func refresh(id: UUID) async throws -> MITMRuleSet {
        guard let url = ruleSetStore.ruleSet(id: id)?.subscriptionURL else {
            throw MITMRuleSetRefreshError.missingSubscriptionURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw MITMRuleSetRefreshError.invalidStatusCode(http.statusCode)
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw MITMRuleSetRefreshError.undecodableBody
        }

        let parsed = MITMRuleSetParser.parse(body)
        guard parsed.rules.count <= MITMRuleSet.maxRuleCount else {
            throw MITMRuleSetRefreshError.tooManyRules
        }
        guard let updated = ruleSetStore.applyRefreshedContent(
            domainSuffixes: parsed.domainSuffixes,
            rules: parsed.rules,
            parameters: parsed.parameters,
            to: id
        ) else {
            throw MITMRuleSetRefreshError.ruleSetRemoved
        }
        return updated
    }
}
