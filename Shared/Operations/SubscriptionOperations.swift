//
//  SubscriptionOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct SubscriptionOperations {
    let store: SubscriptionStore
    let configurationStore: ConfigurationStore
    let reaction: StoreMutationReaction

    func add(_ subscription: Subscription, configurations: [ProxyConfiguration]) {
        store.add(subscription)
        let tagged = configurations.map { configuration in
            ProxyConfiguration(
                id: configuration.id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscription.id,
                outbound: configuration.outbound
            )
        }
        configurationStore.replaceConfigurations(for: subscription.id, with: tagged)
        reaction.run()
    }
    
    func delete(_ subscription: Subscription) {
        configurationStore.deleteConfigurations(for: subscription.id)
        store.delete(subscription)
        reaction.run()
    }

    func rename(_ subscription: Subscription, to newName: String) {
        store.rename(subscription, to: newName)
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        store.move(fromOffsets: source, toOffset: destination)
    }
    
    func refresh(_ subscription: Subscription) async throws {
        let subscriptionId = subscription.id
        let url = store.subscriptions.first { $0.id == subscriptionId }?.url ?? subscription.url
        let result = try await SubscriptionFetcher.fetch(url: url)

        guard let current = store.subscriptions.first(where: { $0.id == subscriptionId }) else { return }

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
        store.applyRefreshResult(result, to: subscriptionId)
        reaction.run()
    }
}
