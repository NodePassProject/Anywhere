//
//  SubscriptionEntity.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation

/// A proxy subscription as Shortcuts and Siri see it; rule set and module subscriptions are only refreshed in bulk.
struct SubscriptionEntity: AppEntity {
    static let typeDisplayRepresentation = TypeDisplayRepresentation(
        name: "Subscription",
        numericFormat: "\(placeholder: .int) subscriptions"
    )

    static let defaultQuery = SubscriptionEntityQuery()

    let id: UUID

    @Property(title: "Name")
    var name: String

    @Property(title: "Proxies")
    var proxyCount: Int

    @Property(title: "Last Update")
    var lastUpdate: Date?

    @Property(title: "Expiration")
    var expiration: Date?

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(
            title: "\(name)",
            subtitle: "\(proxyCount) proxies",
            image: .init(systemName: "antenna.radiowaves.left.and.right")
        )
    }

    init(subscription: Subscription, proxyCount: Int) {
        id = subscription.id
        name = subscription.name
        self.proxyCount = proxyCount
        lastUpdate = subscription.lastUpdate
        expiration = subscription.expire
    }

    @MainActor
    static func all(in container: AppContainer) async throws -> [SubscriptionEntity] {
        try await container.awaitStoresLoaded()
        var counts: [UUID: Int] = [:]
        for configuration in container.configurationStore.configurations {
            if let subscriptionId = configuration.subscriptionId {
                counts[subscriptionId, default: 0] += 1
            }
        }
        return container.subscriptionStore.subscriptions.map {
            SubscriptionEntity(subscription: $0, proxyCount: counts[$0.id] ?? 0)
        }
    }
}

// MARK: - Query

struct SubscriptionEntityQuery: EntityQuery, EntityStringQuery, EnumerableEntityQuery {
    @Dependency var container: AppContainer

    @MainActor
    func entities(for identifiers: [UUID]) async throws -> [SubscriptionEntity] {
        let all = try await SubscriptionEntity.all(in: container)
        return identifiers.compactMap { id in all.first { $0.id == id } }
    }

    @MainActor
    func entities(matching string: String) async throws -> [SubscriptionEntity] {
        try await SubscriptionEntity.all(in: container).filter {
            $0.name.localizedCaseInsensitiveContains(string)
        }
    }

    @MainActor
    func suggestedEntities() async throws -> [SubscriptionEntity] {
        try await SubscriptionEntity.all(in: container)
    }

    @MainActor
    func allEntities() async throws -> [SubscriptionEntity] {
        try await SubscriptionEntity.all(in: container)
    }
}
