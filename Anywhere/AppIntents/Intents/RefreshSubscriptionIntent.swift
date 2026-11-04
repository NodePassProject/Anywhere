//
//  RefreshSubscriptionIntent.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation

struct RefreshSubscriptionIntent: AppIntent {
    static let title: LocalizedStringResource = "Update Subscription"
    static let description = IntentDescription(
        "Fetches a proxy subscription again and replaces its proxies with the latest list."
    )

    static var parameterSummary: some ParameterSummary {
        Summary("Update \(\.$subscription)")
    }

    @Parameter(title: "Subscription", requestValueDialog: "Which subscription?")
    var subscription: SubscriptionEntity

    @Dependency var container: AppContainer
    @Dependency var operations: Operations

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<SubscriptionEntity> & ProvidesDialog {
        try await container.awaitStoresLoaded()

        guard let record = container.subscriptionStore.subscriptions.first(where: { $0.id == subscription.id }) else {
            throw AnywhereIntentError.subscriptionNotFound
        }
        do {
            try await operations.subscriptions.refresh(record)
        } catch {
            throw AnywhereIntentError.refreshFailed(record.name, error.localizedDescription)
        }

        let updated = try await SubscriptionEntity.all(in: container).first { $0.id == record.id } ?? subscription
        return .result(value: updated, dialog: "Updated \(updated.name) with \(updated.proxyCount) proxies.")
    }
}
