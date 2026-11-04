//
//  RefreshAllSubscriptionsIntent.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation

struct RefreshAllSubscriptionsIntent: AppIntent {
    static let title: LocalizedStringResource = "Update All Subscriptions"
    static let description = IntentDescription(
        "Re-fetches every proxy subscription, subscribed rule set, and subscribed module."
    )

    private static let maxConcurrentRefreshes = 4

    @Dependency var container: AppContainer
    @Dependency var operations: Operations

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<Int> & ProvidesDialog {
        try await container.awaitStoresLoaded()

        let jobs = collectJobs()
        guard !jobs.isEmpty else {
            return .result(value: 0, dialog: "There are no subscriptions to update.")
        }

        let outcomes = await Self.run(jobs)
        let failures = outcomes.filter { $0.failure != nil }
        let succeeded = outcomes.count - failures.count
        let failureList = failures.map { "\($0.name): \($0.failure ?? "")" }.joined(separator: ", ")

        if succeeded == 0 {
            throw AnywhereIntentError.refreshAllFailed(failureList)
        }
        if !failures.isEmpty {
            return .result(
                value: succeeded,
                dialog: "Updated \(succeeded) of \(outcomes.count) subscriptions. Failed: \(failureList)"
            )
        }

        let proxies = outcomes.filter { $0.kind == .proxy }.count
        let ruleSets = outcomes.filter { $0.kind == .ruleSet }.count
        let modules = outcomes.filter { $0.kind == .module }.count
        return .result(
            value: succeeded,
            dialog: "Updated \(proxies) proxy subscriptions, \(ruleSets) rule sets and \(modules) modules."
        )
    }

    // MARK: - Jobs

    private enum Kind {
        case proxy
        case ruleSet
        case module
    }

    private struct Job: Sendable {
        let name: String
        let kind: Kind
        let refresh: @Sendable () async throws -> Void
    }

    private struct Outcome {
        let name: String
        let kind: Kind
        let failure: String?
    }

    @MainActor
    private func collectJobs() -> [Job] {
        let operations = self.operations
        var jobs: [Job] = []

        for subscription in container.subscriptionStore.subscriptions {
            jobs.append(Job(name: subscription.name, kind: .proxy) {
                try await operations.subscriptions.refresh(subscription)
            })
        }
        for ruleSet in container.routingRuleSetStore.customRuleSets where ruleSet.subscriptionURL != nil {
            let id = ruleSet.id
            jobs.append(Job(name: ruleSet.name, kind: .ruleSet) {
                try await operations.routingRuleSets.refresh(id)
            })
        }
        for ruleSet in container.mitmRuleSetStore.ruleSets where ruleSet.subscriptionURL != nil {
            let id = ruleSet.id
            jobs.append(Job(name: ruleSet.name, kind: .ruleSet) {
                try await operations.mitmRuleSets.refresh(id: id)
            })
        }
        for module in container.moduleStore.modules where module.isSubscribed {
            let id = module.id
            jobs.append(Job(name: module.name, kind: .module) {
                try await operations.modules.refresh(id: id)
            })
        }
        return jobs
    }

    private static func run(_ jobs: [Job]) async -> [Outcome] {
        await withTaskGroup(of: Outcome.self, returning: [Outcome].self) { group in
            var pending = jobs.makeIterator()
            func enqueueNext() {
                guard let job = pending.next() else { return }
                group.addTask {
                    do {
                        try await job.refresh()
                        return Outcome(name: job.name, kind: job.kind, failure: nil)
                    } catch {
                        return Outcome(name: job.name, kind: job.kind, failure: error.localizedDescription)
                    }
                }
            }
            for _ in 0..<maxConcurrentRefreshes { enqueueNext() }

            var outcomes: [Outcome] = []
            for await outcome in group {
                outcomes.append(outcome)
                enqueueNext()
            }
            return outcomes
        }
    }
}
