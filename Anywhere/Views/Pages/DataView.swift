//
//  DataView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct DataView: View {
    @Environment(AppSettings.self) private var appSettings
    @Environment(Operations.self) private var operations
    @Environment(SubscriptionStore.self) private var subscriptionStore
    @Environment(RoutingRuleSetStore.self) private var routingRuleSetStore
    @Environment(MITMRuleSetStore.self) private var mitmRuleSetStore
    @Environment(ModuleStore.self) private var moduleStore

    @State private var isUpdating = false
    @State private var updateSucceeded = false
    @State private var updateError: String?

    private enum SubscribedItem {
        case proxies(Subscription)
        case routingRuleSet(CustomRoutingRuleSet)
        case mitmRuleSet(MITMRuleSet)
        case module(Module)

        var name: String {
            switch self {
            case .proxies(let subscription): subscription.name
            case .routingRuleSet(let ruleSet): ruleSet.name
            case .mitmRuleSet(let ruleSet): ruleSet.name
            case .module(let module): module.name
            }
        }

        func refresh(using operations: Operations) async throws {
            switch self {
            case .proxies(let subscription):
                try await operations.subscriptions.refresh(subscription)
            case .routingRuleSet(let ruleSet):
                try await operations.routingRuleSets.refresh(ruleSet.id)
            case .mitmRuleSet(let ruleSet):
                try await operations.mitmRuleSets.refresh(id: ruleSet.id)
            case .module(let module):
                try await operations.modules.refresh(id: module.id)
            }
        }
    }

    private var subscribedItems: [SubscribedItem] {
        subscriptionStore.subscriptions.map(SubscribedItem.proxies)
            + routingRuleSetStore.customRuleSets.filter { $0.subscriptionURL != nil }.map(SubscribedItem.routingRuleSet)
            + mitmRuleSetStore.ruleSets.filter { $0.subscriptionURL != nil }.map(SubscribedItem.mitmRuleSet)
            + moduleStore.modules.filter(\.isSubscribed).map(SubscribedItem.module)
    }

    var body: some View {
        NavigationStack {
            @Bindable var appSettings = appSettings
            Form {
                Section {
                    Toggle(isOn: $appSettings.iCloudSyncEnabled) {
                        TextWithColorfulIcon(title: "iCloud Sync", systemName: "icloud.fill", foregroundStyle: .blue, backgroundStyle: .white.gradient)
                    }
                }
                
                Section {
                    Button {
                        updateAllSubscriptions()
                    } label: {
                        HStack {
                            Label("Update All Subscriptions", systemImage: updateSucceeded ? "checkmark" : "arrow.clockwise")
                                .contentTransition(.symbolEffect(.replace))
                            if isUpdating {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(isUpdating || subscribedItems.isEmpty)
                } footer: {
                    Text("Re-fetches every proxy subscription, subscribed rule set, and subscribed module.")
                }
            }
            .navigationTitle("Data")
            .alert("Update Failed", isPresented: Binding(
                get: { updateError != nil },
                set: { if !$0 { updateError = nil } }
            )) {
                Button("OK") { updateError = nil }
            } message: {
                Text(updateError ?? "")
            }
        }
    }

    private func updateAllSubscriptions() {
        guard !isUpdating else { return }
        let items = subscribedItems
        guard !items.isEmpty else { return }
        isUpdating = true
        Task {
            var failures: [String] = []
            await withTaskGroup(of: String?.self) { group in
                for item in items {
                    let name = item.name
                    group.addTask {
                        do {
                            try await item.refresh(using: operations)
                            return nil
                        } catch {
                            return "\(name): \(error.localizedDescription)"
                        }
                    }
                }
                for await failure in group {
                    if let failure {
                        failures.append(failure)
                    }
                }
            }
            isUpdating = false
            if failures.isEmpty {
                updateSucceeded = true
                try? await Task.sleep(for: .seconds(2))
                updateSucceeded = false
            } else {
                updateError = failures.joined(separator: "\n")
            }
        }
    }
}
