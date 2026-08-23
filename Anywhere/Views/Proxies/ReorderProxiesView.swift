//
//  ReorderProxiesView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import SwiftUI

struct ReorderView: View {
    @Environment(Operations.self) private var operations
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    private var groupedServerIds: Set<UUID> {
        Set(groupStore.groups(of: .servers).flatMap(\.memberIds))
    }

    private var groupedChainIds: Set<UUID> {
        Set(groupStore.groups(of: .chains).flatMap(\.memberIds))
    }

    private var ungroupedStandaloneConfigurations: [ProxyConfiguration] {
        configurationStore.configurations.filter { $0.subscriptionId == nil && !groupedServerIds.contains($0.id) }
    }

    private var ungroupedChains: [ProxyChain] {
        chainStore.chains.filter { !groupedChainIds.contains($0.id) }
    }

    var body: some View {
        List {
            let standalone = ungroupedStandaloneConfigurations
            if standalone.count > 1 {
                Section("Proxies") {
                    ForEach(standalone) { configuration in
                        configurationRow(configuration)
                    }
                    .onMove { source, destination in
                        operations.configurations.move(withIds: standalone.map(\.id), fromOffsets: source, toOffset: destination)
                    }
                }
            }

            let chains = ungroupedChains
            if chains.count > 1 {
                Section("Chains") {
                    ForEach(chains) { chain in
                        chainRow(chain)
                    }
                    .onMove { source, destination in
                        operations.chains.move(withIds: chains.map(\.id), fromOffsets: source, toOffset: destination)
                    }
                }
            }

            let serverGroups = groupStore.groups(of: .servers)
            if serverGroups.count > 1 {
                Section("Server Groups") {
                    ForEach(serverGroups) { group in
                        groupRow(group)
                    }
                    .onMove { source, destination in
                        operations.groups.move(.servers, fromOffsets: source, toOffset: destination)
                    }
                }
            }

            let chainGroups = groupStore.groups(of: .chains)
            if chainGroups.count > 1 {
                Section("Chain Groups") {
                    ForEach(chainGroups) { group in
                        groupRow(group)
                    }
                    .onMove { source, destination in
                        operations.groups.move(.chains, fromOffsets: source, toOffset: destination)
                    }
                }
            }

            if subscriptionStore.subscriptions.count > 1 {
                Section("Subscriptions") {
                    ForEach(subscriptionStore.subscriptions) { subscription in
                        subscriptionRow(subscription)
                    }
                    .onMove { source, destination in
                        operations.subscriptions.move(fromOffsets: source, toOffset: destination)
                    }
                }
            }
        }
        .environment(\.editMode, .constant(.active))
        .navigationTitle("Reorder")
    }

    // MARK: - Rows

    private func configurationRow(_ configuration: ProxyConfiguration) -> some View {
        Text(configuration.name)
            .font(.body.weight(.medium))
    }

    private func chainRow(_ chain: ProxyChain) -> some View {
        Text(chain.name)
            .font(.body.weight(.medium))
    }

    private func groupRow(_ group: ProxyGroup) -> some View {
        Text(group.name)
            .font(.body.weight(.medium))
    }

    private func subscriptionRow(_ subscription: Subscription) -> some View {
        Text(subscription.name)
            .font(.body.weight(.medium))
    }
}
