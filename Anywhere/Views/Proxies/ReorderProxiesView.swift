//
//  ReorderProxiesView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import SwiftUI

enum ReorderScope: Hashable, Identifiable {
    case topLevel
    case subscription(UUID)
    case group(UUID)

    var id: Self { self }
}

struct ReorderView: View {
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    var scope: ReorderScope = .topLevel

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
            switch scope {
            case .topLevel:
                topLevelSections
            case .subscription(let id):
                if let subscription = subscriptionStore.subscriptions.first(where: { $0.id == id }) {
                    subscriptionRows(subscription)
                }
            case .group(let id):
                if let group = groupStore.groups.first(where: { $0.id == id }) {
                    groupMemberRows(group)
                }
            }
        }
        .environment(\.editMode, .constant(.active))
        .navigationTitle(title)
    }

    private var title: String {
        switch scope {
        case .topLevel:
            String(localized: "Reorder")
        case .subscription(let id):
            subscriptionStore.subscriptions.first(where: { $0.id == id })?.name ?? String(localized: "Reorder")
        case .group(let id):
            groupStore.groups.first(where: { $0.id == id })?.name ?? String(localized: "Reorder")
        }
    }

    // MARK: - Top Level

    @ViewBuilder
    private var topLevelSections: some View {
        let standalone = ungroupedStandaloneConfigurations
        if standalone.count > 1 {
            Section("Proxies") {
                ForEach(standalone) { configuration in
                    configurationRow(configuration)
                }
                .onMove { source, destination in
                    configurationStore.moveConfigurations(withIds: standalone.map(\.id), fromOffsets: source, toOffset: destination)
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
                    chainStore.moveChains(withIds: chains.map(\.id), fromOffsets: source, toOffset: destination)
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
                    groupStore.move(.servers, fromOffsets: source, toOffset: destination)
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
                    groupStore.move(.chains, fromOffsets: source, toOffset: destination)
                }
            }
        }

        if subscriptionStore.subscriptions.count > 1 {
            Section("Subscriptions") {
                ForEach(subscriptionStore.subscriptions) { subscription in
                    subscriptionRow(subscription)
                }
                .onMove { source, destination in
                    subscriptionStore.move(fromOffsets: source, toOffset: destination)
                }
            }
        }
    }

    // MARK: - Scoped Rows

    @ViewBuilder
    private func subscriptionRows(_ subscription: Subscription) -> some View {
        let configurations = configurationStore.configurations(for: subscription)
        Section("Proxies") {
            ForEach(configurations) { configuration in
                configurationRow(configuration)
            }
            .onMove { source, destination in
                configurationStore.moveConfigurations(withIds: configurations.map(\.id), fromOffsets: source, toOffset: destination)
            }
        }
    }

    @ViewBuilder
    private func groupMemberRows(_ group: ProxyGroup) -> some View {
        switch group.kind {
        case .servers:
            let members = group.memberIds.compactMap { id in
                configurationStore.configurations.first { $0.id == id }
            }
            Section("Proxies") {
                ForEach(members) { configuration in
                    configurationRow(configuration)
                }
                .onMove { source, destination in
                    groupStore.moveMembers(of: group.id, withIds: members.map(\.id), fromOffsets: source, toOffset: destination)
                }
            }
        case .chains:
            let members = group.memberIds.compactMap { id in
                chainStore.chains.first { $0.id == id }
            }
            Section("Chains") {
                ForEach(members) { chain in
                    chainRow(chain)
                }
                .onMove { source, destination in
                    groupStore.moveMembers(of: group.id, withIds: members.map(\.id), fromOffsets: source, toOffset: destination)
                }
            }
        }
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
