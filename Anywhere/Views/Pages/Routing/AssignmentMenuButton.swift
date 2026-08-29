//
//  AssignmentMenuButton.swift
//  Anywhere
//
//  Created by NodePassProject on 8/9/26.
//

import SwiftUI

struct AssignmentMenuButton: View {
    @Binding var selection: String?

    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    var body: some View {
        Menu {
            Picker("Policies", selection: $selection) {
                Label("Default", systemImage: "diamond").tag(nil as String?)
                Label("PROXY", systemImage: "circle.grid.2x1.right.filled").tag("PROXY" as String?)
                Label("DIRECT", systemImage: "arrow.right").tag("DIRECT" as String?)
                Label("REJECT", systemImage: "slash.circle").tag("REJECT" as String?)
            }
            Menu {
                Picker("Servers", selection: $selection) {
                    ForEach(ungroupedProxyItems) { item in
                        Text(item.name).tag(item.id.uuidString as String?)
                    }
                }
            } label: {
                Label("Servers", systemImage: "server.rack")
            }
            let chains = chainItems
            if !chains.isEmpty {
                Menu {
                    Picker("Chains", selection: $selection) {
                        ForEach(chains) { item in
                            Text(item.name).tag(item.id.uuidString as String?)
                        }
                    }
                } label: {
                    Label("Chains", systemImage:  "point.bottomleft.forward.to.point.topright.scurvepath.fill")
                }
            }
            Section("Groups") {
                ForEach(serverGroups) { group in
                    let members = memberItems(of: group)
                    if !members.isEmpty {
                        Menu {
                            Picker(group.name, selection: $selection) {
                                ForEach(members) { item in
                                    Text(item.name).tag(item.id.uuidString as String?)
                                }
                            }
                        } label: {
                            Label(group.name, systemImage: "folder")
                        }
                    }
                }
            }
            Section("Subscriptions") {
                ForEach(subscriptionStore.subscriptions) { subscription in
                    let members = memberItems(of: subscription)
                    if !members.isEmpty {
                        Menu {
                            Picker(subscription.name, selection: $selection) {
                                ForEach(members) { item in
                                    Text(item.name).tag(item.id.uuidString as String?)
                                }
                            }
                        } label: {
                            Label(subscription.name, systemImage: "globe")
                        }
                    }
                }
            }
        } label: {
            HStack {
                AssignmentLabel(assignedConfigurationId: selection)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
    }
    
    private var serverGroups: [ProxyGroup] {
        groupStore.groups(of: .servers)
    }
    
    private var ungroupedProxyItems: [PickerItem] {
        let grouped = Set(serverGroups.flatMap(\.memberIds))
        return configurationStore.configurations
            .filter { $0.subscriptionId == nil && !grouped.contains($0.id) }
            .map { PickerItem(id: $0.id, name: $0.name) }
    }

    private var chainItems: [PickerItem] {
        chainStore.chains.compactMap { chain in
            let proxies = chain.resolveProxies(from: configurationStore.configurations)
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { return nil }
            return PickerItem(id: chain.id, name: chain.name)
        }
    }

    private func memberItems(of group: ProxyGroup) -> [PickerItem] {
        group.memberIds.compactMap { id in
            configurationStore.configurations
                .first { $0.id == id }
                .map { PickerItem(id: $0.id, name: $0.name) }
        }
    }

    private func memberItems(of subscription: Subscription) -> [PickerItem] {
        configurationStore.configurations
            .filter { $0.subscriptionId == subscription.id }
            .map { PickerItem(id: $0.id, name: $0.name) }
    }
}

struct AssignmentLabel: View {
    let assignedConfigurationId: String?

    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore

    var body: some View {
        HStack {
            if let assignedId = assignedConfigurationId {
                if assignedId == "PROXY" {
                    Text("PROXY")
                } else if assignedId == "DIRECT" {
                    Text("DIRECT")
                } else if assignedId == "REJECT" {
                    Text("REJECT")
                } else if let config = configurationStore.configurations.first(where: { $0.id.uuidString == assignedId }) {
                    Text(config.name)
                } else if let chain = chainStore.chains.first(where: { $0.id.uuidString == assignedId }) {
                    Text(chain.name)
                } else {
                    Text("Default")
                }
            } else {
                Text("Default")
            }
        }
        .foregroundStyle(.secondary)
    }
}
