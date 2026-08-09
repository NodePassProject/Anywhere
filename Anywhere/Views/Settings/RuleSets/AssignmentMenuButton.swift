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
                Text("Default").tag(nil as String?)
                Text("DIRECT").tag("DIRECT" as String?)
                Text("REJECT").tag("REJECT" as String?)
            }
            Menu("Servers") {
                Picker("Servers", selection: $selection) {
                    ForEach(ungroupedProxyItems) { item in
                        Text(item.name).tag(item.id.uuidString as String?)
                    }
                }
            }
            if !chainStore.pickerItems.isEmpty {
                Menu("Chains") {
                    Picker("Chains", selection: $selection) {
                        ForEach(chainStore.pickerItems) { item in
                            Text(item.name).tag(item.id.uuidString as String?)
                        }
                    }
                }
            }
            Section("Groups") {
                ForEach(serverGroups) { group in
                    let members = memberItems(of: group)
                    if !members.isEmpty {
                        Menu(group.name) {
                            Picker(group.name, selection: $selection) {
                                ForEach(members) { item in
                                    Text(item.name).tag(item.id.uuidString as String?)
                                }
                            }
                        }
                    }
                }
            }
            Section("Subscriptions") {
                ForEach(subscriptionStore.pickerSections) { section in
                    Menu(section.header ?? "") {
                        Picker(section.header ?? "", selection: $selection) {
                            ForEach(section.items) { item in
                                Text(item.name).tag(item.id.uuidString as String?)
                            }
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
        return configurationStore.standalonePickerItems.filter { !grouped.contains($0.id) }
    }

    private func memberItems(of group: ProxyGroup) -> [PickerItem] {
        group.memberIds.compactMap { id in
            configurationStore.configurations
                .first { $0.id == id }
                .map { PickerItem(id: $0.id, name: $0.name) }
        }
    }
}

struct AssignmentLabel: View {
    let assignedConfigurationId: String?

    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore

    var body: some View {
        HStack {
            if let assignedId = assignedConfigurationId {
                if assignedId == "DIRECT" {
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
