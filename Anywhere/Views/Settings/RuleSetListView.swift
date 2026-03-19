//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct RuleSetListView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared

    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }

    @State var routingRuleSets: [RuleSetStore.RuleSet] = RuleSetStore.shared.routingRuleSets
    @State private var pickerConfig = PickerConfig()
    @State private var editingRuleSetId: String?
    @State private var rowFrames: [String: CGRect] = [:]

    // Deterministic UUIDs for special picker items
    private static let defaultUUID = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
    private static let directUUID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    private static let rejectUUID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!

    private var pickerItems: [PickerItem] {
        var items: [PickerItem] = [
            PickerItem(id: Self.defaultUUID, name: "Default"),
            PickerItem(id: Self.directUUID, name: "DIRECT"),
            PickerItem(id: Self.rejectUUID, name: "REJECT"),
        ]
        for configuration in standaloneConfigurations {
            items.append(PickerItem(id: configuration.id, name: configuration.name))
        }
        for (_, configurations) in subscribedGroups {
            for configuration in configurations {
                items.append(PickerItem(id: configuration.id, name: configuration.name))
            }
        }
        return items
    }

    private func displayName(for configurationId: String?) -> String {
        switch configurationId {
        case nil: return "Default"
        case "DIRECT": return "DIRECT"
        case "REJECT": return "REJECT"
        default:
            if let uuid = UUID(uuidString: configurationId!),
               let config = viewModel.configurations.first(where: { $0.id == uuid }) {
                return config.name
            }
            return "Default"
        }
    }

    private func pickerUUID(for configurationId: String?) -> UUID {
        switch configurationId {
        case nil: return Self.defaultUUID
        case "DIRECT": return Self.directUUID
        case "REJECT": return Self.rejectUUID
        default:
            if let uuid = UUID(uuidString: configurationId!) {
                return uuid
            }
            return Self.defaultUUID
        }
    }

    private func configurationId(for uuid: UUID?) -> String? {
        switch uuid {
        case Self.defaultUUID: return nil
        case Self.directUUID: return "DIRECT"
        case Self.rejectUUID: return "REJECT"
        default: return uuid?.uuidString
        }
    }

    var body: some View {
        List {
            ForEach(routingRuleSets) { ruleSet in
                Button {
                    editingRuleSetId = ruleSet.id
                    pickerConfig.text = displayName(for: ruleSet.assignedConfigurationId)
                    pickerConfig.selectedId = pickerUUID(for: ruleSet.assignedConfigurationId)
                    pickerConfig.sourceFrame = rowFrames[ruleSet.id] ?? .zero
                    pickerConfig.show = true
                } label: {
                    HStack {
                        AppIconView(ruleSet.name)
                        Text(ruleSet.name)
                        Spacer()
                        HStack(spacing: 4) {
                            Text(displayName(for: ruleSet.assignedConfigurationId))
                                .foregroundStyle(.secondary)
                                .onGeometryChange(for: CGRect.self) { proxy in
                                    proxy.frame(in: .global)
                                } action: { newValue in
                                    rowFrames[ruleSet.id] = newValue
                                    if editingRuleSetId == ruleSet.id {
                                        pickerConfig.sourceFrame = newValue
                                    }
                                }
                                .opacity(pickerConfig.show && editingRuleSetId == ruleSet.id ? 0 : 1)
                            Image(systemName: "chevron.up.chevron.down")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .listRowSpacing(8)
        .navigationTitle("Routing Rules")
        .picker3D($pickerConfig, items: pickerItems)
        .onChange(of: pickerConfig.show) {
            if !pickerConfig.show, let editingId = editingRuleSetId {
                let newConfigId = configurationId(for: pickerConfig.selectedId)
                if let index = routingRuleSets.firstIndex(where: { $0.id == editingId }),
                   routingRuleSets[index].assignedConfigurationId != newConfigId {
                    routingRuleSets[index].assignedConfigurationId = newConfigId
                    RuleSetStore.shared.updateAssignment(routingRuleSets[index], configurationId: newConfigId)
                }
                viewModel.syncRoutingConfigurationToNE()
                editingRuleSetId = nil
            }
        }
        .onAppear {
            routingRuleSets = RuleSetStore.shared.routingRuleSets
        }
    }
}
