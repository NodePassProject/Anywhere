//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct RuleSetListView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    
    private var experimentalEnabled: Bool {
        AWCore.getExperimentalEnabled()
    }
    
    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }
    
    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }
    
    @State var builtInServiceRuleSets: [RuleSetStore.RuleSet] = RuleSetStore.shared.builtInServiceRuleSets
    @State var customRuleSets: [RuleSetStore.CustomRuleSet] = RuleSetStore.shared.customRuleSets
    @State private var showAddSheet = false
    @State private var newRuleSetName = ""
    
    var body: some View {
        List {
            Section {
                ForEach($builtInServiceRuleSets) { $ruleSet in
                    if !ruleSet.isCustom {
                        assignmentPicker(for: $ruleSet)
                    }
                }
            }
            if !customRuleSets.isEmpty {
                Section {
                    ForEach(customRuleSets) { custom in
                        NavigationLink {
                            CustomRuleSetDetailView(customRuleSetId: custom.id)
                        } label: {
                            HStack {
                                Image(systemName: "list.bullet.rectangle")
                                    .foregroundStyle(.secondary)
                                    .frame(width: 32, height: 32)
                                VStack(alignment: .leading) {
                                    Text(custom.name)
                                    Text("\(custom.rules.count) rule(s)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if let ruleSet = builtInServiceRuleSets.first(where: { $0.id == custom.id.uuidString }) {
                                    assignmentLabel(for: ruleSet)
                                }
                            }
                        }
                    }
                    .onDelete { offsets in
                        let customs = RuleSetStore.shared.customRuleSets
                        for offset in offsets {
                            RuleSetStore.shared.removeCustomRuleSet(customs[offset].id)
                        }
                        customRuleSets = RuleSetStore.shared.customRuleSets
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                    }
                } header: {
                    Text("Custom")
                }
            }
        }
        .listRowSpacing(8)
        .navigationTitle("Routing Rules")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu("More", systemImage: "ellipsis") {
                    if experimentalEnabled {
                        Button {
                            showAddSheet = true
                        } label: {
                            Label("New Rule Set", systemImage: "plus")
                        }
                    }
                    Button {
                        RuleSetStore.shared.resetAssignments()
                        builtInServiceRuleSets = RuleSetStore.shared.builtInServiceRuleSets
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                    } label: {
                        Label("Reset", systemImage: "arrow.clockwise")
                    }
                }
            }
        }
        .onChange(of: builtInServiceRuleSets) { oldValue, newValue in
            for currentRuleSet in newValue {
                let previousRuleSet = oldValue.first(where: { $0.id == currentRuleSet.id })
                if currentRuleSet.assignedConfigurationId != previousRuleSet?.assignedConfigurationId {
                    RuleSetStore.shared.updateAssignment(currentRuleSet, configurationId: currentRuleSet.assignedConfigurationId)
                }
            }
            Task { await viewModel.syncRoutingConfigurationToNE() }
        }
        .onAppear {
            builtInServiceRuleSets = RuleSetStore.shared.builtInServiceRuleSets
            customRuleSets = RuleSetStore.shared.customRuleSets
        }
        .alert("New Rule Set", isPresented: $showAddSheet) {
            TextField("Name", text: $newRuleSetName)
            Button("Add") {
                let name = newRuleSetName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                _ = RuleSetStore.shared.addCustomRuleSet(name: name)
                customRuleSets = RuleSetStore.shared.customRuleSets
                newRuleSetName = ""
            }
            Button("Cancel", role: .cancel) {
                newRuleSetName = ""
            }
        }
    }
    
    @ViewBuilder
    private func assignmentPicker(for ruleSet: Binding<RuleSetStore.RuleSet>) -> some View {
        Picker(selection: ruleSet.assignedConfigurationId) {
            Text("Default").tag(nil as String?)
            Text("DIRECT").tag("DIRECT" as String?)
            Text("REJECT").tag("REJECT" as String?)
            ForEach(standaloneConfigurations) { configuration in
                Text(configuration.name).tag(configuration.id.uuidString as String?)
            }
            ForEach(subscribedGroups, id: \.0.id) { subscription, configurations in
                Section {
                    ForEach(configurations) { configuration in
                        Text(configuration.name).tag(configuration.id.uuidString as String?)
                    }
                } header: {
                    Text(subscription.name)
                }
            }
        } label: {
            HStack {
                AppIconView(ruleSet.wrappedValue.name)
                Text(ruleSet.wrappedValue.name)
            }
        }
    }
    
    @ViewBuilder
    private func assignmentLabel(for ruleSet: RuleSetStore.RuleSet) -> some View {
        HStack {
            if let assignedId = ruleSet.assignedConfigurationId {
                if assignedId == "DIRECT" {
                    Text("DIRECT")
                } else if assignedId == "REJECT" {
                    Text("REJECT")
                } else if let config = viewModel.configurations.first(where: { $0.id.uuidString == assignedId }) {
                    Text(config.name)
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
