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

    var body: some View {
        List {
            ForEach($routingRuleSets) { $ruleSet in
                Picker(selection: $ruleSet.assignedConfigurationId) {
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
                        AppIconView(ruleSet.name)
                        Text(ruleSet.name)
                    }
                }
            }
            .onChange(of: routingRuleSets) { oldValue, newValue in
                for currentRoutingRuleSet in newValue {
                    let previousRoutingRuleSet = oldValue.first(where: { $0.id == currentRoutingRuleSet.id })
                    if currentRoutingRuleSet.assignedConfigurationId != previousRoutingRuleSet?.assignedConfigurationId {
                        RuleSetStore.shared.updateAssignment(currentRoutingRuleSet, configurationId: currentRoutingRuleSet.assignedConfigurationId)
                    }
                }
                Task { await viewModel.syncRoutingConfigurationToNE() }
            }
        }
        .listRowSpacing(8)
        .navigationTitle("Routing Rules")
        .onAppear {
            routingRuleSets = RuleSetStore.shared.routingRuleSets
        }
    }
}
