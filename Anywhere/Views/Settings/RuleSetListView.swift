//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct RuleSetListView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    // Workaround: SwiftUI view redraw bugs
    @State private var shouldRefreshList: Bool = false
    
    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }

    private var routingRuleSets: [RuleSetStore.RuleSet] {
        RuleSetStore.shared.ruleSets.filter { $0.name != "ADBlock" }
    }

    var body: some View {
        List {
            let shouldRefreshList = !shouldRefreshList
            ForEach(routingRuleSets) { ruleSet in
                Picker(selection: Binding(
                    get: { ruleSet.assignedConfigurationId },
                    set: { newValue in
                        RuleSetStore.shared.updateAssignment(ruleSet, configurationId: newValue)
                        viewModel.syncRoutingConfigurationToNE()
                        self.shouldRefreshList.toggle()
                    }
                )) {
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
        }
        .listRowSpacing(8)
        .navigationTitle("Routing Rules")
    }
}
