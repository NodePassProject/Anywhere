//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct RuleSetListView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel
    // Workaround: SwiftUI view redraw bugs
    @State private var shouldRefreshList: Bool = false
    
    private var standaloneConfigurations: [VLESSConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [VLESSConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }

    var body: some View {
        List {
            let shouldRefreshList = !shouldRefreshList
            ForEach(RuleSetStore.shared.ruleSets) { ruleSet in
                Picker(selection: Binding(
                    get: { ruleSet.assignedConfigurationId },
                    set: { newValue in
                        self.shouldRefreshList.toggle()
                        RuleSetStore.shared.updateAssignment(ruleSet, configurationId: newValue)
                        viewModel.syncRoutingConfigurationToNE()
                    }
                )) {
                    Text("Default").tag(nil as String?)
                    Text("DIRECT").tag("DIRECT" as String?)
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
                    HStack(spacing: 12) {
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
