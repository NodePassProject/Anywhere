//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct RuleSetListView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel
    @Bindable private var ruleSetStore = RuleSetStore.shared

    var body: some View {
        List {
            ForEach(ruleSetStore.ruleSets) { ruleSet in
                Picker(selection: Binding(
                    get: { ruleSet.assignedConfigurationId },
                    set: { newValue in
                        ruleSetStore.updateAssignment(ruleSet, configurationId: newValue)
                        viewModel.syncRoutingConfigurationToNE()
                    }
                )) {
                    Text("Default").tag(nil as String?)
                    Text("DIRECT").tag("DIRECT" as String?)
                    ForEach(viewModel.configurations) { configuration in
                        Text(configuration.name).tag(configuration.id.uuidString as String?)
                    }
                } label: {
                    Text(ruleSet.name)
                }
            }
            .listRowSpacing(8)
        }
        .navigationTitle("Routing Rules")
    }
}
