//
//  ReorderProxiesView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/8/26.
//

import SwiftUI

struct ReorderProxiesView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    
    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    var body: some View {
        List {
            if standaloneConfigurations.count > 1 {
                Section("Proxies") {
                    ForEach(standaloneConfigurations) { configuration in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(configuration.name)
                                .font(.body.weight(.medium))
                            Text("\(configuration.serverAddress):\(String(configuration.serverPort))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .truncationMode(.middle)
                                .lineLimit(1)
                        }
                    }
                    .onMove { source, destination in
                        viewModel.moveStandaloneConfigurations(fromOffsets: source, toOffset: destination)
                    }
                }
            }
            
            if viewModel.subscriptions.count > 1 {
                Section("Subscriptions") {
                    ForEach(viewModel.subscriptions) { subscription in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(subscription.name)
                                .font(.body.weight(.medium))
                            Text(subscription.url)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .truncationMode(.middle)
                                .lineLimit(1)
                        }
                    }
                    .onMove { source, destination in
                        viewModel.moveSubscriptions(fromOffsets: source, toOffset: destination)
                    }
                }
            }
        }
        .environment(\.editMode, .constant(.active))
        .navigationTitle("Reorder Proxies")
    }
}
