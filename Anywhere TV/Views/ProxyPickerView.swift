//
//  ProxyPickerView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/14/26.
//

import SwiftUI

struct ProxyPickerView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Environment(\.dismiss) var dismiss

    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }

    var body: some View {
        NavigationStack {
            if !viewModel.configurations.isEmpty {
                List {
                    if !standaloneConfigurations.isEmpty {
                        Section {
                            ForEach(standaloneConfigurations) { configuration in
                                proxyRow(configuration)
                            }
                        }
                    }
                    
                    ForEach(subscribedGroups, id: \.0.id) { subscription, configurations in
                        Section(subscription.name) {
                            ForEach(configurations) { configuration in
                                proxyRow(configuration)
                            }
                        }
                    }
                }
                .padding(.horizontal)
                .navigationTitle("Select Proxy")
            } else {
                ContentUnavailableView("No Proxies", systemImage: "network")
            }
        }
    }

    @ViewBuilder
    private func proxyRow(_ configuration: ProxyConfiguration) -> some View {
        Button {
            viewModel.selectedConfiguration = configuration
            dismiss()
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                Text(configuration.name)
                    .font(.body)
                Text("\(configuration.serverAddress):\(configuration.serverPort, format: .number.grouping(.never))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
