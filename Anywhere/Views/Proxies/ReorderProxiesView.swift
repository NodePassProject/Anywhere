//
//  ReorderProxiesView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import SwiftUI

struct ReorderProxiesView: View {
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(SubscriptionStore.self) private var subscriptionStore
    @Environment(ChainStore.self) private var chainStore

    private var standaloneConfigurations: [ProxyConfiguration] {
        configStore.configurations.filter { $0.subscriptionId == nil }
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
                        configStore.moveStandaloneConfigurations(fromOffsets: source, toOffset: destination)
                    }
                }
            }
            
            if subscriptionStore.subscriptions.count > 1 {
                Section("Subscriptions") {
                    ForEach(subscriptionStore.subscriptions) { subscription in
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
                        subscriptionStore.move(fromOffsets: source, toOffset: destination)
                    }
                }
            }

            if chainStore.chains.count > 1 {
                Section("Chains") {
                    ForEach(chainStore.chains) { chain in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(chain.name)
                                .font(.body.weight(.medium))
                            Text("\(chain.proxyIds.count) proxie(s)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .onMove { source, destination in
                        chainStore.move(fromOffsets: source, toOffset: destination)
                    }
                }
            }
        }
        .environment(\.editMode, .constant(.active))
        .navigationTitle("Reorder Proxies")
    }
}
