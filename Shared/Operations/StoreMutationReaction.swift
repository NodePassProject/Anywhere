//
//  StoreMutationReaction.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct StoreMutationReaction {
    let configurationStore: ConfigurationStore
    let chainStore: ChainStore
    let routingRuleSetStore: RoutingRuleSetStore
    let selection: ProxySelection
    let latency: LatencyCenter
    let tunnel: TunnelController
    let appState: AppState
    let exporter: RoutingExportScheduler

    func run() {
        let configurations = configurationStore.configurations
        let chains = chainStore.chains

        if selection.revalidate(configurations: configurations, chains: chains),
           let configuration = selection.selectedConfiguration {
            tunnel.pushConfiguration(configuration)
        }

        latency.pruneLatencyState(liveConfigurationIds: Set(configurations.map(\.id)))
        latency.pruneChainLatencyState(liveChainIds: Set(chains.map(\.id)))

        let availableIds = Set(configurations.map { $0.id.uuidString })
            .union(chains.map { $0.id.uuidString })
        let affected = routingRuleSetStore.clearOrphanedAssignments(availableIds: availableIds)
        if !affected.isEmpty { appState.orphanedRuleSetNames = affected }

        exporter.schedule()
    }
}
