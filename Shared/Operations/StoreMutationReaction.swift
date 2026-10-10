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
    let moduleStore: ModuleStore
    let selection: ProxySelection
    let latency: LatencyCenter
    let appState: AppState
    let routingExportScheduler: RoutingExportScheduler
    let mitmExportScheduler: MITMExportScheduler

    func run() {
        let configurations = configurationStore.configurations
        let chains = chainStore.chains

        selection.revalidate(configurations: configurations, chains: chains)

        latency.pruneLatencyState(liveConfigurationIds: Set(configurations.map(\.id)))
        latency.pruneChainLatencyState(liveChainIds: Set(chains.map(\.id)))

        let availableIds = Set(configurations.map { $0.id.uuidString })
            .union(chains.map { $0.id.uuidString })
        var affected = routingRuleSetStore.clearOrphanedAssignments(availableIds: availableIds)
        affected += moduleStore.clearOrphanedAssignments(availableIds: availableIds)
        if !affected.isEmpty { appState.orphanedRuleSetNames = affected }

        routingExportScheduler.schedule()
        mitmExportScheduler.schedule()
    }
}
