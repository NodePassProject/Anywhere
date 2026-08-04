//
//  StoreCoordinator.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation

@MainActor
final class StoreCoordinator {
    private let configurationStore: ConfigurationStore
    private let chainStore: ChainStore
    private let subscriptionStore: SubscriptionStore
    private let routingRuleSetStore: RoutingRuleSetStore
    private let mitmRuleSetStore: MITMRuleSetStore
    private let selection: ProxySelection
    private let latency: LatencyCenter
    private let routingExporter: RoutingExporter
    private let appState: AppState

    init(
        configurationStore: ConfigurationStore,
        chainStore: ChainStore,
        subscriptionStore: SubscriptionStore,
        routingRuleSetStore: RoutingRuleSetStore,
        mitmRuleSetStore: MITMRuleSetStore,
        selection: ProxySelection,
        latency: LatencyCenter,
        routingExporter: RoutingExporter,
        appState: AppState
    ) {
        self.configurationStore = configurationStore
        self.chainStore = chainStore
        self.subscriptionStore = subscriptionStore
        self.routingRuleSetStore = routingRuleSetStore
        self.mitmRuleSetStore = mitmRuleSetStore
        self.selection = selection
        self.latency = latency
        self.routingExporter = routingExporter
        self.appState = appState
    }
    
    func activate() {
        configurationStore.onDidMutate = { [weak self] in self?.configurationsChanged() }
        chainStore.onDidMutate = { [weak self] in self?.chainsChanged() }
        chainsChanged()
    }

    // MARK: - Mutation Reactions

    private func configurationsChanged() {
        let configurations = configurationStore.configurations
        let chains = chainStore.chains
        selection.revalidateSelection(configurations: configurations, chains: chains)
        latency.pruneLatencyState(liveConfigurationIds: Set(configurations.map(\.id)))
        clearOrphans(configurations: configurations, chains: chains)
        routingExporter.scheduleExport()
    }

    private func chainsChanged() {
        latency.pruneChainLatencyState(liveChainIds: Set(chainStore.chains.map(\.id)))
        guard configurationStore.isLoaded else { return }
        let configurations = configurationStore.configurations
        selection.revalidateSelection(configurations: configurations, chains: chainStore.chains)
        clearOrphans(configurations: configurations, chains: chainStore.chains)
        routingExporter.scheduleExport()
    }
    
    private func clearOrphans(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        let availableIds = Set(configurations.map { $0.id.uuidString })
            .union(chains.map { $0.id.uuidString })
        let affected = routingRuleSetStore.clearOrphanedAssignments(availableIds: availableIds)
        if !affected.isEmpty { appState.orphanedRuleSetNames = affected }
    }

    // MARK: - Remote Reload
    
    func reloadAll() async {
        await subscriptionStore.reload()
        await chainStore.reload()
        await configurationStore.reload()
        await routingRuleSetStore.reload()
        await mitmRuleSetStore.reload()
    }
}
