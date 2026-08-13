//
//  AppContainer.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
final class AppContainer {
    let syncStore: SyncStore

    let tunnel: TunnelController
    let selection: ProxySelection
    let latency: LatencyCenter
    let stats: ConnectionStatsModel

    let configurationStore: ConfigurationStore
    let chainStore: ChainStore
    let groupStore: GroupStore
    let subscriptionStore: SubscriptionStore
    let routingRuleSetStore: RoutingRuleSetStore
    let mitmRuleSetStore: MITMRuleSetStore
    let certificateStore: CertificateStore

    let proxyRows: ProxyRowCoordinator
    let chainRows: ChainRowCoordinator

    let routingExporter: RoutingExporter
    let appState = AppState()
    let coordinator: StoreCoordinator
    let subscriptionRefresher: SubscriptionRefresher
    let customRuleSetRefresher: CustomRuleSetRefresher
    let mitmRuleSetRefresher: MITMRuleSetRefresher

    init(syncStore: SyncStore = .shared, tunnelProvider: TunnelProviding? = nil) {
        self.syncStore = syncStore
        
        LegacyBlobBridge.importAll(into: syncStore)

        let tunnel = TunnelController(provider: tunnelProvider ?? LiveTunnelProvider())
        let selection = ProxySelection()
        let latency = LatencyCenter(tunnel: tunnel)
        let stats = ConnectionStatsModel()

        let configurationStore = ConfigurationStore(syncStore: syncStore)
        let chainStore = ChainStore(syncStore: syncStore, configurationStore: configurationStore)
        let groupStore = GroupStore(syncStore: syncStore)
        let subscriptionStore = SubscriptionStore(syncStore: syncStore, configurationStore: configurationStore)
        let routingRuleSetStore = RoutingRuleSetStore(syncStore: syncStore)
        let mitmRuleSetStore = MITMRuleSetStore(syncStore: syncStore)
        let certificateStore = CertificateStore()

        let routingExporter = RoutingExporter(
            ruleSetStore: routingRuleSetStore,
            configurationStore: configurationStore,
            chainStore: chainStore
        )

        // MARK: Wiring

        tunnel.configurationProvider = { [weak selection] in
            selection?.selectedConfiguration
        }
        tunnel.onStatusApplied = { [weak tunnel, weak stats] status in
            guard let stats else { return }
            if status == .connected {
                guard let tunnel else { return }
                stats.startPolling { [weak tunnel] data in
                    await tunnel?.sendRaw(data)
                }
            } else {
                stats.stopPolling()
                if status == .disconnected || status == .invalid {
                    stats.reset()
                }
            }
        }
        selection.onPersistedChange = { [weak routingExporter] in
            routingExporter?.scheduleExport()
        }
        selection.onSelectionChanged = { [weak tunnel] configuration in
            if let configuration {
                tunnel?.pushConfiguration(configuration)
            }
        }
        latency.isLiveConfiguration = { [weak configurationStore] id in
            configurationStore?.configurations.contains { $0.id == id } ?? false
        }
        latency.isLiveChain = { [weak chainStore] id in
            chainStore?.chains.contains { $0.id == id } ?? false
        }
        latency.isResolvableChain = { [weak chainStore, weak configurationStore] id in
            guard let chain = chainStore?.chains.first(where: { $0.id == id }),
                  let configurations = configurationStore?.configurations else { return false }
            return chain.resolveComposite(from: configurations) != nil
        }
        routingRuleSetStore.onNeedsExport = { [weak routingExporter] in
            routingExporter?.scheduleExport()
        }

        // MARK: Assembly

        self.tunnel = tunnel
        self.selection = selection
        self.latency = latency
        self.stats = stats
        self.configurationStore = configurationStore
        self.chainStore = chainStore
        self.groupStore = groupStore
        self.subscriptionStore = subscriptionStore
        self.routingRuleSetStore = routingRuleSetStore
        self.mitmRuleSetStore = mitmRuleSetStore
        self.certificateStore = certificateStore
        self.routingExporter = routingExporter

        proxyRows = ProxyRowCoordinator(
            configurationStore: configurationStore,
            selection: selection,
            latency: latency
        )
        chainRows = ChainRowCoordinator(
            chainStore: chainStore,
            configurationStore: configurationStore,
            selection: selection,
            latency: latency
        )
        coordinator = StoreCoordinator(
            configurationStore: configurationStore,
            chainStore: chainStore,
            groupStore: groupStore,
            subscriptionStore: subscriptionStore,
            routingRuleSetStore: routingRuleSetStore,
            mitmRuleSetStore: mitmRuleSetStore,
            selection: selection,
            latency: latency,
            routingExporter: routingExporter,
            appState: appState
        )
        subscriptionRefresher = SubscriptionRefresher(
            subscriptionStore: subscriptionStore,
            configurationStore: configurationStore
        )
        customRuleSetRefresher = CustomRuleSetRefresher(ruleSetStore: routingRuleSetStore)
        mitmRuleSetRefresher = MITMRuleSetRefresher(ruleSetStore: mitmRuleSetStore)

        // MARK: Startup

        coordinator.activate()
        routingExporter.scheduleExport()
        tunnel.start()
    }
}
