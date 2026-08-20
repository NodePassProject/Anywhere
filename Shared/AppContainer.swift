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
final class AppContainer {
    let syncStore: SyncStore

    // MARK: - Residents

    let tunnel: TunnelController
    let selection = ProxySelection()
    let latency = LatencyCenter()
    let stats = ConnectionStatsModel()
    let appState = AppState()

    let configurationStore: ConfigurationStore
    let chainStore: ChainStore
    let groupStore: GroupStore
    let subscriptionStore: SubscriptionStore
    let routingRuleSetStore: RoutingRuleSetStore
    let mitmRuleSetStore: MITMRuleSetStore
    let certificateStore: CertificateStore

    private let routingExportDebouncer = Debouncer(interval: .seconds(2))
    private var started = false

    init(syncStore: SyncStore = .shared, tunnelProvider: TunnelProviding? = nil) {
        self.syncStore = syncStore
        
        LegacyBlobBridge.importAll(into: syncStore)

        tunnel = TunnelController(provider: tunnelProvider ?? LiveTunnelProvider())
        configurationStore = ConfigurationStore(syncStore: syncStore)
        chainStore = ChainStore(syncStore: syncStore)
        groupStore = GroupStore(syncStore: syncStore)
        subscriptionStore = SubscriptionStore(syncStore: syncStore)
        routingRuleSetStore = RoutingRuleSetStore(syncStore: syncStore)
        mitmRuleSetStore = MITMRuleSetStore(syncStore: syncStore)
        certificateStore = CertificateStore()
    }

    // MARK: - Operation Factories

    var exportScheduler: RoutingExportScheduler {
        RoutingExportScheduler(
            debouncer: routingExportDebouncer,
            ruleSetStore: routingRuleSetStore,
            configurationStore: configurationStore,
            chainStore: chainStore
        )
    }

    var mutationReaction: StoreMutationReaction {
        StoreMutationReaction(
            configurationStore: configurationStore,
            chainStore: chainStore,
            routingRuleSetStore: routingRuleSetStore,
            selection: selection,
            latency: latency,
            tunnel: tunnel,
            appState: appState,
            exporter: exportScheduler
        )
    }

    // MARK: - Startup

    func start() {
        guard !started else { return }
        started = true

        Task { await LoadOperation(configurationStore: configurationStore, reaction: mutationReaction).run() }
        observeTunnelStatus()
        exportScheduler.schedule()
        tunnel.start()
    }
    
    private func observeTunnelStatus() {
        withObservationTracking {
            _ = tunnel.rawStatus
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                TunnelSessionReaction(tunnel: self.tunnel, stats: self.stats, selection: self.selection).run()
                self.observeTunnelStatus()
            }
        }
    }
}
