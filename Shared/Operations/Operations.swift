//
//  Operations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class Operations {
    @ObservationIgnored private let container: AppContainer

    init(container: AppContainer) {
        self.container = container
    }

    var configurations: ConfigurationOperations {
        ConfigurationOperations(store: container.configurationStore, reaction: container.mutationReaction)
    }

    var chains: ChainOperations {
        ChainOperations(store: container.chainStore, reaction: container.mutationReaction)
    }

    var subscriptions: SubscriptionOperations {
        SubscriptionOperations(
            store: container.subscriptionStore,
            configurationStore: container.configurationStore,
            reaction: container.mutationReaction
        )
    }

    var groups: GroupOperations {
        GroupOperations(store: container.groupStore)
    }

    var certificates: CertificateOperations {
        CertificateOperations(store: container.certificateStore)
    }

    var routingRuleSets: RoutingRuleSetOperations {
        RoutingRuleSetOperations(store: container.routingRuleSetStore, exporter: container.exportScheduler)
    }

    var mitmRuleSets: MITMRuleSetOperations {
        MITMRuleSetOperations(store: container.mitmRuleSetStore)
    }

    var selection: SelectionOperations {
        SelectionOperations(
            selection: container.selection,
            tunnel: container.tunnel,
            exporter: container.exportScheduler
        )
    }

    var tunnel: TunnelOperations {
        TunnelOperations(tunnel: container.tunnel, selection: container.selection)
    }

    var latency: LatencyRunner {
        LatencyRunner(
            latency: container.latency,
            tunnel: container.tunnel,
            configurationStore: container.configurationStore,
            chainStore: container.chainStore
        )
    }
    
    func reload(_ keys: Set<SyncStore.Key>) async {
        let stores: [(SyncStore.Key, any Reloadable)] = [
            (.groups, container.groupStore),
            (.subscriptions, container.subscriptionStore),
            (.chains, container.chainStore),
            (.configurations, container.configurationStore),
            (.customRuleSets, container.routingRuleSetStore),
            (.mitm, container.mitmRuleSetStore),
        ]
        let affected = stores.filter { keys.contains($0.0) }.map(\.1)
        guard !affected.isEmpty else { return }
        await ReloadOperation(stores: affected, reaction: container.mutationReaction).run()
    }
}
