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
    
    func reloadAll() async {
        await ReloadOperation(
            stores: [
                container.groupStore,
                container.subscriptionStore,
                container.chainStore,
                container.configurationStore,
                container.routingRuleSetStore,
                container.mitmRuleSetStore,
            ],
            reaction: container.mutationReaction
        ).run()
    }
}
