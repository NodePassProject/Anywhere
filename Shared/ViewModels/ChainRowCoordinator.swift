//
//  ChainRowCoordinator.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class ChainRowCoordinator {
    private(set) var models: [ChainListItem] = []
    @ObservationIgnored private var byID: [UUID: ChainListItem] = [:]

    @ObservationIgnored private let chainStore: ChainStore
    @ObservationIgnored private let configurationStore: ConfigurationStore
    @ObservationIgnored private let selection: ProxySelection
    @ObservationIgnored private let latency: LatencyCenter

    init(chainStore: ChainStore, configurationStore: ConfigurationStore, selection: ProxySelection, latency: LatencyCenter) {
        self.chainStore = chainStore
        self.configurationStore = configurationStore
        self.selection = selection
        self.latency = latency
        reconcile()
        observe()
    }

    func model(for id: UUID) -> ChainListItem? { byID[id] }

    private func observe() {
        withObservationTracking {
            _ = chainStore.chains
            _ = configurationStore.configurations
            _ = selection.selectedChainId
            _ = latency.chainLatencyResults
        } onChange: { [weak self] in
            guard let self else { return }
            Task { @MainActor in
                self.reconcile()
                self.observe()
            }
        }
    }

    private func reconcile() {
        let chains = chainStore.chains
        let configurations = configurationStore.configurations
        let selectedId = selection.selectedChainId
        let latency = latency.chainLatencyResults

        var ordered: [ChainListItem] = []
        var updated: [UUID: ChainListItem] = [:]
        for chain in chains {
            let isSelected = chain.id == selectedId
            let result = latency[chain.id]
            let model = byID[chain.id]
            if let model {
                model.update(chain, configurations: configurations, isSelected: isSelected, latency: result)
            }
            let resolved = model ?? ChainListItem(chain, configurations: configurations, isSelected: isSelected, latency: result)
            ordered.append(resolved)
            updated[chain.id] = resolved
        }
        byID = updated
        // Publish a new array only on structural change; content updates flow through each model's own observation.
        if models.map(\.id) != ordered.map(\.id) {
            models = ordered
        }
    }
}
