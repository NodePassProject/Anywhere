//
//  ProxyRowCoordinator.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class ProxyRowCoordinator {
    private(set) var models: [ProxyListItem] = []
    @ObservationIgnored private var byID: [UUID: ProxyListItem] = [:]

    @ObservationIgnored private let configurationStore: ConfigurationStore
    @ObservationIgnored private let selection: ProxySelection
    @ObservationIgnored private let latency: LatencyCenter

    init(configurationStore: ConfigurationStore, selection: ProxySelection, latency: LatencyCenter) {
        self.configurationStore = configurationStore
        self.selection = selection
        self.latency = latency
        reconcile()
        observe()
    }

    func model(for id: UUID) -> ProxyListItem? { byID[id] }

    private func observe() {
        withObservationTracking {
            _ = configurationStore.configurations
            _ = selection.selectedConfiguration
            _ = selection.selectedChainId
            _ = latency.latencyResults
        } onChange: { [weak self] in
            guard let self else { return }
            Task { @MainActor in
                self.reconcile()
                self.observe()
            }
        }
    }

    private func reconcile() {
        let configurations = configurationStore.configurations
        let selectedId = selection.selectedConfiguration?.id
        let selectedChainId = selection.selectedChainId
        let latency = latency.latencyResults

        var ordered: [ProxyListItem] = []
        var updated: [UUID: ProxyListItem] = [:]
        for configuration in configurations {
            let isSelected = configuration.id == selectedId && selectedChainId == nil
            let result = latency[configuration.id]
            let model = byID[configuration.id]
            if let model {
                model.update(configuration, isSelected: isSelected, latency: result)
            }
            let resolved = model ?? ProxyListItem(configuration, isSelected: isSelected, latency: result)
            ordered.append(resolved)
            updated[configuration.id] = resolved
        }
        byID = updated
        if models.map(\.id) != ordered.map(\.id) {
            models = ordered
        }
    }
}
