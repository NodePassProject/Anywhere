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
    static let shared = ProxyRowCoordinator()

    private(set) var models: [ProxyListItem] = []
    @ObservationIgnored private var byID: [UUID: ProxyListItem] = [:]

    private init() {
        reconcile()
        observe()
    }

    func model(for id: UUID) -> ProxyListItem? { byID[id] }

    private func observe() {
        withObservationTracking {
            _ = ConfigurationStore.shared.configurations
            _ = VPNViewModel.shared.selectedConfiguration
            _ = VPNViewModel.shared.selectedChainId
            _ = VPNViewModel.shared.latencyResults
        } onChange: { [weak self] in
            guard let self else { return }
            Task { @MainActor in
                self.reconcile()
                self.observe()
            }
        }
    }

    private func reconcile() {
        let configurations = ConfigurationStore.shared.configurations
        let selectedId = VPNViewModel.shared.selectedConfiguration?.id
        let selectedChainId = VPNViewModel.shared.selectedChainId
        let latency = VPNViewModel.shared.latencyResults

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
