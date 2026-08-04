//
//  ProxySelection.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class ProxySelection {
    var selectedConfiguration: ProxyConfiguration? {
        didSet {
            if !_suppressPersistence {
                selectedChainId = nil
                AWCore.setSelectedChainId(nil)
                AWCore.setSelectedConfigurationId(selectedConfiguration?.id)
                onPersistedChange?()
            }
            onSelectionChanged?(selectedConfiguration)
        }
    }
    private(set) var selectedChainId: UUID?

    @ObservationIgnored private var _suppressPersistence = false
    
    @ObservationIgnored var onPersistedChange: (() -> Void)?
    @ObservationIgnored var onSelectionChanged: ((ProxyConfiguration?) -> Void)?

    private func withoutPersistence(_ block: () -> Void) {
        _suppressPersistence = true
        defer { _suppressPersistence = false }
        block()
    }

    private func restoreSelection(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        guard selectedConfiguration == nil, selectedChainId == nil else { return }
        if let savedChainId = AWCore.getSelectedChainId(),
           let chain = chains.first(where: { $0.id == savedChainId }),
           let resolved = chain.resolveComposite(from: configurations) {
            selectedChainId = savedChainId
            withoutPersistence { selectedConfiguration = resolved }
        } else if let savedConfigurationId = AWCore.getSelectedConfigurationId(),
                  let configuration = configurations.first(where: { $0.id == savedConfigurationId }) {
            withoutPersistence { selectedConfiguration = configuration }
        } else {
            selectedConfiguration = configurations.first
        }
    }

    func revalidateSelection(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        if selectedConfiguration == nil, selectedChainId == nil {
            restoreSelection(configurations: configurations, chains: chains)
            return
        }
        if let chainId = selectedChainId {
            if let chain = chains.first(where: { $0.id == chainId }),
               let resolved = chain.resolveComposite(from: configurations) {
                withoutPersistence { selectedConfiguration = resolved }
            } else {
                selectedChainId = nil
                AWCore.setSelectedChainId(nil)
                selectedConfiguration = configurations.first
            }
        } else {
            if let selected = selectedConfiguration {
                if let refreshed = configurations.first(where: { $0.id == selected.id }) {
                    if refreshed != selected { selectedConfiguration = refreshed }
                } else {
                    selectedConfiguration = configurations.first
                }
            }
            if selectedConfiguration == nil {
                selectedConfiguration = configurations.first
            }
        }
    }

    func selectChain(_ chain: ProxyChain, configurations: [ProxyConfiguration]) {
        guard let resolved = chain.resolveComposite(from: configurations) else { return }
        selectedChainId = chain.id
        AWCore.setSelectedChainId(chain.id)
        AWCore.setSelectedConfigurationId(nil)
        onPersistedChange?()
        withoutPersistence { selectedConfiguration = resolved }
    }

    func selectIfNone(_ configuration: ProxyConfiguration) {
        if selectedConfiguration == nil { selectedConfiguration = configuration }
    }
}
