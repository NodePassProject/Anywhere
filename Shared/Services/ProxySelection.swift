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
    private(set) var selectedConfiguration: ProxyConfiguration?
    private(set) var selectedChainId: UUID?

    // MARK: - Mutations

    func select(_ configuration: ProxyConfiguration) {
        selectedChainId = nil
        AWCore.setSelectedChainId(nil)
        AWCore.setSelectedConfigurationId(configuration.id)
        selectedConfiguration = configuration
    }

    @discardableResult
    func selectChain(_ chain: ProxyChain, configurations: [ProxyConfiguration]) -> Bool {
        guard let resolved = chain.resolveComposite(from: configurations) else { return false }
        selectedChainId = chain.id
        AWCore.setSelectedChainId(chain.id)
        AWCore.setSelectedConfigurationId(nil)
        selectedConfiguration = resolved
        return true
    }

    @discardableResult
    func selectIfNone(_ configuration: ProxyConfiguration) -> Bool {
        guard selectedConfiguration == nil else { return false }
        select(configuration)
        return true
    }

    // MARK: - Revalidation
    
    func revalidate(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        if selectedConfiguration == nil, selectedChainId == nil {
            restoreSelection(configurations: configurations, chains: chains)
            return
        }
        if let chainId = selectedChainId {
            if let chain = chains.first(where: { $0.id == chainId }),
               let resolved = chain.resolveComposite(from: configurations) {
                if resolved != selectedConfiguration {
                    selectedConfiguration = resolved
                }
            } else {
                selectedChainId = nil
                AWCore.setSelectedChainId(nil)
                fallBack(to: configurations.first)
            }
        } else if let selected = selectedConfiguration {
            if let refreshed = configurations.first(where: { $0.id == selected.id }) {
                if refreshed != selected {
                    selectedConfiguration = refreshed
                }
            } else {
                fallBack(to: configurations.first)
            }
        }
    }

    private func restoreSelection(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        if let savedChainId = AWCore.getSelectedChainId(),
           let chain = chains.first(where: { $0.id == savedChainId }),
           let resolved = chain.resolveComposite(from: configurations) {
            selectedChainId = savedChainId
            selectedConfiguration = resolved
        } else if let savedConfigurationId = AWCore.getSelectedConfigurationId(),
                  let configuration = configurations.first(where: { $0.id == savedConfigurationId }) {
            selectedConfiguration = configuration
        } else {
            fallBack(to: configurations.first)
        }
    }

    private func fallBack(to configuration: ProxyConfiguration?) {
        AWCore.setSelectedChainId(nil)
        AWCore.setSelectedConfigurationId(configuration?.id)
        selectedConfiguration = configuration
    }
}
