//
//  WatchSnapshotBuilder.swift
//  Anywhere
//
//  Created by NodePassProject on 8/29/26.
//

import Foundation

nonisolated struct WatchSnapshotBuilder {
    let status: VPNStatus
    let selectedId: UUID?
    let selectedName: String?
    let configurations: [ProxyConfiguration]
    let chains: [ProxyChain]
    let groups: [ProxyGroup]
    let subscriptions: [Subscription]

    var snapshot: WatchBridge.Snapshot {
        WatchBridge.Snapshot(
            status: status,
            selectedId: selectedId,
            selectedName: selectedName,
            sections: sections
        )
    }
    
    private var sections: [WatchBridge.Section] {
        var sections: [WatchBridge.Section] = []
        
        let serverGroups = groups.filter { $0.kind == .servers }
        let groupedConfigurationIds = Set(serverGroups.flatMap(\.memberIds))
        var configurationItems: [UUID: WatchBridge.Item] = [:]
        var bySubscription: [UUID: [WatchBridge.Item]] = [:]
        var looseConfigurations: [WatchBridge.Item] = []
        for configuration in configurations {
            let item = WatchBridge.Item(id: configuration.id, name: configuration.name)
            configurationItems[configuration.id] = item
            if let subscriptionId = configuration.subscriptionId {
                bySubscription[subscriptionId, default: []].append(item)
            } else if !groupedConfigurationIds.contains(configuration.id) {
                looseConfigurations.append(item)
            }
        }
        if !looseConfigurations.isEmpty {
            sections.append(WatchBridge.Section(
                id: WatchBridge.standaloneSectionId,
                header: nil,
                items: looseConfigurations
            ))
        }
        sections.append(contentsOf: groupSections(for: serverGroups, members: configurationItems))
        
        let chainGroups = groups.filter { $0.kind == .chains }
        let groupedChainIds = Set(chainGroups.flatMap(\.memberIds))
        var chainItems: [UUID: WatchBridge.Item] = [:]
        var looseChains: [WatchBridge.Item] = []
        for chain in usableChains {
            let item = WatchBridge.Item(id: chain.id, name: chain.name)
            chainItems[chain.id] = item
            if !groupedChainIds.contains(chain.id) {
                looseChains.append(item)
            }
        }
        if !looseChains.isEmpty {
            sections.append(WatchBridge.Section(
                id: WatchBridge.chainsSectionId,
                header: String(localized: "Chains"),
                items: looseChains
            ))
        }
        sections.append(contentsOf: groupSections(for: chainGroups, members: chainItems))
        
        for subscription in subscriptions {
            guard let items = bySubscription[subscription.id], !items.isEmpty else { continue }
            sections.append(WatchBridge.Section(
                id: subscription.id,
                header: subscription.name,
                items: items
            ))
        }

        return sections
    }
    
    private func groupSections(
        for groups: [ProxyGroup],
        members: [UUID: WatchBridge.Item]
    ) -> [WatchBridge.Section] {
        groups.compactMap { group in
            let items = group.memberIds.compactMap { members[$0] }
            guard !items.isEmpty else { return nil }
            return WatchBridge.Section(id: group.id, header: group.name, items: items)
        }
    }
    
    private var usableChains: [ProxyChain] {
        let known = Set(configurations.map(\.id))
        return chains.filter { $0.proxyIds.count >= 2 && $0.proxyIds.allSatisfy(known.contains) }
    }
}
