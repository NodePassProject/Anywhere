//
//  PickerQuery.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

nonisolated struct PickerQuery {
    let configurations: [ProxyConfiguration]
    let chains: [ProxyChain]
    let subscriptions: [Subscription]
    
    var standaloneItems: [PickerItem] {
        configurations
            .filter { $0.subscriptionId == nil }
            .map { PickerItem(id: $0.id, name: $0.name) }
    }
    
    var chainItems: [PickerItem] {
        chains.compactMap { chain in
            let proxies = chain.resolveProxies(from: configurations)
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { return nil }
            return PickerItem(id: chain.id, name: chain.name)
        }
    }
    
    var subscriptionSections: [PickerSection] {
        subscriptions.compactMap { subscription in
            let items = configurations.filter { $0.subscriptionId == subscription.id }
            guard !items.isEmpty else { return nil }
            return PickerSection(
                id: subscription.id,
                header: subscription.name,
                items: items.map { PickerItem(id: $0.id, name: $0.name) }
            )
        }
    }
}
