//
//  VPNViewModel+PickerItems.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import Foundation

extension VPNViewModel {
    /// Valid chains (those that resolve to ≥2 proxies) as picker items.
    var chainPickerItems: [PickerItem] {
        chains.compactMap { chain in
            let proxies = chain.resolveProxies(from: configurations)
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { return nil }
            return PickerItem(id: chain.id, name: chain.name)
        }
    }

    /// Configurations that don't belong to any subscription.
    var standalonePickerItems: [PickerItem] {
        configurations
            .filter { $0.subscriptionId == nil }
            .map { PickerItem(id: $0.id, name: $0.name) }
    }

    /// One section per non-empty subscription, headed by the subscription's name.
    var subscriptionPickerSections: [PickerSection] {
        subscriptions.compactMap { subscription in
            let configs = configurations(for: subscription)
            guard !configs.isEmpty else { return nil }
            return PickerSection(
                id: subscription.id,
                header: subscription.name,
                items: configs.map { PickerItem(id: $0.id, name: $0.name) }
            )
        }
    }
}
