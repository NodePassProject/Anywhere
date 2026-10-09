//
//  SelectionOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct SelectionOperations {
    let proxySelection: ProxySelection
    let tunnelController: TunnelController
    let routingExportScheduler: RoutingExportScheduler

    func select(_ configuration: ProxyConfiguration) {
        proxySelection.select(configuration)
        tunnelController.pushConfiguration(configuration)
        routingExportScheduler.schedule()
    }

    func selectChain(_ chain: ProxyChain, configurations: [ProxyConfiguration]) {
        guard proxySelection.selectChain(chain, configurations: configurations) else { return }
        if let resolved = proxySelection.selectedConfiguration {
            tunnelController.pushConfiguration(resolved)
        }
        routingExportScheduler.schedule()
    }

    func selectIfNone(_ configuration: ProxyConfiguration) {
        guard proxySelection.selectIfNone(configuration) else { return }
        tunnelController.pushConfiguration(configuration)
        routingExportScheduler.schedule()
    }
}
