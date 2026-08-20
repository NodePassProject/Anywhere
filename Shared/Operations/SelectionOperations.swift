//
//  SelectionOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct SelectionOperations {
    let selection: ProxySelection
    let tunnel: TunnelController
    let exporter: RoutingExportScheduler

    func select(_ configuration: ProxyConfiguration) {
        selection.select(configuration)
        tunnel.pushConfiguration(configuration)
        exporter.schedule()
    }

    func selectChain(_ chain: ProxyChain, configurations: [ProxyConfiguration]) {
        guard selection.selectChain(chain, configurations: configurations) else { return }
        if let resolved = selection.selectedConfiguration {
            tunnel.pushConfiguration(resolved)
        }
        exporter.schedule()
    }

    func selectIfNone(_ configuration: ProxyConfiguration) {
        guard selection.selectIfNone(configuration) else { return }
        tunnel.pushConfiguration(configuration)
        exporter.schedule()
    }
}
