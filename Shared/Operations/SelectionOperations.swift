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

    func select(_ configuration: ProxyConfiguration) {
        proxySelection.select(configuration)
    }

    func selectChain(_ chain: ProxyChain, configurations: [ProxyConfiguration]) {
        proxySelection.selectChain(chain, configurations: configurations)
    }

    func selectIfNone(_ configuration: ProxyConfiguration) {
        proxySelection.selectIfNone(configuration)
    }
}
