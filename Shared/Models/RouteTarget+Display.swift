//
//  RouteTarget+Display.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

extension RouteTarget {
    func displayName(configStore: ConfigurationStore, chainStore: ChainStore) -> String {
        switch self {
        case .direct:
            return String(localized: "DIRECT")
        case .reject:
            return String(localized: "REJECT")
        case .proxy(let id):
            if let configuration = configStore.configurations.first(where: { $0.id == id }) {
                return configuration.name
            }
            if let chain = chainStore.chains.first(where: { $0.id == id }) {
                return chain.name
            }
            return String(localized: "Proxy")
        }
    }
}
