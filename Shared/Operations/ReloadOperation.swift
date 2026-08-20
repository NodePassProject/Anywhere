//
//  ReloadOperation.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
protocol Reloadable {
    func reload() async
}

extension ConfigurationStore: Reloadable {}
extension ChainStore: Reloadable {}
extension GroupStore: Reloadable {}
extension SubscriptionStore: Reloadable {}
extension RoutingRuleSetStore: Reloadable {}
extension MITMRuleSetStore: Reloadable {}

@MainActor
struct ReloadOperation {
    let stores: [any Reloadable]
    let reaction: StoreMutationReaction

    func run() async {
        for store in stores {
            await store.reload()
        }
        reaction.run()
    }
}
