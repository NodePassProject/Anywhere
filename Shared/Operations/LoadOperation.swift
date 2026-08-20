//
//  LoadOperation.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct LoadOperation {
    let configurationStore: ConfigurationStore
    let reaction: StoreMutationReaction

    func run() async {
        await configurationStore.loadInitial()
        reaction.run()
    }
}
