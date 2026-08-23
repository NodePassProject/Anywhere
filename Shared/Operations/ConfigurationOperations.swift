//
//  ConfigurationOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct ConfigurationOperations {
    let store: ConfigurationStore
    let reaction: StoreMutationReaction

    func add(_ configuration: ProxyConfiguration) {
        store.add(configuration)
        reaction.run()
    }

    func update(_ configuration: ProxyConfiguration) {
        store.update(configuration)
        reaction.run()
    }

    func delete(_ configuration: ProxyConfiguration) {
        store.delete(configuration)
        reaction.run()
    }

    func move(withIds ids: [UUID], fromOffsets source: IndexSet, toOffset destination: Int) {
        store.moveConfigurations(withIds: ids, fromOffsets: source, toOffset: destination)
        reaction.run()
    }

    func reorder(for subscriptionId: UUID, to orderedIds: [UUID]) {
        store.reorderConfigurations(for: subscriptionId, to: orderedIds)
        reaction.run()
    }
}
