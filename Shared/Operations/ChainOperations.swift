//
//  ChainOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct ChainOperations {
    let store: ChainStore
    let reaction: StoreMutationReaction

    func add(_ chain: ProxyChain) {
        store.add(chain)
        reaction.run()
    }

    func update(_ chain: ProxyChain) {
        store.update(chain)
        reaction.run()
    }

    func delete(_ chain: ProxyChain) {
        store.delete(chain)
        reaction.run()
    }

    func move(withIds ids: [UUID], fromOffsets source: IndexSet, toOffset destination: Int) {
        store.moveChains(withIds: ids, fromOffsets: source, toOffset: destination)
        reaction.run()
    }
}
