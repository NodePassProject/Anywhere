//
//  GroupOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct GroupOperations {
    let store: GroupStore

    func add(_ group: ProxyGroup) { store.add(group) }
    func update(_ group: ProxyGroup) { store.update(group) }
    func delete(_ group: ProxyGroup) { store.delete(group) }

    func move(_ kind: ProxyGroup.Kind, fromOffsets source: IndexSet, toOffset destination: Int) {
        store.move(kind, fromOffsets: source, toOffset: destination)
    }

    func addMember(_ memberId: UUID, to groupId: UUID) {
        store.addMember(memberId, to: groupId)
    }

    func removeMember(_ memberId: UUID, from groupId: UUID) {
        store.removeMember(memberId, from: groupId)
    }

    func moveMembers(of groupId: UUID, withIds ids: [UUID], fromOffsets source: IndexSet, toOffset destination: Int) {
        store.moveMembers(of: groupId, withIds: ids, fromOffsets: source, toOffset: destination)
    }
}
