//
//  GroupStore.swift
//  Anywhere
//
//  Created by NodePassProject on 8/8/26.
//

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
class GroupStore {
    private(set) var groups: [ProxyGroup] = []
    private var tombstones: [ProxyGroup] = []

    @ObservationIgnored private let syncStore: SyncStore
    @ObservationIgnored private var loadedItems: [Data]?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?

    init(syncStore: SyncStore) {
        self.syncStore = syncStore
        let items = syncStore.loadItems(.groups)
        loadedItems = items
        let split = Self.decodeSplit(from: items)
        groups = split.live
        tombstones = split.tombstones
    }

    // MARK: - CRUD

    func add(_ group: ProxyGroup) {
        let tombstone = tombstones.first { $0.id == group.id }
        tombstones.removeAll { $0.id == group.id }
        var stamped = group
        stamped.updatedAt = SyncStamp.after(tombstone)
        groups.append(stamped)
        save()
    }

    func update(_ group: ProxyGroup) {
        if let index = groups.firstIndex(where: { $0.id == group.id }) {
            var stamped = group
            stamped.updatedAt = SyncStamp.after(groups[index])
            groups[index] = stamped
            save()
        }
    }

    func delete(_ group: ProxyGroup) {
        groups.removeAll { $0.id == group.id }
        recordTombstone(group)
        save()
    }

    func move(_ kind: ProxyGroup.Kind, fromOffsets source: IndexSet, toOffset destination: Int) {
        groups.moveSubsequence(where: { $0.kind == kind }, fromOffsets: source, toOffset: destination)
        save()
    }

    func reload() async {
        while true {
            let previous = loadedItems
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [syncStore] () -> (items: [Data], live: [ProxyGroup], tombstones: [ProxyGroup])? in
                let items = syncStore.loadItems(.groups)
                guard items != previous else { return nil }
                let split = Self.decodeSplit(from: items)
                return (items, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedItems = outcome.items
            groups = outcome.live
            tombstones = outcome.tombstones
            return
        }
    }

    // MARK: - Membership

    func groups(of kind: ProxyGroup.Kind) -> [ProxyGroup] {
        groups.filter { $0.kind == kind }
    }

    func group(containing memberId: UUID, kind: ProxyGroup.Kind) -> ProxyGroup? {
        groups.first { $0.kind == kind && $0.memberIds.contains(memberId) }
    }

    func addMember(_ memberId: UUID, to groupId: UUID) {
        guard var group = groups.first(where: { $0.id == groupId }),
              !group.memberIds.contains(memberId) else { return }
        group.memberIds.append(memberId)
        update(group)
    }

    func removeMember(_ memberId: UUID, from groupId: UUID) {
        guard var group = groups.first(where: { $0.id == groupId }),
              group.memberIds.contains(memberId) else { return }
        group.memberIds.removeAll { $0 == memberId }
        update(group)
    }
    
    func moveMembers(of groupId: UUID, withIds ids: [UUID], fromOffsets source: IndexSet, toOffset destination: Int) {
        guard var group = groups.first(where: { $0.id == groupId }) else { return }
        let idSet = Set(ids)
        group.memberIds.moveSubsequence(where: { idSet.contains($0) }, fromOffsets: source, toOffset: destination)
        update(group)
    }

    // MARK: - Persistence

    nonisolated private static func decodeSplit(from items: [Data]) -> (live: [ProxyGroup], tombstones: [ProxyGroup]) {
        Tombstone.split(SyncCodec.decodeItems(ProxyGroup.self, key: .groups, payloads: items))
    }

    private func recordTombstone(_ group: ProxyGroup) {
        var tomb = group
        tomb.deletedAt = .now
        tomb.memberIds = []
        tombstones.removeAll { $0.id == group.id }
        tombstones.append(tomb)
    }

    private func save() {
        mutationEpoch += 1
        let live = groups
        let snapshot = live + tombstones
        let previous = saveTask
        saveTask = Task.detached { [syncStore] in
            await previous?.value
            syncStore.save(.groups, items: SyncCodec.encodeItems(snapshot), order: SyncCodec.order(of: live))
        }
    }
}
