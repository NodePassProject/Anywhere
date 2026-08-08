//
//  GroupStore.swift
//  Anywhere
//
//  Created by NodePassProject on 8/8/26.
//

import Foundation
import Observation
import SwiftUI

nonisolated private let logger = AnywhereLogger(category: "GroupStore")

@MainActor
@Observable
class GroupStore {
    private(set) var groups: [ProxyGroup] = []
    private var tombstones: [ProxyGroup] = []

    @ObservationIgnored private let blobStore: JSONBlobStore
    @ObservationIgnored private var loadedBlob: Data?
    @ObservationIgnored private var mutationEpoch = 0

    @ObservationIgnored private var saveTask: Task<Void, Never>?

    init(blobStore: JSONBlobStore) {
        self.blobStore = blobStore
        let data = blobStore.load(.groups)
        loadedBlob = data
        let split = Self.decodeSplit(from: data)
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
            let previous = loadedBlob
            let epoch = mutationEpoch
            await saveTask?.value
            guard epoch == mutationEpoch else { continue }
            let outcome = await Task.detached(priority: .utility) {
                [blobStore] () -> (data: Data?, live: [ProxyGroup], tombstones: [ProxyGroup])? in
                let data = blobStore.load(.groups)
                guard data != previous else { return nil }
                let split = Self.decodeSplit(from: data)
                return (data, split.live, split.tombstones)
            }.value
            guard let outcome else { return }
            guard epoch == mutationEpoch else { continue }
            loadedBlob = outcome.data
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

    func toggleCollapsed(_ group: ProxyGroup) {
        guard var current = groups.first(where: { $0.id == group.id }) else { return }
        current.collapsed.toggle()
        update(current)
    }

    // MARK: - Persistence

    nonisolated private static func decodeSplit(from data: Data?) -> (live: [ProxyGroup], tombstones: [ProxyGroup]) {
        guard let data else { return ([], []) }
        guard let all = JSONDecoder().decodeSkippingInvalid([ProxyGroup].self, from: data) else {
            JSONBlobStore.quarantine(.groups, data)
            return ([], [])
        }
        return Tombstone.split(all)
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
        let snapshot = groups + tombstones
        let previous = saveTask
        saveTask = Task.detached { [blobStore] in
            await previous?.value
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(snapshot)
                blobStore.save(.groups, data: data)
            } catch {
                logger.report(AnywhereError.store(.saveFailed(.groups, underlying: error)))
            }
        }
    }
}
