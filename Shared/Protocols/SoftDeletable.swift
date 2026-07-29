//
//  SoftDeletable.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation

nonisolated protocol SoftDeletable: Sendable {
    var deletedAt: Date? { get }
    var updatedAt: Date { get }
}

nonisolated extension SoftDeletable {
    var syncStamp: Date { max(updatedAt, deletedAt ?? .distantPast) }
}

nonisolated enum SyncStamp {
    static func after(_ previous: Date?) -> Date {
        max(Date.now, (previous ?? .distantPast).addingTimeInterval(0.001))
    }

    static func after<T: SoftDeletable>(_ previous: T?) -> Date {
        after(previous?.syncStamp)
    }
}

nonisolated enum Tombstone {
    static let lifetime: TimeInterval = 30 * 24 * 60 * 60
    
    static func collected<T: SoftDeletable>(_ items: [T], now: Date = .now) -> [T] {
        items.filter { item in
            guard let deletedAt = item.deletedAt else { return true }
            return now.timeIntervalSince(deletedAt) < lifetime
        }
    }
    
    static func split<T: SoftDeletable>(_ items: [T], now: Date = .now) -> (live: [T], tombstones: [T]) {
        let kept = collected(items, now: now)
        return (kept.filter { $0.deletedAt == nil }, kept.filter { $0.deletedAt != nil })
    }
}
