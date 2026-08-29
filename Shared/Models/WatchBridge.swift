//
//  WatchBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import Foundation

nonisolated enum WatchBridge {
    static let requestKey = "watchRequest"
    static let snapshotKey = "watchSnapshot"
    static let snapshotDateKey = "watchSnapshotDate"

    static let standaloneSectionId = UUID(uuidString: "6B9C1A34-0A61-4E7A-9A20-000000000001")!
    static let chainsSectionId = UUID(uuidString: "6B9C1A34-0A61-4E7A-9A20-000000000002")!

    // MARK: - Watch → iPhone

    enum Request: Codable {
        case state
        case toggleVPN
        case select(id: UUID)
    }

    // MARK: - iPhone → Watch

    struct Item: Codable, Hashable, Identifiable {
        let id: UUID
        let name: String
    }
    
    struct Section: Codable, Hashable, Identifiable {
        let id: UUID
        let header: String?
        let items: [Item]
    }
    
    struct Snapshot: Codable, Hashable {
        var status: VPNStatus
        var selectedId: UUID?
        var selectedName: String?
        var sections: [Section]

        var hasConfigurations: Bool {
            sections.contains { !$0.items.isEmpty }
        }
    }
}

nonisolated extension WatchBridge.Request {
    var payload: [String: Any]? {
        guard let data = try? JSONEncoder().encode(self) else { return nil }
        return [WatchBridge.requestKey: data]
    }

    init?(payload: [String: Any]) {
        guard let data = payload[WatchBridge.requestKey] as? Data,
              let request = try? JSONDecoder().decode(Self.self, from: data) else { return nil }
        self = request
    }
}

nonisolated extension WatchBridge.Snapshot {
    var payload: [String: Any]? {
        guard let data = try? JSONEncoder().encode(self) else { return nil }
        return [
            WatchBridge.snapshotKey: data,
            WatchBridge.snapshotDateKey: Date.now,
        ]
    }

    init?(payload: [String: Any]) {
        guard let data = payload[WatchBridge.snapshotKey] as? Data,
              let snapshot = try? JSONDecoder().decode(Self.self, from: data) else { return nil }
        self = snapshot
    }
}
