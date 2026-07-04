//
//  WatchBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import Foundation

/// Wire types for the iPhone ⇄ Apple Watch WatchConnectivity bridge.
/// Payloads travel JSON-encoded under a single dictionary key so both sides
/// share one typed envelope instead of loose dictionary fields.
nonisolated enum WatchBridge {
    /// Key holding a JSON-encoded ``Request`` in a watch → iPhone message.
    static let requestKey = "watchRequest"
    /// Key holding a JSON-encoded ``Snapshot`` in replies and application context.
    static let snapshotKey = "watchSnapshot"
    /// Key holding the `Date` the iPhone took the accompanying snapshot, so
    /// the watch can show how stale its data is. Lives beside the snapshot
    /// rather than inside it to keep identical snapshots byte-identical.
    static let snapshotDateKey = "watchSnapshotDate"

    /// Stable ids for the two synthesized picker sections; subscription
    /// sections use the subscription's own id.
    static let standaloneSectionId = UUID(uuidString: "6B9C1A34-0A61-4E7A-9A20-000000000001")!
    static let chainsSectionId = UUID(uuidString: "6B9C1A34-0A61-4E7A-9A20-000000000002")!

    // MARK: - Watch → iPhone

    enum Request: Codable {
        /// Ask for a fresh ``Snapshot`` without changing anything.
        case state
        /// Connect when disconnected, disconnect when connected.
        case toggleVPN
        /// Make the configuration or chain with this id the active selection.
        case select(id: UUID)
    }

    // MARK: - iPhone → Watch

    struct Item: Codable, Hashable, Identifiable {
        let id: UUID
        let name: String
    }

    /// Same shape as `PickerSection`; `header` is nil for the standalone group.
    struct Section: Codable, Hashable, Identifiable {
        let id: UUID
        let header: String?
        let items: [Item]
    }

    /// Everything the watch UI renders.
    struct Snapshot: Codable, Hashable {
        var status: VPNStatus
        /// Selected chain id when a chain is active, otherwise the selected
        /// configuration id — matching the picker items' ids.
        var selectedId: UUID?
        var selectedName: String?
        var sections: [Section]

        var hasConfigurations: Bool {
            sections.contains { !$0.items.isEmpty }
        }
    }
}

nonisolated extension WatchBridge.Request {
    /// Dictionary payload for `sendMessage`.
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
    /// Dictionary payload for `updateApplicationContext` and message replies,
    /// stamped with the moment the snapshot was taken.
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
