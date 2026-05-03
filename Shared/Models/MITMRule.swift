//
//  MITMRule.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

struct MITMRule: Codable, Equatable, Identifiable {
    var id = UUID()
    var type: DomainRuleType
    var value: String

    init(id: UUID = UUID(), type: DomainRuleType, value: String) {
        self.id = id
        self.type = type
        self.value = value
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(DomainRuleType.self, forKey: .type)
        self.value = try container.decode(String.self, forKey: .value)
        self.id = UUID()
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(value, forKey: .value)
    }
}

/// Persisted shape for the MITM feature: master toggle plus the user's
/// match rules. Owned by the app side via ``MITMStore`` and read by the
/// network extension via ``LWIPStack/loadMITMSetting``. Keeping the
/// schema in one Codable type means new fields show up at compile time
/// on both sides instead of silently disappearing through a
/// hand-rolled JSON parser.
struct MITMSnapshot: Codable, Equatable {
    var enabled: Bool
    var rules: [MITMRule]

    static let empty = MITMSnapshot(enabled: false, rules: [])

    /// Best-effort decode of the persisted blob. Returns ``empty`` when
    /// no snapshot has been written yet or the blob fails to decode
    /// (older schema, corruption, etc.) — both sides treat that as
    /// "MITM disabled" rather than crashing.
    static func load() -> MITMSnapshot {
        guard let data = AWCore.getMITMData() else { return .empty }
        return (try? JSONDecoder().decode(MITMSnapshot.self, from: data)) ?? .empty
    }

    /// Encodes and persists the snapshot, then fires the Darwin
    /// notification the extension observes to trigger a reload.
    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        AWCore.setMITMData(data)
        AWCore.notifyMITMChanged()
    }
}
