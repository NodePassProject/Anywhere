//
//  ProxyGroup.swift
//  Anywhere
//
//  Created by NodePassProject on 8/8/26.
//

import Foundation

nonisolated struct ProxyGroup: Identifiable, Codable, Hashable, SoftDeletable {
    enum Kind: String, Codable {
        case servers, chains
    }

    let id: UUID
    var name: String
    var kind: Kind
    var memberIds: [UUID]
    var collapsed: Bool
    var updatedAt: Date
    var deletedAt: Date? = nil

    init(id: UUID = UUID(), name: String, kind: Kind, memberIds: [UUID] = [], collapsed: Bool = false, updatedAt: Date = .now) {
        self.id = id
        self.name = name
        self.kind = kind
        self.memberIds = memberIds
        self.collapsed = collapsed
        self.updatedAt = updatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        kind = try container.decode(Kind.self, forKey: .kind)
        memberIds = try container.decodeIfPresent([UUID].self, forKey: .memberIds) ?? []
        collapsed = (try? container.decode(Bool.self, forKey: .collapsed)) ?? false
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? deletedAt ?? .distantPast
        deletedAt = try container.decodeIfPresent(Date.self, forKey: .deletedAt)
    }
}
