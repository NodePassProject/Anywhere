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
