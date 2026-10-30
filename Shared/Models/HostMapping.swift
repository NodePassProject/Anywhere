//
//  HostMapping.swift
//  Anywhere
//
//  Created by NodePassProject on 10/10/26.
//

import Foundation

nonisolated struct HostMapping: Codable, Hashable, Sendable {
    var host: String
    var address: String

    var isValid: Bool {
        DNSName.normalizedHost(host) != nil && Self.canonicalAddress(address) != nil
    }

    static func canonicalAddress(_ address: String) -> String? {
        let bare = DNSName.stripBrackets(address.trimmingCharacters(in: .whitespacesAndNewlines))
        return DNSUpstream.canonicalIPv4(bare) ?? DNSUpstream.canonicalIPv6(bare)
    }

    static func load() -> [HostMapping] {
        guard let data = AWCore.getHostMappingsData() else { return [] }
        return (try? JSONDecoder().decode([HostMapping].self, from: data)) ?? []
    }

    static func store(_ mappings: [HostMapping]) {
        guard !mappings.isEmpty else { return AWCore.setHostMappingsData(nil) }
        AWCore.setHostMappingsData(try? JSONEncoder().encode(mappings))
    }
}
