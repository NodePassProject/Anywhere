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
        Self.normalizedHost(host) != nil && Self.canonicalAddress(address) != nil
    }

    static func normalizedHost(_ host: String) -> String? {
        var name = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.utf8.count <= 253, !DNSName.isIPAddress(name) else { return nil }
        for label in name.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.utf8.first != UInt8(ascii: "-"), label.utf8.last != UInt8(ascii: "-"),
                  label.utf8.allSatisfy(isLabelByte)
            else { return nil }
        }
        return name
    }

    static func canonicalAddress(_ address: String) -> String? {
        let bare = DNSName.stripBrackets(address.trimmingCharacters(in: .whitespacesAndNewlines))
        return DNSUpstream.canonicalIPv4(bare) ?? DNSUpstream.canonicalIPv6(bare)
    }

    private static func isLabelByte(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || byte == UInt8(ascii: "-")
            || byte == UInt8(ascii: "_")
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
