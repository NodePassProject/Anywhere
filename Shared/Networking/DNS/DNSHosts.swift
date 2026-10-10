//
//  DNSHosts.swift
//  Anywhere
//
//  Created by NodePassProject on 10/10/26.
//

import Foundation
import Synchronization

nonisolated final class DNSHosts: Sendable {
    static let shared = DNSHosts()

    private struct Entry {
        var ipv4: [String] = []
        var ipv6: [String] = []
    }

    private let table = Mutex<[String: Entry]?>(nil)

    func addresses(for host: String, family: DNSAddressFamily) -> [String]? {
        var key = DNSName.cacheKey(for: host)
        if key.hasSuffix(".") { key.removeLast() }
        return table.withLock { table -> [String]? in
            if table == nil { table = Self.build(HostMapping.load()) }
            guard let entry = table?[key] else { return nil }
            switch family {
            case .ipv4: return entry.ipv4
            case .ipv6: return entry.ipv6
            case .preferIPv4: return entry.ipv4 + entry.ipv6
            }
        }
    }

    func invalidate() {
        table.withLock { $0 = nil }
    }

    private static func build(_ mappings: [HostMapping]) -> [String: Entry] {
        var table: [String: Entry] = [:]
        for mapping in mappings {
            guard let host = HostMapping.normalizedHost(mapping.host),
                  let address = HostMapping.canonicalAddress(mapping.address)
            else { continue }
            var entry = table[host, default: Entry()]
            if address.contains(":") {
                if !entry.ipv6.contains(address) { entry.ipv6.append(address) }
            } else if !entry.ipv4.contains(address) {
                entry.ipv4.append(address)
            }
            table[host] = entry
        }
        return table
    }
}
