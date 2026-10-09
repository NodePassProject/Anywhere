//
//  DNSName.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation

nonisolated enum DNSName {
    static func stripBrackets(_ host: String) -> String {
        host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast())
            : host
    }

    static func isIPAddress(_ host: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 { return true }
        var v6 = in6_addr()
        return inet_pton(AF_INET6, host, &v6) == 1
    }

    static func cacheKey(for host: String) -> String {
        for byte in host.utf8
        where (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) || byte >= 0x80 {
            return host.lowercased()
        }
        return host
    }
}
