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

    static func normalizedHost(_ host: String) -> String? {
        var name = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.utf8.count <= 253, !isIPAddress(name) else { return nil }
        for label in name.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.utf8.first != UInt8(ascii: "-"), label.utf8.last != UInt8(ascii: "-"),
                  label.utf8.allSatisfy(isLabelByte)
            else { return nil }
        }
        return name
    }

    static func normalizedDomainSuffix(_ suffix: String) -> String? {
        var name = suffix.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.hasPrefix("*.") || name.hasPrefix("+.") {
            name.removeFirst(2)
        } else if name.hasPrefix(".") {
            name.removeFirst()
        }
        return normalizedHost(name)
    }

    private static func isLabelByte(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || byte == UInt8(ascii: "-")
            || byte == UInt8(ascii: "_")
    }
}
