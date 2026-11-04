//
//  DNSMode.swift
//  Anywhere
//
//  Created by NodePassProject on 7/24/26.
//

import Foundation

nonisolated enum DNSMode: String, CaseIterable {
    case `default`
    case udp
    case doh

    var title: String {
        switch self {
        case .default: return String(localized: "Default")
        case .udp: return String(localized: "UDP")
        case .doh: return String(localized: "DoH")
        }
    }
}

nonisolated enum FallbackDNSMode: String, CaseIterable {
    case `default`
    case udp

    var title: String {
        switch self {
        case .default: return String(localized: "Default")
        case .udp: return String(localized: "UDP")
        }
    }
}

nonisolated enum DNSUpstream: Sendable, Equatable {
    case system
    case udp(host: String, port: UInt16)
    case doh(URL)

    static let defaultPort: UInt16 = 53
    static let defaultUDPServer = "1.1.1.1"
    static let defaultDoHURL = "https://cloudflare-dns.com/dns-query"

    static let defaultUDP = DNSUpstream.udp(host: defaultUDPServer, port: defaultPort)
    static let defaultDoH = DNSUpstream.doh(URL(string: defaultDoHURL)!)
    
    static func forwardingServers(preferring preferred: DNSUpstream, includeIPv6: Bool) -> [String] {
        let builtIn = builtInServers(includeIPv6: includeIPv6)
        guard case .udp(let host, _) = preferred,
              includeIPv6 || !isIPv6Literal(host)
        else { return builtIn }
        return [host] + builtIn.filter { $0 != host }
    }

    private static func builtInServers(includeIPv6: Bool) -> [String] {
        includeIPv6
            ? ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
            : ["1.1.1.1", "1.0.0.1"]
    }

    init(mode: DNSMode, udpServer: String, dohURL: String) {
        switch mode {
        case .default: self = .system
        case .udp: self = Self.parseUDP(udpServer) ?? Self.defaultUDP
        case .doh: self = Self.parseDoH(dohURL) ?? Self.defaultDoH
        }
    }

    var isSystem: Bool { self == .system }
    
    static func parseUDP(_ server: String) -> DNSUpstream? {
        let trimmed = server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let rest = trimmed[trimmed.index(after: close)...]
            guard let canonicalHost = canonicalIPv6(host) else { return nil }
            if rest.isEmpty { return .udp(host: canonicalHost, port: defaultPort) }
            guard rest.hasPrefix(":"), let port = parsePort(rest.dropFirst()) else { return nil }
            return .udp(host: canonicalHost, port: port)
        }

        if let canonicalHost = canonicalIPv6(trimmed) { return .udp(host: canonicalHost, port: defaultPort) }

        let parts = trimmed.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard let canonicalHost = canonicalIPv4(String(parts[0])) else { return nil }
        guard parts.count == 2 else { return .udp(host: canonicalHost, port: defaultPort) }
        guard let port = parsePort(parts[1]) else { return nil }
        return .udp(host: canonicalHost, port: port)
    }
    
    static func parseDoH(_ urlString: String) -> DNSUpstream? {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let url = URL(string: trimmed),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty
        else { return nil }
        return .doh(url)
    }

    private static func parsePort(_ text: some StringProtocol) -> UInt16? {
        guard let port = UInt16(text), port > 0 else { return nil }
        return port
    }

    static func isIPv6Literal(_ host: String) -> Bool {
        canonicalIPv6(host) != nil
    }
    
    static func canonicalIPv4(_ host: String) -> String? {
        var address = in_addr()
        guard inet_pton(AF_INET, host, &address) == 1 else { return nil }
        return format(&address, family: AF_INET, capacity: INET_ADDRSTRLEN)
    }
    
    static func canonicalIPv6(_ host: String) -> String? {
        var address = in6_addr()
        guard inet_pton(AF_INET6, host, &address) == 1 else { return nil }
        return format(&address, family: AF_INET6, capacity: INET6_ADDRSTRLEN)
    }

    private static func format(_ address: UnsafeRawPointer, family: Int32, capacity: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(capacity))
        guard inet_ntop(family, address, &buffer, socklen_t(capacity)) != nil else { return nil }
        return buffer.withUnsafeBufferPointer { pointer in
            pointer.baseAddress.map { String(cString: $0) }
        }
    }
}
