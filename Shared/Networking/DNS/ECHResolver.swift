//
//  ECHResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation

nonisolated final class ECHResolver: Sendable {
    static let shared = ECHResolver()

    static let minTTL: TimeInterval = 60
    static let maxTTL: TimeInterval = 86_400
    static let negativeTTL: TimeInterval = 30
    static let queryTimeout: TimeInterval = 5

    private let cache = DNSLookupCache<String, Data?>(name: "ECH", capacity: DNSResolver.maxEntries, missing: nil)
    private let blockingBridge = DNSSyscallConcurrencyBridge()

    private init() {}

    // MARK: - Public API

    func resolveConfigList(for host: String) async -> Data? {
        let bare = DNSName.stripBrackets(host)
        if bare.isEmpty || DNSName.isIPAddress(bare) { return nil }

        let upstream = AWCore.getECHDNSUpstream()
        return await cache.value(for: DNSName.cacheKey(for: bare), from: upstream) { [self] in
            let result = await lookup(bare, upstream: upstream)
            let ttl = result
                .map { min(max(TimeInterval($0.ttl), Self.minTTL), Self.maxTTL) }
                ?? Self.negativeTTL
            return (value: result?.payload, ttl: ttl)
        }
    }

    func flush() {
        cache.flush()
    }

    // MARK: - Internal

    private func lookup(_ host: String, upstream: DNSUpstream) async -> (payload: Data, ttl: UInt32)? {
        if upstream.isSystem {
            return await blockingBridge.queryFirstRecord(
                host: host,
                rrtype: DNSMessage.typeHTTPS,
                timeout: Self.queryTimeout,
                accept: { echParseSVCBECH($0) }
            )
        }
        return (try? await DNSUpstreamClient.queryRecord(
            host,
            type: DNSMessage.typeHTTPS,
            via: upstream,
            accept: { echParseSVCBECH($0) }
        )) ?? nil
    }
}

private nonisolated func echParseSVCBECH(_ rdata: Data) -> Data? {
    return rdata.withUnsafeBytes { raw -> Data? in
        let bytes = raw.bindMemory(to: UInt8.self)
        guard let base = bytes.baseAddress else { return nil }
        let count = bytes.count
        var i = 0
        guard count >= 2 else { return nil }
        i += 2
        while i < count {
            let labelLen = Int(bytes[i]); i += 1
            if labelLen == 0 { break }
            if labelLen & 0xC0 != 0 { return nil }
            i += labelLen
            if i > count { return nil }
        }
        while i + 4 <= count {
            let paramKey = Int(bytes[i]) << 8 | Int(bytes[i + 1]); i += 2
            let valueLen = Int(bytes[i]) << 8 | Int(bytes[i + 1]); i += 2
            guard i + valueLen <= count else { return nil }
            if paramKey == 5 {
                guard valueLen > 0 else { return nil }
                return Data(bytes: base + i, count: valueLen)
            }
            i += valueLen
        }
        return nil
    }
}
