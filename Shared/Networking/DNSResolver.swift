//
//  DNSResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "DNSResolver")

nonisolated final class DNSResolver: Sendable {
    static let shared = DNSResolver()

    static let defaultTTL: TimeInterval = 120

    static let maxEntries = 1024

    static let echMinTTL: TimeInterval = 60
    static let echMaxTTL: TimeInterval = 86_400
    static let echNegativeTTL: TimeInterval = 30
    static let echQueryTimeout: TimeInterval = 5

    private struct CacheEntry: ExpiringEntry {
        let ips: [String]
        let expiry: CFAbsoluteTime
    }

    private struct ECHCacheEntry: ExpiringEntry {
        let config: Data?
        let expiry: CFAbsoluteTime
    }
    
    private struct State {
        var cache: [String: CacheEntry] = [:]
        var inFlight: [String: Task<[String], Never>] = [:]
        var echCache: [String: ECHCacheEntry] = [:]
        var echInFlight: [String: Task<Data?, Never>] = [:]
        var generation: UInt64 = 0
    }

    private let state = Mutex(State())
    
    private static let blockingBridge = DNSSyscallConcurrencyBridge()

    private init() {}

    // MARK: - Public API
    
    func resolveAll(_ host: String, forceFresh: Bool = false) async -> [String] {
        let bare = Self.stripBrackets(host)

        if Self.isIPAddress(bare) { return [bare] }

        let key = Self.cacheKey(for: bare)

        enum Role {
            case cacheHit([String])
            case join(Task<[String], Never>)
        }

        let (role, cached): (Role, [String]?) = state.withLock { state in
            let entry = state.cache[key]
            let cached = entry?.ips
            let expired = entry.map { $0.expiry <= CFAbsoluteTimeGetCurrent() } ?? false

            if let cached, !expired, !forceFresh { return (.cacheHit(cached), cached) }
            if let existing = state.inFlight[key] { return (.join(existing), cached) }

            let scheduledGeneration = state.generation
            let task = Task<[String], Never> { [self] in
                await lookup(key: key, host: bare, scheduledGeneration: scheduledGeneration)
            }
            state.inFlight[key] = task
            return (.join(task), cached)
        }

        let ips: [String]
        switch role {
        case .cacheHit(let hit): return hit
        case .join(let task): ips = await task.value
        }

        guard !ips.isEmpty else {
            if let cached { return cached }
            logger.warning("[DNS] Resolution failed for \(bare)")
            return []
        }

        return ips
    }

    func resolveHost(_ host: String, forceFresh: Bool = false) async -> String? {
        await resolveAll(host, forceFresh: forceFresh).first
    }

    func prewarm(_ host: String, forceFresh: Bool = false) async {
        _ = await resolveAll(host, forceFresh: forceFresh)
    }
    
    func cachedIPs(for host: String) -> [String]? {
        let bare = Self.stripBrackets(host)
        if Self.isIPAddress(bare) { return [bare] }
        let key = Self.cacheKey(for: bare)
        return state.withLock { $0.cache[key]?.ips }
    }

    func flush() {
        let count: Int = state.withLock { state in
            state.generation &+= 1
            state.echCache.removeAll(keepingCapacity: true)
            let count = state.cache.count
            state.cache.removeAll(keepingCapacity: true)
            return count
        }
        guard count > 0 else { return }
        logger.info("[DNS] Cleared \(count) cached \(count == 1 ? "host" : "hosts") after network change")
    }

    // MARK: - Internal
    
    private func lookup(key: String, host: String, scheduledGeneration: UInt64) async -> [String] {
        let resolved = await Self.blockingBridge.run { Self.resolveViaGetaddrinfo(host) }
        state.withLock { state in
            state.inFlight.removeValue(forKey: key)
            guard scheduledGeneration == state.generation, !resolved.isEmpty else { return }
            Self.store(&state, key: key, ips: resolved)
        }
        return resolved
    }

    private static func store(_ state: inout State, key: String, ips: [String]) {
        let now = CFAbsoluteTimeGetCurrent()
        state.cache[key] = CacheEntry(ips: ips, expiry: now + Self.defaultTTL)
        compact(&state.cache, now: now)
    }
    
    private static func compact<Entry: ExpiringEntry>(_ cache: inout [String: Entry], now: CFAbsoluteTime) {
        if cache.contains(where: { $0.value.expiry <= now }) {
            cache = cache.filter { $0.value.expiry > now }
        }

        while cache.count > Self.maxEntries {
            guard let coldest = cache.min(by: { $0.value.expiry < $1.value.expiry })?.key
            else { break }
            cache.removeValue(forKey: coldest)
        }
    }

    private static func cacheKey(for host: String) -> String {
        for byte in host.utf8
        where (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) || byte >= 0x80 {
            return host.lowercased()
        }
        return host
    }

    private static func stripBrackets(_ host: String) -> String {
        host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast())
            : host
    }

    private static func isIPAddress(_ host: String) -> Bool {
        var ipv4SockAddr = sockaddr_in()
        if inet_pton(AF_INET, host, &ipv4SockAddr.sin_addr) == 1 { return true }
        var ipv6SockAddr = sockaddr_in6()
        if inet_pton(AF_INET6, host, &ipv6SockAddr.sin6_addr) == 1 { return true }
        return false
    }

    private static func resolveViaGetaddrinfo(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0, let res = result else { return [] }
        defer { freeaddrinfo(res) }

        var ipv4: [String] = []
        var ipv6: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = res
        while let info = current {
            if info.pointee.ai_family == AF_INET {
                var address = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &address.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    let ip = String(nulTerminated: buffer)
                    if !ipv4.contains(ip) { ipv4.append(ip) }
                }
            } else if info.pointee.ai_family == AF_INET6 {
                var address = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &address.sin6_addr, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    let ip = String(nulTerminated: buffer)
                    if !ipv6.contains(ip) { ipv6.append(ip) }
                }
            }
            current = info.pointee.ai_next
        }
        return ipv4 + ipv6
    }

    // MARK: - ECH resolution
    
    func resolveECHConfigList(for host: String) async -> Data? {
        let bare = Self.stripBrackets(host)
        // An IP literal has no domain that could carry an HTTPS record.
        if bare.isEmpty || Self.isIPAddress(bare) { return nil }

        let key = Self.cacheKey(for: bare)
        let now = CFAbsoluteTimeGetCurrent()

        enum Action { case cached(Data?); case join(Task<Data?, Never>) }
        let action: Action = state.withLock { state in
            if let entry = state.echCache[key], entry.expiry > now {
                return .cached(entry.config)
            }
            if let existing = state.echInFlight[key] {
                return .join(existing)          // await the in-flight leader
            }
            let scheduledGeneration = state.generation
            let task = Task<Data?, Never> { [self] in
                await lookupECH(bare: bare, key: key, scheduledGeneration: scheduledGeneration)
            }
            state.echInFlight[key] = task
            return .join(task)
        }

        switch action {
        case .cached(let config):
            return config
        case .join(let task):
            return await task.value
        }
    }
    
    private func lookupECH(bare: String, key: String, scheduledGeneration: UInt64) async -> Data? {
        let result = await Self.blockingBridge.queryFirstRecord(
            host: bare,
            rrtype: kHTTPSRecordType,
            timeout: Self.echQueryTimeout,
            accept: { echParseSVCBECH($0) }
        )

        return state.withLock { state in
            state.echInFlight[key] = nil
            guard scheduledGeneration == state.generation else { return nil }
            let ttl: TimeInterval = result
                .map { min(max(TimeInterval($0.ttl), Self.echMinTTL), Self.echMaxTTL) }
                ?? Self.echNegativeTTL
            let insertedAt = CFAbsoluteTimeGetCurrent()
            state.echCache[key] = ECHCacheEntry(config: result?.payload,
                                                expiry: insertedAt + ttl)
            Self.compact(&state.echCache, now: insertedAt)
            return result?.payload
        }
    }
}

private nonisolated protocol ExpiringEntry {
    var expiry: CFAbsoluteTime { get }
}

private nonisolated let kHTTPSRecordType: UInt16 = 65

private nonisolated func echParseSVCBECH(_ rdata: Data) -> Data? {
    return rdata.withUnsafeBytes { raw -> Data? in
        let bytes = raw.bindMemory(to: UInt8.self)
        guard let base = bytes.baseAddress else { return nil }
        let count = bytes.count
        var i = 0
        guard count >= 2 else { return nil }                  // SvcPriority
        i += 2
        while i < count {                                     // TargetName labels
            let labelLen = Int(bytes[i]); i += 1
            if labelLen == 0 { break }
            if labelLen & 0xC0 != 0 { return nil }             // no compression in SVCB
            i += labelLen
            if i > count { return nil }
        }
        while i + 4 <= count {                                // SvcParams
            let paramKey = Int(bytes[i]) << 8 | Int(bytes[i + 1]); i += 2
            let valueLen = Int(bytes[i]) << 8 | Int(bytes[i + 1]); i += 2
            guard i + valueLen <= count else { return nil }
            if paramKey == 5 {                                 // SvcParamKey "ech"
                guard valueLen > 0 else { return nil }
                return Data(bytes: base + i, count: valueLen)
            }
            i += valueLen
        }
        return nil
    }
}
