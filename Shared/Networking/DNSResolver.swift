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

    /// How long past TTL a stale answer is still served before cleanup drops it.
    static let staleServeWindow: TimeInterval = defaultTTL

    /// Backstop cap; TTL-based cleanup normally bounds the cache.
    static let maxEntries = 1024

    static let echMinTTL: TimeInterval = 60
    static let echMaxTTL: TimeInterval = 86_400
    static let echNegativeTTL: TimeInterval = 30
    static let echQueryTimeout: TimeInterval = 5

    private struct CacheEntry {
        let ips: [String]
        let expiry: CFAbsoluteTime
    }

    private struct ECHCacheEntry {
        /// nil = negative cache: the host publishes no usable ECH record.
        let config: Data?
        let expiry: CFAbsoluteTime
    }

    private struct State {
        var cache: [String: CacheEntry] = [:]

        /// ECHConfigList bytes discovered from DNS HTTPS records, keyed by
        /// lowercased host.
        var echCache: [String: ECHCacheEntry] = [:]

        /// Coalesces concurrent ECH lookups for the same host (single-flight): the
        /// first caller queries DNS, later callers await its shared task.
        var echInFlight: [String: Task<Data?, Never>] = [:]

        /// Hosts with a background refresh in flight; coalesces duplicate lookups.
        var inFlightRefreshes: Set<String> = []

        /// Epoch bumped by `flush`; a background refresh only commits if the epoch
        /// it captured is still current.
        var generation: UInt64 = 0
    }

    private let state = Mutex(State())
    
    private static let blockingBridge = DNSSyscallConcurrencyBridge()

    private init() {}

    // MARK: - Public API

    /// Async counterpart of ``resolveAll(_:forceFresh:)``: the potentially blocking
    /// lookup runs on the resolver's worker queue and resumes the caller with the result.
    func resolveAll(_ host: String, forceFresh: Bool = false) async -> [String] {
        await Self.blockingBridge.run {
            self.resolveAll(host, forceFresh: forceFresh)
        }
    }

    /// Async counterpart of ``resolveHost(_:forceFresh:)``.
    func resolveHost(_ host: String, forceFresh: Bool = false) async -> String? {
        await resolveAll(host, forceFresh: forceFresh).first
    }

    /// Async counterpart of ``prewarm(_:forceFresh:)``.
    func prewarm(_ host: String, forceFresh: Bool = false) async {
        _ = await resolveAll(host, forceFresh: forceFresh)
    }

    // MARK: - Public API (synchronous — blocking-tolerant callers only)

    /// Resolves a hostname to IP strings. A fresh hit returns immediately; a
    /// stale hit returns the old IPs and refreshes in the background unless
    /// `forceFresh` forces a synchronous lookup. Returns empty on failure.
    func resolveAll(_ host: String, forceFresh: Bool = false) -> [String] {
        let bare = Self.stripBrackets(host)

        if Self.isIPAddress(bare) { return [bare] }

        let key = Self.cacheKey(for: bare)

        let entry: CacheEntry? = state.withLock { $0.cache[key] }
        let cached = entry?.ips
        let expired = entry.map { $0.expiry <= CFAbsoluteTimeGetCurrent() } ?? false

        if let cached, !expired { return cached }

        if let cached, expired, !forceFresh {
            scheduleBackgroundRefresh(key: key, host: bare)
            return cached
        }

        let ips = Self.resolveViaGetaddrinfo(bare)
        guard !ips.isEmpty else {
            if let cached { return cached }
            logger.warning("[DNS] Resolution failed for \(bare)")
            return []
        }

        state.withLock { Self.store(&$0, key: key, ips: ips) }

        return ips
    }

    /// Returns cached IPs without triggering resolution; `nil` when absent.
    func cachedIPs(for host: String) -> [String]? {
        let bare = Self.stripBrackets(host)
        if Self.isIPAddress(bare) { return [bare] }
        let key = Self.cacheKey(for: bare)
        return state.withLock { $0.cache[key]?.ips }
    }

    /// Convenience: returns a single resolved IP (first result), or `nil` on failure.
    func resolveHost(_ host: String, forceFresh: Bool = false) -> String? {
        resolveAll(host, forceFresh: forceFresh).first
    }

    /// Pre-resolves and caches a hostname so subsequent lookups are instant.
    func prewarm(_ host: String, forceFresh: Bool = false) {
        _ = resolveAll(host, forceFresh: forceFresh)
    }

    /// Drops every cached entry; call on physical network path change, where
    /// cached IPs may be wrong (split-horizon DNS, GeoDNS). Bumping the
    /// generation voids in-flight refreshes; clearing `inFlightRefreshes` is
    /// required because voided commits bail without self-removing.
    func flush() {
        let count: Int = state.withLock { state in
            state.generation &+= 1
            state.inFlightRefreshes.removeAll(keepingCapacity: true)
            // ECH configs can be split-horizon / GeoDNS specific too; drop them
            // so the next connection rediscovers against the new path. The
            // generation bump above also voids an in-flight lookup's commit.
            state.echCache.removeAll(keepingCapacity: true)
            let count = state.cache.count
            state.cache.removeAll(keepingCapacity: true)
            return count
        }
        guard count > 0 else { return }
        logger.info("[DNS] Cleared \(count) cached \(count == 1 ? "host" : "hosts") after network change")
    }

    // MARK: - Internal

    /// Fires a background refresh unless one is already in flight; the
    /// generation guard keeps a pre-flush lookup from committing.
    private func scheduleBackgroundRefresh(key: String, host: String) {
        let (shouldFire, scheduledGeneration): (Bool, UInt64) = state.withLock { state in
            if state.inFlightRefreshes.contains(key) { return (false, state.generation) }
            state.inFlightRefreshes.insert(key)
            return (true, state.generation)
        }
        guard shouldFire else { return }
        Task { [self] in
            let ips = await Self.blockingBridge.run { Self.resolveViaGetaddrinfo(host) }
            state.withLock { state in
                // Flushed mid-lookup; flush already cleared this key, so leave the set be.
                guard scheduledGeneration == state.generation else { return }
                if !ips.isEmpty {
                    Self.store(&state, key: key, ips: ips)
                }
                state.inFlightRefreshes.remove(key)
            }
        }
    }

    /// Inserts or refreshes `key`, then sweeps aged-out entries.
    private static func store(_ state: inout State, key: String, ips: [String]) {
        let now = CFAbsoluteTimeGetCurrent()
        state.cache[key] = CacheEntry(ips: ips, expiry: now + Self.defaultTTL)
        compact(&state, now: now)
    }

    /// Drops entries past the stale-serve window, then trims to `maxEntries`.
    private static func compact(_ state: inout State, now: CFAbsoluteTime) {
        let cutoff = now - Self.staleServeWindow
        if state.cache.contains(where: { $0.value.expiry <= cutoff }) {
            state.cache = state.cache.filter { $0.value.expiry > cutoff }
        }

        while state.cache.count > Self.maxEntries {
            guard let coldest = state.cache.min(by: { $0.value.expiry < $1.value.expiry })?.key
            else { break }
            state.cache.removeValue(forKey: coldest)
        }
    }

    /// Drops expired ECH entries (not served stale), then trims to `maxEntries`.
    private static func compactECH(_ state: inout State, now: CFAbsoluteTime) {
        if state.echCache.contains(where: { $0.value.expiry <= now }) {
            state.echCache = state.echCache.filter { $0.value.expiry > now }
        }

        while state.echCache.count > Self.maxEntries {
            guard let coldest = state.echCache.min(by: { $0.value.expiry < $1.value.expiry })?.key
            else { break }
            state.echCache.removeValue(forKey: coldest)
        }
    }

    /// Lowercased cache key that avoids allocating for the common all-lowercase
    /// ASCII case; bytes >= 0x80 may be subject to Unicode case-folding.
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

    // MARK: - ECH (HTTPS record) resolution
    
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
        // The DNSService fd/poll machinery lives in the bridge; this side only supplies the
        // SVCB "ech" SvcParam parser and caches the outcome.
        let result = await Self.blockingBridge.queryFirstRecord(
            host: bare,
            rrtype: kHTTPSRecordType,
            timeout: Self.echQueryTimeout,
            accept: { echParseSVCBECH($0) }
        )

        return state.withLock { state in
            state.echInFlight[key] = nil
            // A flush mid-lookup bumps the generation: this result may be bound
            // to the pre-change network path, so discard it and let callers fail
            // closed and rediscover rather than sealing against a stale ECH key.
            guard scheduledGeneration == state.generation else { return nil }
            let ttl: TimeInterval = result
                .map { min(max(TimeInterval($0.ttl), Self.echMinTTL), Self.echMaxTTL) }
                ?? Self.echNegativeTTL
            let insertedAt = CFAbsoluteTimeGetCurrent()
            state.echCache[key] = ECHCacheEntry(config: result?.payload,
                                                expiry: insertedAt + ttl)
            Self.compactECH(&state, now: insertedAt)
            return result?.payload
        }
    }
}

/// DNS RR type for HTTPS records (RFC 9460). Used as a literal to avoid a hard
/// dependency on `kDNSServiceType_HTTPS`, which is missing from older SDKs.
private nonisolated let kHTTPSRecordType: UInt16 = 65

/// Extracts the `ech` SvcParam (SvcParamKey 5) from an HTTPS/SVCB record's RDATA
/// (RFC 9460): `SvcPriority(2) ++ TargetName ++ SvcParams`, where each SvcParam
/// is `key(2) ++ length(2) ++ value`. Returns the ECHConfigList bytes, or nil
/// when absent. TargetName is uncompressed per spec; AliasMode (priority 0,
/// no params) yields nil. Passed to the DNS bridge as the record-payload parser.
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
