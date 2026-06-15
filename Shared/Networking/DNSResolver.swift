//
//  DNSResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation
import dnssd

private let logger = AnywhereLogger(category: "DNSResolver")

// MARK: - DNSResolver

/// Thread-safe DNS cache resolving via `getaddrinfo` on the physical
/// interface, bypassing the tunnel to avoid routing loops.
///
/// Stale entries are served immediately and refreshed in the background
/// (coalesced per host), so connect paths block only on a cold miss;
/// `forceFresh` overrides for callers that need accuracy.
nonisolated final class DNSResolver {
    static let shared = DNSResolver()

    /// Default TTL for cached entries (seconds).
    static let defaultTTL: TimeInterval = 120

    /// How long past TTL a stale answer is still served before cleanup drops it.
    static let staleServeWindow: TimeInterval = defaultTTL

    /// Backstop cap; TTL-based cleanup normally bounds the cache.
    static let maxEntries = 1024

    /// Clamp bounds for a cached ECH HTTPS-record result.
    static let echMinTTL: TimeInterval = 60
    static let echMaxTTL: TimeInterval = 86_400
    /// How long a "no ECH record" answer is cached.
    static let echNegativeTTL: TimeInterval = 30
    /// Per-lookup timeout for the system-resolver HTTPS-record query.
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

    private var cache: [String: CacheEntry] = [:]

    /// ECHConfigList bytes discovered from DNS HTTPS records, keyed by
    /// lowercased host.
    private var echCache: [String: ECHCacheEntry] = [:]

    /// Coalesces concurrent ECH lookups for the same host (single-flight): the
    /// first caller queries DNS, later callers wait on its result.
    private var echWaiters: [String: [(Data?) -> Void]] = [:]

    private let lock = ReadWriteLock()

    /// Hosts with a background refresh in flight; coalesces duplicate lookups.
    private var inFlightRefreshes: Set<String> = []

    /// Epoch bumped by `flush`; a background refresh only commits if the epoch
    /// it captured is still current. Lock-guarded alongside `cache`.
    private var generation: UInt64 = 0

    private init() {}

    // MARK: - Public API

    /// Resolves a hostname to IP strings. A fresh hit returns immediately; a
    /// stale hit returns the old IPs and refreshes in the background unless
    /// `forceFresh` forces a synchronous lookup. Returns empty on failure.
    func resolveAll(_ host: String, forceFresh: Bool = false) -> [String] {
        let bare = Self.stripBrackets(host)

        if Self.isIPAddress(bare) { return [bare] }

        let key = Self.cacheKey(for: bare)

        let entry: CacheEntry? = lock.withReadLock { cache[key] }
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

        lock.withWriteLock {
            storeUnlocked(key: key, ips: ips)
        }

        return ips
    }

    /// Returns cached IPs without triggering resolution; `nil` when absent.
    func cachedIPs(for host: String) -> [String]? {
        let bare = Self.stripBrackets(host)
        if Self.isIPAddress(bare) { return [bare] }
        let key = Self.cacheKey(for: bare)
        return lock.withReadLock { cache[key]?.ips }
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
        let count: Int = lock.withWriteLock {
            generation &+= 1
            inFlightRefreshes.removeAll(keepingCapacity: true)
            // ECH configs can be split-horizon / GeoDNS specific too; drop them
            // so the next connection rediscovers against the new path. The
            // generation bump above also voids an in-flight lookup's commit.
            echCache.removeAll(keepingCapacity: true)
            let count = cache.count
            cache.removeAll(keepingCapacity: true)
            return count
        }
        guard count > 0 else { return }
        logger.info("[DNS] Cleared \(count) cached \(count == 1 ? "host" : "hosts") after network change")
    }

    // MARK: - Internal

    /// Fires a background refresh unless one is already in flight; the
    /// generation guard keeps a pre-flush lookup from committing.
    private func scheduleBackgroundRefresh(key: String, host: String) {
        let (shouldFire, scheduledGeneration): (Bool, UInt64) = lock.withWriteLock {
            if inFlightRefreshes.contains(key) { return (false, generation) }
            inFlightRefreshes.insert(key)
            return (true, generation)
        }
        guard shouldFire else { return }
        DispatchQueue.global(qos: .utility).async { [self] in
            let ips = Self.resolveViaGetaddrinfo(host)
            self.lock.withWriteLock {
                // Flushed mid-lookup; flush already cleared this key, so leave the set be.
                guard scheduledGeneration == self.generation else { return }
                if !ips.isEmpty {
                    self.storeUnlocked(key: key, ips: ips)
                }
                self.inFlightRefreshes.remove(key)
            }
        }
    }

    /// Inserts or refreshes `key`, then sweeps aged-out entries. Caller must
    /// hold the write lock.
    private func storeUnlocked(key: String, ips: [String]) {
        let now = CFAbsoluteTimeGetCurrent()
        cache[key] = CacheEntry(ips: ips, expiry: now + Self.defaultTTL)
        compactUnlocked(now: now)
    }

    /// Drops entries past the stale-serve window, then trims to `maxEntries`.
    /// Caller must hold the write lock.
    private func compactUnlocked(now: CFAbsoluteTime) {
        let cutoff = now - Self.staleServeWindow
        if cache.contains(where: { $0.value.expiry <= cutoff }) {
            cache = cache.filter { $0.value.expiry > cutoff }
        }

        while cache.count > Self.maxEntries {
            guard let coldest = cache.min(by: { $0.value.expiry < $1.value.expiry })?.key
            else { break }
            cache.removeValue(forKey: coldest)
        }
    }

    /// Drops expired ECH entries (not served stale), then trims to `maxEntries`.
    /// Caller must hold the write lock.
    private func compactECHUnlocked(now: CFAbsoluteTime) {
        if echCache.contains(where: { $0.value.expiry <= now }) {
            echCache = echCache.filter { $0.value.expiry > now }
        }

        while echCache.count > Self.maxEntries {
            guard let coldest = echCache.min(by: { $0.value.expiry < $1.value.expiry })?.key
            else { break }
            echCache.removeValue(forKey: coldest)
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
        var sa4 = sockaddr_in()
        if inet_pton(AF_INET, host, &sa4.sin_addr) == 1 { return true }
        var sa6 = sockaddr_in6()
        if inet_pton(AF_INET6, host, &sa6.sin6_addr) == 1 { return true }
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
                var addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    let ip = String(cString: buf)
                    if !ipv4.contains(ip) { ipv4.append(ip) }
                }
            } else if info.pointee.ai_family == AF_INET6 {
                var addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    let ip = String(cString: buf)
                    if !ipv6.contains(ip) { ipv6.append(ip) }
                }
            }
            current = info.pointee.ai_next
        }
        return ipv4 + ipv6
    }

    // MARK: - ECH (HTTPS record) resolution

    /// Resolves the ECHConfigList for `host` from its DNS HTTPS record (RFC 9460
    /// SvcParamKey 5, `ech`). The query goes through the system resolver — the
    /// same mDNSResponder path as `getaddrinfo`, so it inherits the same
    /// tunnel-bypass behavior. Results are cached by the record's TTL and misses
    /// are negatively cached briefly. `completion` runs on an arbitrary queue
    /// with the ECHConfigList bytes, or nil when no usable record is published.
    func resolveECHConfigList(for host: String, completion: @escaping (Data?) -> Void) {
        let bare = Self.stripBrackets(host)
        // An IP literal has no domain that could carry an HTTPS record.
        if bare.isEmpty || Self.isIPAddress(bare) { completion(nil); return }

        let key = Self.cacheKey(for: bare)
        let now = CFAbsoluteTimeGetCurrent()

        enum Action { case cached(Data?); case joined; case lead(generation: UInt64) }
        let action: Action = lock.withWriteLock {
            if let entry = echCache[key], entry.expiry > now {
                return .cached(entry.config)
            }
            if echWaiters[key] != nil {
                echWaiters[key]?.append(completion)
                return .joined
            }
            echWaiters[key] = []          // claim leadership for this host
            return .lead(generation: generation)
        }

        switch action {
        case .cached(let config):
            completion(config)
        case .joined:
            break                          // resumed by the leader below
        case .lead(let scheduledGeneration):
            DispatchQueue.global(qos: .userInitiated).async { [self] in
                let result = Self.queryHTTPSRecordECH(host: bare)
                let (config, waiters): (Data?, [(Data?) -> Void]) = lock.withWriteLock {
                    let waiters = echWaiters[key] ?? []
                    echWaiters[key] = nil
                    // A flush mid-lookup bumps the generation: this result may be
                    // bound to the pre-change network path, so discard it and let
                    // callers fail closed and rediscover rather than sealing
                    // against a stale ECH key.
                    guard scheduledGeneration == generation else { return (nil, waiters) }
                    let ttl: TimeInterval = result
                        .map { min(max(TimeInterval($0.ttl), Self.echMinTTL), Self.echMaxTTL) }
                        ?? Self.echNegativeTTL
                    let insertedAt = CFAbsoluteTimeGetCurrent()
                    echCache[key] = ECHCacheEntry(config: result?.config,
                                                  expiry: insertedAt + ttl)
                    compactECHUnlocked(now: insertedAt)
                    return (result?.config, waiters)
                }
                completion(config)
                for waiter in waiters { waiter(config) }
            }
        }
    }

    /// Blocking system-resolver query for `host`'s HTTPS record, returning the
    /// `ech` SvcParam bytes and the record's TTL, or nil on miss/timeout. Drives
    /// the dns_sd request to completion on the calling (background) queue.
    private static func queryHTTPSRecordECH(host: String) -> (config: Data, ttl: UInt32)? {
        final class QueryResult { var config: Data?; var ttl: UInt32 = 0; var answered = false }
        let result = QueryResult()

        // Non-capturing so it bridges to the C callback; state flows via context.
        let callback: DNSServiceQueryRecordReply = { _, flags, _, errorCode, _, rrtype, _, rdlen, rdata, ttl, context in
            guard let context else { return }
            let result = Unmanaged<QueryResult>.fromOpaque(context).takeUnretainedValue()
            // MoreComing clear marks the batch complete; note it so the poll loop
            // stops instead of waiting out the timeout when the host publishes no
            // usable ECH record (the common negative case resolves promptly).
            if (flags & kDNSServiceFlagsMoreComing) == 0 { result.answered = true }
            guard errorCode == kDNSServiceErr_NoError,
                  rrtype == kHTTPSRecordType, let rdata, rdlen > 0
            else { return }
            guard result.config == nil else { return }   // keep the first usable record
            if let ech = echParseSVCBECH(Data(bytes: rdata, count: Int(rdlen))) {
                result.config = ech
                result.ttl = ttl
            }
        }

        var serviceRef: DNSServiceRef?
        let context = Unmanaged.passUnretained(result).toOpaque()
        let queryError = host.withCString { cHost in
            DNSServiceQueryRecord(&serviceRef, 0, 0, cHost,
                                  kHTTPSRecordType, UInt16(kDNSServiceClass_IN), callback, context)
        }
        guard queryError == kDNSServiceErr_NoError, let serviceRef else { return nil }
        defer { DNSServiceRefDeallocate(serviceRef) }

        let fd = DNSServiceRefSockFD(serviceRef)
        guard fd >= 0 else { return nil }

        let deadline = CFAbsoluteTimeGetCurrent() + echQueryTimeout
        while result.config == nil, !result.answered {
            let remaining = deadline - CFAbsoluteTimeGetCurrent()
            if remaining <= 0 { break }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pfd, 1, Int32(remaining * 1000))
            guard ready > 0, (pfd.revents & Int16(POLLIN)) != 0 else { break }
            if DNSServiceProcessResult(serviceRef) != kDNSServiceErr_NoError { break }
        }
        guard let config = result.config else { return nil }
        return (config, result.ttl)
    }
}

/// DNS RR type for HTTPS records (RFC 9460). Used as a literal to avoid a hard
/// dependency on `kDNSServiceType_HTTPS`, which is missing from older SDKs.
private let kHTTPSRecordType: UInt16 = 65

/// Extracts the `ech` SvcParam (SvcParamKey 5) from an HTTPS/SVCB record's RDATA
/// (RFC 9460): `SvcPriority(2) ++ TargetName ++ SvcParams`, where each SvcParam
/// is `key(2) ++ length(2) ++ value`. Returns the ECHConfigList bytes, or nil
/// when absent. TargetName is uncompressed per spec; AliasMode (priority 0,
/// no params) yields nil. A free function so the C callback can reach it.
private func echParseSVCBECH(_ rdata: Data) -> Data? {
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
