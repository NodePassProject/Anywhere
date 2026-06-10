//
//  DNSResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

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

    private struct CacheEntry {
        let ips: [String]
        let expiry: CFAbsoluteTime
    }

    private var cache: [String: CacheEntry] = [:]
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
}
