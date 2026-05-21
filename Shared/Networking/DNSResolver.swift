//
//  DNSResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

private let logger = AnywhereLogger(category: "DNSResolver")

// MARK: - DNSResolver

/// Thread-safe DNS cache for hostnames resolved outside the VPN tunnel — used
/// for both upstream proxy servers and direct-routed destinations. Always
/// resolves through the physical network interface via `getaddrinfo`, bypassing
/// the VPN tunnel to avoid routing loops.
///
/// Stale entries are returned immediately on TTL expiry and refreshed in the
/// background, so connect paths never block on DNS for previously-seen hosts.
/// Concurrent stale hits on the same hostname coalesce into one background
/// refresh. `forceFresh: true` overrides the stale-fast path for callers that
/// need accuracy (e.g. latency tests).
nonisolated final class DNSResolver {
    static let shared = DNSResolver()

    /// Default TTL for cached entries (seconds).
    static let defaultTTL: TimeInterval = 120

    private struct CacheEntry {
        let ips: [String]
        let expiry: Date
    }

    private var cache: [String: CacheEntry] = [:]
    private let lock = ReadWriteLock()

    /// Hostnames currently being refreshed in the background. Guards against
    /// duplicate concurrent `getaddrinfo` calls when many callers hit the
    /// stale-fast path for the same key at once.
    private var inFlightRefreshes: Set<String> = []

    /// Monotonic epoch bumped by ``flush``. A background refresh captures the
    /// epoch when it is scheduled and only commits its result if the epoch is
    /// still current, so a lookup that began on the previous network can't
    /// restore a flushed entry after the path has moved on. Lock-guarded
    /// alongside `cache`.
    private var generation: UInt64 = 0

    private init() {}

    // MARK: - Public API

    /// Resolves a hostname to IP address strings, using the cache when
    /// available. Always resolves via local DNS (physical interface), bypassing
    /// the VPN tunnel.
    ///
    /// - If `host` is already an IP, returns it directly without caching.
    /// - If the cache entry is fresh, returns it.
    /// - If the cache entry is stale and `forceFresh` is false, returns the
    ///   stale IPs immediately and triggers a background refresh.
    /// - Otherwise, resolves synchronously and caches the result; on synchronous
    ///   failure, falls back to stale IPs if any exist.
    ///
    /// - Parameter forceFresh: Bypass the stale-fast path and always resolve
    ///   synchronously when the cache is missing or expired. Use this for
    ///   latency tests and other flows where stale IPs would skew results.
    /// - Returns: All resolved IP addresses (IPv4 and IPv6), or empty on failure.
    func resolveAll(_ host: String, forceFresh: Bool = false) -> [String] {
        let bare = Self.stripBrackets(host)

        // IP addresses bypass cache
        if Self.isIPAddress(bare) { return [bare] }

        let key = bare.lowercased()

        let entry: CacheEntry? = lock.withReadLock { cache[key] }
        let cached = entry?.ips
        let expired = entry.map { $0.expiry <= Date() } ?? false

        // Cache hit — not expired
        if let cached, !expired { return cached }

        // Stale entry, not forceFresh — return stale, refresh in background.
        // forceFresh skips this path so callers that need accuracy (latency
        // tests) always block for a fresh lookup.
        if let cached, expired, !forceFresh {
            scheduleBackgroundRefresh(key: key, host: bare)
            return cached
        }

        // Cache miss, or forceFresh — resolve synchronously
        let ips = Self.resolveViaGetaddrinfo(bare)
        guard !ips.isEmpty else {
            // If we have stale IPs, return them as fallback
            if let cached { return cached }
            logger.warning("[DNS] Resolution failed for \(bare)")
            return []
        }

        lock.withWriteLock {
            cache[key] = CacheEntry(ips: ips, expiry: Date() + Self.defaultTTL)
        }

        return ips
    }

    /// Returns cached IPs for a domain without triggering resolution.
    /// Returns `nil` if no cache entry exists (not even stale).
    func cachedIPs(for host: String) -> [String]? {
        let bare = Self.stripBrackets(host)
        if Self.isIPAddress(bare) { return [bare] }
        let key = bare.lowercased()
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

    /// Drops every cached entry. Call this when the physical network path
    /// changes — interface switch (Wi-Fi⇄cellular), Wi-Fi roam, or restore from
    /// unavailable. Cached IPs were resolved against the *previous* network's
    /// resolver and can be wrong on the new one: split-horizon/corporate DNS,
    /// GeoDNS or CDN PoPs that differ per egress, or captive-portal answers
    /// picked up on the way in. Without a flush the stale-fast path keeps
    /// handing out those IPs for up to the full TTL, so connections
    /// reestablished right after the change redial addresses that may no longer
    /// route.
    ///
    /// Bumping the generation also voids any background refresh already in
    /// flight (its `getaddrinfo` may have been issued on the network we're
    /// leaving), so it can't quietly restore a flushed entry once it returns.
    /// The next lookup for each host then resolves fresh over the new path.
    func flush() {
        let cleared: Int = lock.withWriteLock {
            let count = cache.count
            cache.removeAll(keepingCapacity: true)
            inFlightRefreshes.removeAll(keepingCapacity: true)
            generation &+= 1
            return count
        }
        if cleared > 0 {
            logger.info("[DNS] Flushed \(cleared) cached \(cleared == 1 ? "entry" : "entries") after network change")
        }
    }

    // MARK: - Internal

    /// Fires a background refresh for `key` if one isn't already in flight.
    /// The lock-guarded set ensures duplicate concurrent stale-cache hits for
    /// the same hostname coalesce into one `getaddrinfo` call.
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
                // A flush during the lookup means we resolved against a network
                // path that no longer applies — drop the result. The flush also
                // cleared this key from inFlightRefreshes, so leave the set be.
                guard scheduledGeneration == self.generation else { return }
                if !ips.isEmpty {
                    self.cache[key] = CacheEntry(ips: ips, expiry: Date() + Self.defaultTTL)
                }
                self.inFlightRefreshes.remove(key)
            }
        }
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

    /// Resolves a domain to IP address strings via `getaddrinfo`.
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
