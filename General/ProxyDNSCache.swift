//
//  ProxyDNSCache.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "ProxyDNSCache")

// MARK: - ProxyDNSCache

/// Thread-safe DNS cache for proxy server domains. Always resolves through the
/// physical network interface using `DNSServiceGetAddrInfo`, bypassing the VPN
/// tunnel to avoid routing loops.
///
/// The active proxy domain (set via ``setActiveProxyDomain(_:)``) returns stale
/// cached IPs on TTL expiry (to avoid blocking connections) while refreshing in
/// the background. Non-active domains refresh synchronously.
final class ProxyDNSCache {
    static let shared = ProxyDNSCache()

    /// Default TTL for cached entries (seconds).
    static let defaultTTL: TimeInterval = 120

    private struct CacheEntry {
        let ips: [String]
        let expiry: Date
    }

    private var cache: [String: CacheEntry] = [:]
    private let lock = ReadWriteLock()

    /// The currently active proxy domain (returns stale IPs on expiry instead of blocking).
    private var activeProxyDomain: String?

    private init() {}

    /// Set the currently active proxy domain. It gets stale-IP treatment on TTL
    /// expiry (returns cached IPs immediately, refreshes in background).
    func setActiveProxyDomain(_ domain: String?) {
        lock.withWriteLock {
            activeProxyDomain = domain.map { Self.stripBrackets($0).lowercased() }
        }
    }

    // MARK: - Public API

    /// Resolves a proxy server hostname to IP address strings, using the cache
    /// when available. Always resolves via local DNS (physical interface),
    /// bypassing the VPN tunnel.
    ///
    /// - If `host` is already an IP, returns it directly without caching.
    /// - If `host` is the active proxy domain and cache is expired, returns stale
    ///   IPs immediately and refreshes in the background.
    /// - Otherwise, resolves synchronously and caches the result.
    ///
    /// - Returns: All resolved IP addresses (IPv4 and IPv6), or empty on failure.
    func resolveAll(_ host: String) -> [String] {
        let bare = Self.stripBrackets(host)

        // IP addresses bypass cache
        if Self.isIPAddress(bare) { return [bare] }

        let key = bare.lowercased()

        let isActive: Bool = lock.withReadLock { activeProxyDomain == key }

        // Check cache
        let (cached, expired): ([String]?, Bool) = lock.withReadLock {
            if let entry = cache[key] {
                if entry.expiry > Date() {
                    return (entry.ips, false)
                } else {
                    return (entry.ips, true)
                }
            }
            return (nil, false)
        }

        // Cache hit — not expired
        if let cached, !expired { return cached }

        // Active proxy with stale cache — return stale, refresh in background
        if let cached, expired, isActive {
            DispatchQueue.global(qos: .utility).async { [self] in
                let ips = Self.resolveViaGetaddrinfo(bare)
                if !ips.isEmpty {
                    self.lock.withWriteLock {
                        self.cache[key] = CacheEntry(ips: ips, expiry: Date() + Self.defaultTTL)
                    }
                }
            }
            return cached
        }

        // Cache miss or expired non-active entry — resolve synchronously
        let ips = Self.resolveViaGetaddrinfo(bare)
        guard !ips.isEmpty else {
            // If we have stale IPs, return them as fallback
            if let cached { return cached }
            logger.warning("[DNS] Resolution failed for \(bare, privacy: .public)")
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
    func resolveHost(_ host: String) -> String? {
        resolveAll(host).first
    }

    /// Pre-resolves and caches a hostname so subsequent lookups are instant.
    func prewarm(_ host: String) {
        _ = resolveAll(host)
    }

    // MARK: - Internal

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

        var ips: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = res
        while let info = current {
            if info.pointee.ai_family == AF_INET {
                var addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    let ip = String(cString: buf)
                    if !ips.contains(ip) { ips.append(ip) }
                }
            } else if info.pointee.ai_family == AF_INET6 {
                var addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    let ip = String(cString: buf)
                    if !ips.contains(ip) { ips.append(ip) }
                }
            }
            current = info.pointee.ai_next
        }
        return ips
    }
}
