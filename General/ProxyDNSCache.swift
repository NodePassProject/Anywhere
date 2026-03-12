//
//  ProxyDNSCache.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation
import dnssd
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "ProxyDNSCache")

// MARK: - Local DNS Resolution (dns_sd)

/// Context object passed through the dns_sd callback's opaque pointer.
private final class DNSResolveContext {
    var ips: [String] = []
    var done = false
}

/// Callback for `DNSServiceGetAddrInfo`. Extracts IP addresses from each result.
private func dnssdAddrInfoCallback(
    _ sdRef: DNSServiceRef?,
    _ flags: DNSServiceFlags,
    _ interfaceIndex: UInt32,
    _ errorCode: DNSServiceErrorType,
    _ hostname: UnsafePointer<CChar>?,
    _ address: UnsafePointer<sockaddr>?,
    _ ttl: UInt32,
    _ context: UnsafeMutableRawPointer?
) {
    guard let context else { return }
    let ctx = Unmanaged<DNSResolveContext>.fromOpaque(context).takeUnretainedValue()

    if errorCode == kDNSServiceErr_NoError, let address {
        let family = address.pointee.sa_family
        if family == sa_family_t(AF_INET) {
            var addr = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                let ip = String(cString: buf)
                if !ctx.ips.contains(ip) { ctx.ips.append(ip) }
            }
        } else if family == sa_family_t(AF_INET6) {
            var addr = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                let ip = String(cString: buf)
                if !ctx.ips.contains(ip) { ctx.ips.append(ip) }
            }
        }
    }

    if (flags & kDNSServiceFlagsMoreComing) == 0 {
        ctx.done = true
    }
}

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
                let ips = Self.resolveViaLocalDNS(bare)
                if !ips.isEmpty {
                    self.lock.withWriteLock {
                        self.cache[key] = CacheEntry(ips: ips, expiry: Date() + Self.defaultTTL)
                    }
                }
            }
            return cached
        }

        // Cache miss or expired non-active entry — resolve synchronously
        let ips = Self.resolveViaLocalDNS(bare)
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

    /// Resolves a hostname and returns ``BSDSocket/ResolvedAddress`` array ready for TCP connect.
    ///
    /// Uses the DNS cache for domain lookups, then constructs sockaddrs via `getaddrinfo`
    /// with each cached IP (which is instant — no DNS involved).
    func resolveTCP(host: String, port: UInt16) throws -> [BSDSocket.ResolvedAddress] {
        let ips = resolveAll(host)
        guard !ips.isEmpty else {
            throw BSDSocketError.resolutionFailed("DNS resolution failed for \(host)")
        }

        var addresses: [BSDSocket.ResolvedAddress] = []
        for ip in ips {
            if let addrs = try? BSDSocket.resolveAddresses(host: ip, port: port) {
                addresses.append(contentsOf: addrs)
            }
        }

        guard !addresses.isEmpty else {
            throw BSDSocketError.resolutionFailed("No usable addresses for \(host)")
        }
        return addresses
    }

    // MARK: - Local DNS Resolution

    /// Resolves a domain via system DNS through the physical network interface,
    /// bypassing the VPN tunnel. Uses `DNSServiceGetAddrInfo` scoped to the
    /// primary non-tunnel interface (en0 for Wi-Fi, pdp_ip0 for cellular).
    /// Falls back to `getaddrinfo` if the physical interface can't be determined.
    private static func resolveViaLocalDNS(_ host: String) -> [String] {
        guard let ifIndex = physicalInterfaceIndex() else {
            logger.info("[DNS] No physical interface found, falling back to getaddrinfo for \(host, privacy: .public)")
            return resolveViaGetaddrinfo(host)
        }

        let ctx = DNSResolveContext()
        let ctxPtr = Unmanaged.passRetained(ctx).toOpaque()

        var sdRef: DNSServiceRef?
        let err = DNSServiceGetAddrInfo(
            &sdRef,
            0,
            ifIndex,
            DNSServiceProtocol(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6),
            host,
            dnssdAddrInfoCallback,
            ctxPtr
        )

        guard err == kDNSServiceErr_NoError, let ref = sdRef else {
            Unmanaged<DNSResolveContext>.fromOpaque(ctxPtr).release()
            logger.warning("[DNS] DNSServiceGetAddrInfo setup failed (\(err)) for \(host, privacy: .public), falling back")
            return resolveViaGetaddrinfo(host)
        }

        // Process events on the dns_sd socket with a 5-second timeout
        let fd = DNSServiceRefSockFD(ref)
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let deadline = CFAbsoluteTimeGetCurrent() + 5.0

        while !ctx.done {
            let remainingMs = Int32((deadline - CFAbsoluteTimeGetCurrent()) * 1000)
            if remainingMs <= 0 { break }

            let ret = Darwin.poll(&pfd, 1, min(remainingMs, 1000))
            if ret > 0 {
                DNSServiceProcessResult(ref)
            } else if ret < 0 && errno != EINTR {
                break
            }
        }

        DNSServiceRefDeallocate(ref)
        Unmanaged<DNSResolveContext>.fromOpaque(ctxPtr).release()

        if ctx.ips.isEmpty {
            logger.warning("[DNS] Local DNS returned no results for \(host, privacy: .public), falling back")
            return resolveViaGetaddrinfo(host)
        }

        return ctx.ips
    }

    /// Returns the interface index of the primary physical (non-tunnel) network interface.
    /// Prefers en0 (Wi-Fi), falls back to pdp_ip0 (cellular).
    private static func physicalInterfaceIndex() -> UInt32? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(first) }

        var enIndex: UInt32?
        var pdpIndex: UInt32?

        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = current {
            let name = String(cString: ifa.pointee.ifa_name)
            let flags = Int32(ifa.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0
            let isRunning = (flags & IFF_RUNNING) != 0

            if isUp && isRunning {
                if name == "en0" && enIndex == nil {
                    enIndex = if_nametoindex(name)
                } else if name.hasPrefix("pdp_ip") && pdpIndex == nil {
                    pdpIndex = if_nametoindex(name)
                }
            }
            current = ifa.pointee.ifa_next
        }

        return enIndex ?? pdpIndex
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
