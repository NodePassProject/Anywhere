//
//  DNSResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

nonisolated final class DNSResolver: Sendable {
    static let proxies = DNSResolver(
        upstream: { AWCore.getProxyDNSUpstream().reachable },
        hosts: nil,
        fallsBackToSystem: true,
        servesStaleOnFailure: true,
        waitLimit: nil
    )
    
    static let localRequests = DNSResolver(
        upstream: {
            let upstream = AWCore.getLocalRequestDNSUpstream()
            return AWCore.getPreventDNSLeak() ? upstream : upstream.reachable
        },
        hosts: DNSHosts.shared,
        fallsBackToSystem: false,
        servesStaleOnFailure: false,
        waitLimit: .seconds(4)
    )

    static let defaultTTL: TimeInterval = 120

    static let maxEntries = 1024

    private struct Query: Hashable, Sendable {
        let name: String
        let family: DNSAddressFamily
    }

    private let upstreamSource: @Sendable () -> DNSUpstream
    private let hosts: DNSHosts?
    private let fallsBackToSystem: Bool
    private let cache: DNSLookupCache<Query, [String]>
    private let blockingBridge = DNSSyscallConcurrencyBridge()
    
    private init(
        upstream: @escaping @Sendable () -> DNSUpstream,
        hosts: DNSHosts?,
        fallsBackToSystem: Bool,
        servesStaleOnFailure: Bool,
        waitLimit: Duration?
    ) {
        self.upstreamSource = upstream
        self.hosts = hosts
        self.fallsBackToSystem = fallsBackToSystem
        self.cache = DNSLookupCache(
            capacity: Self.maxEntries,
            missing: [],
            servesStaleOnFailure: servesStaleOnFailure,
            waitLimit: waitLimit
        )
    }

    // MARK: - Public API

    var usesSystemUpstream: Bool { upstreamSource().isSystem }

    func resolveAll(_ host: String, family: DNSAddressFamily = .preferIPv4, forceFresh: Bool = false) async -> [String] {
        let bare = DNSName.stripBrackets(host)
        if DNSName.isIPAddress(bare) { return family.admits(bare) ? [bare] : [] }
        if let mapped = hosts?.addresses(for: bare, family: family) { return mapped }
        let query = Query(name: DNSName.cacheKey(for: bare), family: family)
        let upstream = upstreamSource()
        return await cache.value(for: query, from: upstream, forceFresh: forceFresh) { [self] in
            await lookup(bare, family: family, upstream: upstream)
        }
    }

    func resolveHost(_ host: String, family: DNSAddressFamily = .preferIPv4, forceFresh: Bool = false) async -> String? {
        await resolveAll(host, family: family, forceFresh: forceFresh).first
    }
    
    func prewarm(_ host: String, family: DNSAddressFamily = .preferIPv4) {
        let bare = DNSName.stripBrackets(host)
        guard !DNSName.isIPAddress(bare), hosts?.addresses(for: bare, family: family) == nil else { return }
        let query = Query(name: DNSName.cacheKey(for: bare), family: family)
        let upstream = upstreamSource()
        cache.warm(query, from: upstream) { [self] in
            await lookup(bare, family: family, upstream: upstream)
        }
    }

    func cachedIPs(for host: String, family: DNSAddressFamily = .preferIPv4) -> [String]? {
        let bare = DNSName.stripBrackets(host)
        if DNSName.isIPAddress(bare) { return family.admits(bare) ? [bare] : nil }
        if let mapped = hosts?.addresses(for: bare, family: family) { return mapped }
        return cache.cachedValue(for: Query(name: DNSName.cacheKey(for: bare), family: family), from: upstreamSource())
    }

    func flush() {
        cache.flush()
    }

    // MARK: - Internal

    private func lookup(
        _ host: String,
        family: DNSAddressFamily,
        upstream: DNSUpstream
    ) async -> (value: [String], ttl: TimeInterval)? {
        var resolved: [String] = []
        if upstream.isSystem {
            guard !DNSUpstream.systemResolverUnavailable else { return nil }
        } else {
            resolved = (try? await DNSUpstreamClient.resolve(host, via: upstream, family: family)) ?? []
            guard resolved.isEmpty, fallsBackToSystem, !DNSUpstream.systemResolverUnavailable else {
                return Self.cacheable(resolved)
            }
        }
        resolved = await blockingBridge.resolveAddresses(host, family: family)
        return Self.cacheable(resolved)
    }

    private static func cacheable(_ addresses: [String]) -> (value: [String], ttl: TimeInterval)? {
        addresses.isEmpty ? nil : (value: addresses, ttl: defaultTTL)
    }
}
