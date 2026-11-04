//
//  ConnectionRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 7/12/26.
//

import Foundation
import Synchronization

nonisolated struct RouteDecision {
    enum Action {
        case route(target: RouteTarget, configuration: ProxyConfiguration?, ruleSetName: String?)
        case reject(ruleSetName: String?)
        case unreachable
    }

    let host: String
    let hostIsResolvedDomain: Bool
    let action: Action

    var ipRuleLookupPending = false
}

nonisolated final class ConnectionRouter: Sendable {
    let syntheticAddressPool: SyntheticAddressPool
    let domainRouter: DomainRouter

    let preventDNSLeak = Atomic(false)

    private struct RejectedIPs {
        var v4: Set<UInt32> = []
        var v6: Set<SIMD16<UInt8>> = []
        var count: Int { v4.count + v6.count }
    }
    private let rejectedIPs = Mutex(RejectedIPs())
    private static let rejectedIPCap = 4096

    private let dnsRejectLogged = Mutex(Set<String>())
    private static let dnsRejectLoggedCap = 4096

    init(syntheticAddressPool: SyntheticAddressPool, domainRouter: DomainRouter) {
        self.syntheticAddressPool = syntheticAddressPool
        self.domainRouter = domainRouter
    }

    func decision(forIP ip: String) -> RouteDecision {
        guard SyntheticAddressPool.isSyntheticAddress(ip) else {
            guard let match = domainRouter.matchIP(ip) else {
                return RouteDecision(host: ip, hostIsResolvedDomain: false, action: .route(target: .default, configuration: nil, ruleSetName: nil))
            }
            return RouteDecision(
                host: ip,
                hostIsResolvedDomain: false,
                action: markingIfRejectedIP(action(for: match), ip: ip)
            )
        }

        guard let entry = syntheticAddressPool.lookup(ip: ip) else {
            return RouteDecision(host: ip, hostIsResolvedDomain: false, action: .unreachable)
        }
        let domain = entry.domain

        let match: DomainRouter.Match?
        if entry.verdictVersion == domainRouter.currentRulesVersion {
            match = entry.verdict
        } else {
            let versioned = domainRouter.matchDomainVersioned(domain)
            match = versioned.match
            syntheticAddressPool.cacheVerdict(domain: domain, match: match, version: versioned.version)
        }

        if let match {
            return RouteDecision(
                host: domain,
                hostIsResolvedDomain: true,
                action: markingIfRejected(action(for: match), domain: domain)
            )
        }

        if !preventDNSLeak.load(ordering: .relaxed) {
            if let resolvedIP = DNSResolver.localRequests.cachedIPs(for: domain)?.first {
                if let match = domainRouter.matchIP(resolvedIP) {
                    return RouteDecision(
                        host: domain,
                        hostIsResolvedDomain: true,
                        action: action(for: match)
                    )
                }
            } else {
                DNSResolver.localRequests.prewarm(domain)
                return RouteDecision(
                    host: domain,
                    hostIsResolvedDomain: true,
                    action: .route(target: .default, configuration: nil, ruleSetName: nil),
                    ipRuleLookupPending: true
                )
            }
        }

        return RouteDecision(host: domain, hostIsResolvedDomain: true, action: .route(target: .default, configuration: nil, ruleSetName: nil))
    }

    private func markingIfRejected(
        _ action: RouteDecision.Action, domain: String
    ) -> RouteDecision.Action {
        if case .reject = action {
            syntheticAddressPool.markRejected(domain: domain)
        }
        return action
    }

    private func markingIfRejectedIP(
        _ action: RouteDecision.Action, ip: String
    ) -> RouteDecision.Action {
        if case .reject = action {
            markIPRejected(ip)
        }
        return action
    }

    private func markIPRejected(_ ip: String) {
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, ip, &v4) == 1 {
            let key = UInt32(bigEndian: v4.s_addr)
            rejectedIPs.withLock { set in
                if set.count >= Self.rejectedIPCap { set = RejectedIPs() }
                set.v4.insert(key)
            }
        } else if inet_pton(AF_INET6, ip, &v6) == 1 {
            let key = withUnsafeBytes(of: v6) { $0.loadUnaligned(as: SIMD16<UInt8>.self) }
            rejectedIPs.withLock { set in
                if set.count >= Self.rejectedIPCap { set = RejectedIPs() }
                set.v6.insert(key)
            }
        }
    }

    // MARK: - DNS-time verdict

    func dnsVerdict(forDomain domain: String) -> (match: DomainRouter.Match?, rulesVersion: UInt64) {
        if let cached = syntheticAddressPool.cachedVerdict(domain: domain),
           cached.version == domainRouter.currentRulesVersion {
            return (cached.match, cached.version)
        }
        let versioned = domainRouter.matchDomainVersioned(domain)
        return (versioned.match, versioned.version)
    }

    func shouldLogDNSReject(domain: String) -> Bool {
        dnsRejectLogged.withLock { set in
            if set.count >= Self.dnsRejectLoggedCap { set.removeAll(keepingCapacity: true) }
            return set.insert(domain).inserted
        }
    }

    // MARK: - Reject-mark intake checks

    func isRejectMarkedDestination(rawIP: UnsafeRawPointer, isIPv6: Bool) -> Bool {
        if isIPv6 {
            let key = rawIP.loadUnaligned(as: SIMD16<UInt8>.self)
            return rejectedIPs.withLock { $0.v6.contains(key) }
        }
        let key = (UInt32(rawIP.load(fromByteOffset: 0, as: UInt8.self)) << 24)
                | (UInt32(rawIP.load(fromByteOffset: 1, as: UInt8.self)) << 16)
                | (UInt32(rawIP.load(fromByteOffset: 2, as: UInt8.self)) << 8)
                |  UInt32(rawIP.load(fromByteOffset: 3, as: UInt8.self))
        return isRejectMarkedIPv4(key)
    }

    private func isRejectMarkedIPv4(_ key: UInt32) -> Bool {
        syntheticAddressPool.isRejectMarked(ipv4: key) || rejectedIPs.withLock { $0.v4.contains(key) }
    }

    func clearRejectMarks() {
        syntheticAddressPool.clearRejectMarks()
        rejectedIPs.withLock { $0 = RejectedIPs() }
        dnsRejectLogged.withLock { $0.removeAll(keepingCapacity: true) }
    }

    // MARK: - Sniffed host

    func action(forSniffedHost host: String) -> RouteDecision.Action? {
        guard let match = domainRouter.matchDomain(host) else { return nil }
        return action(for: match)
    }

    private func action(for match: DomainRouter.Match) -> RouteDecision.Action {
        switch match.action {
        case .default, .defaultProxy:
            return .route(target: match.action, configuration: nil, ruleSetName: match.ruleSetName)
        case .direct:
            return .route(target: .direct, configuration: nil, ruleSetName: match.ruleSetName)
        case .reject:
            return .reject(ruleSetName: match.ruleSetName)
        case .proxy(let id):
            let configuration = domainRouter.resolveConfiguration(action: match.action)
            return .route(target: .proxy(id), configuration: configuration, ruleSetName: match.ruleSetName)
        }
    }
}
