//
//  ConnectionRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 7/12/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "ConnectionRouter")

nonisolated struct RouteDecision {
    enum Action {
        case route(target: RouteTarget, configuration: ProxyConfiguration?, ruleSetName: String?)
        case routeViaDefault
        case reject(ruleSetName: String?)
        case unreachable
    }
    
    let host: String
    let hostIsResolvedDomain: Bool
    let action: Action
    
    var ipRuleLookupPending = false

    var viaDefault: Bool {
        if case .routeViaDefault = action { return true }
        return false
    }
}

nonisolated final class ConnectionRouter: Sendable {
    let fakeIPPool: FakeIPPool
    let domainRouter: DomainRouter

    let preventDNSLeak = Atomic(false)
    
    private struct RejectedIPs {
        var v4: Set<UInt32> = []
        var v6: Set<SIMD16<UInt8>> = []
        var count: Int { v4.count + v6.count }
    }
    private let rejectedIPs = Mutex(RejectedIPs())
    private static let rejectedIPCap = 4096

    init(fakeIPPool: FakeIPPool, domainRouter: DomainRouter) {
        self.fakeIPPool = fakeIPPool
        self.domainRouter = domainRouter
    }
    
    func decision(forIP ip: String, port: UInt16, proto: String) -> RouteDecision {
        guard FakeIPPool.isFakeIP(ip) else {
            guard let match = domainRouter.matchIP(ip) else {
                return RouteDecision(host: ip, hostIsResolvedDomain: false, action: .routeViaDefault)
            }
            return RouteDecision(
                host: ip,
                hostIsResolvedDomain: false,
                action: markingIfRejectedIP(
                    action(
                        for: match,
                        host: ip,
                        port: port,
                        ruleKind: "IP",
                        proto: proto
                    ),
                    ip: ip
                )
            )
        }

        guard let entry = fakeIPPool.lookup(ip: ip) else {
            logger.debug("[\(proto)] Fake IP not in pool (stale): \(ip):\(port)")
            return RouteDecision(host: ip, hostIsResolvedDomain: false, action: .unreachable)
        }
        let domain = entry.domain

        if let match = domainRouter.matchDomain(domain) {
            return RouteDecision(
                host: domain,
                hostIsResolvedDomain: true,
                action: markingIfRejected(
                    action(
                        for: match,
                        host: domain,
                        port: port,
                        ruleKind: "domain",
                        proto: proto
                    ),
                    domain: domain
                )
            )
        }

        if !preventDNSLeak.load(ordering: .relaxed) {
            if let resolvedIP = RuleResolver.shared.cachedIPv4(for: domain) {
                if let match = domainRouter.matchIP(resolvedIP) {
                    return RouteDecision(
                        host: domain,
                        hostIsResolvedDomain: true,
                        action: markingIfRejected(
                            action(
                                for: match,
                                host: "\(domain) → \(resolvedIP)",
                                port: port,
                                ruleKind: "IP",
                                proto: proto
                            ),
                            domain: domain
                        )
                    )
                }
            } else {
                RuleResolver.shared.warm(domain)
                return RouteDecision(
                    host: domain,
                    hostIsResolvedDomain: true,
                    action: .routeViaDefault,
                    ipRuleLookupPending: true
                )
            }
        }

        return RouteDecision(host: domain, hostIsResolvedDomain: true, action: .routeViaDefault)
    }
    
    private func markingIfRejected(
        _ action: RouteDecision.Action, domain: String
    ) -> RouteDecision.Action {
        if case .reject = action {
            fakeIPPool.markRejected(domain: domain)
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
        let inserted: Bool
        if inet_pton(AF_INET, ip, &v4) == 1 {
            let key = UInt32(bigEndian: v4.s_addr)
            inserted = rejectedIPs.withLock { set in
                if set.count >= Self.rejectedIPCap { set = RejectedIPs() }
                return set.v4.insert(key).inserted
            }
        } else if inet_pton(AF_INET6, ip, &v6) == 1 {
            let key = withUnsafeBytes(of: v6) { $0.loadUnaligned(as: SIMD16<UInt8>.self) }
            inserted = rejectedIPs.withLock { set in
                if set.count >= Self.rejectedIPCap { set = RejectedIPs() }
                return set.v6.insert(key).inserted
            }
        } else {
            inserted = false
        }
        if inserted {
            logger.debug("[ConnectionRouter] Reject-marked IP \(ip)")
        }
    }

    // MARK: - Reject-mark intake checks
    
    func isRejectMarkedDestination(rawIP: UnsafeRawPointer, isIPv6: Bool) -> Bool {
        if fakeIPPool.isRejectMarked(rawIP: rawIP, isIPv6: isIPv6) { return true }
        if isIPv6 {
            let key = rawIP.loadUnaligned(as: SIMD16<UInt8>.self)
            return rejectedIPs.withLock { $0.v6.contains(key) }
        }
        let key = (UInt32(rawIP.load(fromByteOffset: 0, as: UInt8.self)) << 24)
                | (UInt32(rawIP.load(fromByteOffset: 1, as: UInt8.self)) << 16)
                | (UInt32(rawIP.load(fromByteOffset: 2, as: UInt8.self)) << 8)
                |  UInt32(rawIP.load(fromByteOffset: 3, as: UInt8.self))
        return rejectedIPs.withLock { $0.v4.contains(key) }
    }
    
    func isRejectMarkedDestination(ipBytes: SIMD16<UInt8>, isIPv6: Bool) -> Bool {
        if fakeIPPool.isRejectMarked(ipBytes: ipBytes, isIPv6: isIPv6) { return true }
        if isIPv6 {
            return rejectedIPs.withLock { $0.v6.contains(ipBytes) }
        }
        let key = (UInt32(ipBytes[0]) << 24) | (UInt32(ipBytes[1]) << 16)
                | (UInt32(ipBytes[2]) << 8) | UInt32(ipBytes[3])
        return rejectedIPs.withLock { $0.v4.contains(key) }
    }
    
    func clearRejectMarks() {
        fakeIPPool.clearRejectMarks()
        rejectedIPs.withLock { $0 = RejectedIPs() }
    }

    private func action(for match: DomainRouter.Match, host: String, port: UInt16,
                        ruleKind: String, proto: String) -> RouteDecision.Action {
        switch match.action {
        case .direct:
            return .route(target: .direct, configuration: nil, ruleSetName: match.ruleSetName)
        case .reject:
            logger.debug("[\(proto)] Rejected by \(ruleKind) rule: \(host):\(port)")
            return .reject(ruleSetName: match.ruleSetName)
        case .proxy(let id):
            let configuration = domainRouter.resolveConfiguration(action: match.action)
            if configuration == nil {
                logger.report("[\(proto)]", error: AnywhereError.routing(.configurationMissing(host: host)))
            }
            return .route(target: .proxy(id), configuration: configuration, ruleSetName: match.ruleSetName)
        }
    }
}
