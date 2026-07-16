//
//  ConnectionRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 7/12/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "ConnectionRouter")

/// A connection-time routing decision, shared by the TCP SYN filter, TCP
/// accept, and UDP flow-creation paths so the three can't drift.
nonisolated struct RouteDecision {
    enum Action {
        /// A rule matched: commit `target`, dialing through `configuration`
        /// when non-nil (nil for `.direct`, or when a proxy rule's
        /// configuration is missing — the caller keeps its default).
        case route(target: RouteTarget, configuration: ProxyConfiguration?, ruleSetName: String?)
        /// No rule matched — the caller's default outbound applies.
        case routeViaDefault
        /// Rejected by a routing rule.
        case reject(ruleSetName: String?)
        /// Fake IP not found in the pool (stale, e.g. from a previous
        /// session). Callers drop the packet; UDP answers port-unreachable.
        case unreachable
    }

    /// The resolved domain when the destination was a fake IP, else the IP literal.
    let host: String
    /// True when ``host`` is a DNS-resolved domain rather than a raw IP.
    let hostIsResolvedDomain: Bool
    let action: Action

    /// True when no rule matched and the caller's default outbound applies.
    var viaDefault: Bool {
        if case .routeViaDefault = action { return true }
        return false
    }
}

/// Resolves a destination IP through the fake-IP pool, domain rules, and
/// IP-CIDR rules — the single routing decision point for the data plane.
/// Callable from ``TunnelStack/lwipQueue`` and ``TunnelStack/udpQueue``: the
/// pool and matcher are internally synchronized, and the Prevent DNS Leak
/// flag is published through a Mutex.
nonisolated final class ConnectionRouter {
    let fakeIPPool: FakeIPPool
    let domainRouter: DomainRouter

    /// Cross-queue copy of the Prevent DNS Leak setting.
    private let _preventDNSLeak = Mutex(false)

    init(fakeIPPool: FakeIPPool, domainRouter: DomainRouter) {
        self.fakeIPPool = fakeIPPool
        self.domainRouter = domainRouter
    }

    /// Publishes the Prevent DNS Leak setting; callable from any queue.
    func setPreventDNSLeak(_ enabled: Bool) {
        _preventDNSLeak.withLock { $0 = enabled }
    }

    /// Routes a destination IP. `proto` tags log lines only ("TCP"/"UDP").
    func decision(forIP ip: String, port: UInt16, proto: String) -> RouteDecision {
        guard FakeIPPool.isFakeIP(ip) else {
            // Raw IP — only IP-CIDR rules can match.
            guard let match = domainRouter.matchIP(ip) else {
                return RouteDecision(host: ip, hostIsResolvedDomain: false, action: .routeViaDefault)
            }
            return RouteDecision(host: ip, hostIsResolvedDomain: false,
                                 action: action(for: match, host: ip, port: port, ruleKind: "IP", proto: proto))
        }

        guard let entry = fakeIPPool.lookup(ip: ip) else {
            logger.debug("[\(proto)] Fake IP not in pool (stale): \(ip):\(port)")
            return RouteDecision(host: ip, hostIsResolvedDomain: false, action: .unreachable)
        }
        let domain = entry.domain

        if let match = domainRouter.matchDomain(domain) {
            return RouteDecision(host: domain, hostIsResolvedDomain: true,
                                 action: action(for: match, host: domain, port: port, ruleKind: "domain", proto: proto))
        }

        // No domain rule matched. Unless Prevent DNS Leak is enabled, resolve
        // the domain locally and give it a second chance against IP-CIDR
        // rules. The resolved IP feeds matching only — the connection still
        // dials the domain.
        if !_preventDNSLeak.withLock({ $0 }) {
            if let resolvedIP = RuleResolver.shared.cachedIPv4(for: domain) {
                if let match = domainRouter.matchIP(resolvedIP) {
                    return RouteDecision(host: domain, hostIsResolvedDomain: true,
                                         action: action(for: match, host: "\(domain) → \(resolvedIP)",
                                                        port: port, ruleKind: "IP", proto: proto))
                }
            } else {
                RuleResolver.shared.warm(domain)
            }
        }

        return RouteDecision(host: domain, hostIsResolvedDomain: true, action: .routeViaDefault)
    }

    /// Maps a rule match to an action, resolving the dial configuration for
    /// proxy targets. `host`/`ruleKind` feed log lines only.
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
                logger.warning("[\(proto)] Routing config not found for \(host)")
            }
            return .route(target: .proxy(id), configuration: configuration, ruleSetName: match.ruleSetName)
        }
    }
}
