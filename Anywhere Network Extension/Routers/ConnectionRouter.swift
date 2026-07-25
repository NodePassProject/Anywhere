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
    
    var viaDefault: Bool {
        if case .routeViaDefault = action { return true }
        return false
    }
}

nonisolated final class ConnectionRouter: Sendable {
    let fakeIPPool: FakeIPPool
    let domainRouter: DomainRouter
    
    let preventDNSLeak = Atomic(false)

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
                action: action(
                    for: match,
                    host: ip,
                    port: port,
                    ruleKind: "IP",
                    proto: proto
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
                action: action(
                    for: match,
                    host: domain,
                    port: port,
                    ruleKind: "domain",
                    proto: proto
                )
            )
        }
        
        if !preventDNSLeak.load(ordering: .relaxed) {
            if let resolvedIP = RuleResolver.shared.cachedIPv4(for: domain) {
                if let match = domainRouter.matchIP(resolvedIP) {
                    return RouteDecision(
                        host: domain,
                        hostIsResolvedDomain: true,
                        action: action(
                            for: match,
                            host: "\(domain) → \(resolvedIP)",
                            port: port,
                            ruleKind: "IP",
                            proto: proto
                        )
                    )
                }
            } else {
                RuleResolver.shared.warm(domain)
            }
        }

        return RouteDecision(host: domain, hostIsResolvedDomain: true, action: .routeViaDefault)
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
