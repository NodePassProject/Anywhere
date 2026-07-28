//
//  OutboundConnector.swift
//  Anywhere
//
//  Created by NodePassProject on 7/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "OutboundConnector")

nonisolated enum OutboundConnector {

    struct Dialed {
        let connection: ProxyConnection
        /// Retained for the connection's lifetime so the proxy transport stays alive; nil for direct dials.
        let proxyClient: ProxyClient?
    }

    // MARK: - Ambient Routing Context
    
    struct RoutingContext {
        let domainRouter: DomainRouter
        let requestLog: RequestLog
        let defaultRouteTarget: RouteTarget
        let defaultConfiguration: ProxyConfiguration?
        let preventDNSLeak: Bool

        func isDefaultConfiguration(_ id: UUID) -> Bool {
            defaultConfiguration?.id == id
        }
    }

    private static let context = Mutex<RoutingContext?>(nil)
    
    static func setRoutingContext(_ context: RoutingContext?) {
        Self.context.withLock { $0 = context }
    }

    private static func routingContext() -> RoutingContext? {
        context.withLock { $0 }
    }

    // MARK: - Route resolution
    
    static func resolveRoute(host: String) async -> (target: RouteTarget, viaDefault: Bool, ruleSetName: String?) {
        guard let context = routingContext() else { return (.direct, false, nil) }
        let router = context.domainRouter

        let literal = isIPLiteral(host)
        let matched = literal ? router.matchIP(host) : router.matchDomain(host)
        if let matched { return (matched.action, false, matched.ruleSetName) }
        
        if isLoopbackOrPrivate(host) { return (.direct, false, nil) }
        
        if !literal, !context.preventDNSLeak,
           let ip = await RuleResolver.shared.resolveIPv4(for: host),
           let ruleMatch = router.matchIP(ip) {
            return (ruleMatch.action, false, ruleMatch.ruleSetName)
        }

        return (context.defaultRouteTarget, true, nil)
    }

    // MARK: - Dial
    
    static func dial(host: String, port: UInt16) async throws -> Dialed {
        let (route, viaDefault, ruleSetName) = await resolveRoute(host: host)
        routingContext()?.requestLog.record(
            protocol: .unknown,
            host: host,
            port: port,
            routeTarget: route,
            viaDefault: viaDefault,
            ruleSetName: ruleSetName
        )
        switch route {
        case .reject:
            throw AnywhereError.routing(.rejectedByRule(host: host))
        case .direct:
            return try await dialDirect(host: host, port: port)
        case .proxy:
            guard let context = routingContext(),
                  let configuration = resolveConfiguration(for: route, context: context) else {
                // An unresolvable proxy configuration dials direct rather than failing outright.
                logger.warning("[OutboundConnector] No configuration resolved for \(host); dialing direct")
                return try await dialDirect(host: host, port: port)
            }
            return try await dialProxy(configuration: configuration, host: host, port: port)
        }
    }
    
    private static func resolveConfiguration(for route: RouteTarget, context: RoutingContext) -> ProxyConfiguration? {
        if let resolved = context.domainRouter.resolveConfiguration(action: route) { return resolved }
        if route == context.defaultRouteTarget { return context.defaultConfiguration }
        return nil
    }

    private static func dialDirect(host: String, port: UInt16) async throws -> Dialed {
        let transport = TCPTransport(host: host, port: port)
        let connection = DirectProxyConnection(transport: transport)
        do {
            try await transport.connect()
        } catch {
            connection.cancel()
            throw error
        }
        return Dialed(connection: connection, proxyClient: nil)
    }

    private static func dialProxy(
        configuration: ProxyConfiguration, host: String, port: UInt16
    ) async throws -> Dialed {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: routingContext()?.isDefaultConfiguration(configuration.id) ?? false
        )
        do {
            let connection = try await client.connect(to: host, port: port, initialData: nil)
            return Dialed(connection: connection, proxyClient: client)
        } catch {
            await client.cancel()
            throw error
        }
    }

    // MARK: - Address classification

    static func isIPLiteral(_ host: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 { return true }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 { return true }
        return false
    }

    static func isLoopbackOrPrivate(_ host: String) -> Bool {
        if host.caseInsensitiveCompare("localhost") == .orderedSame { return true }

        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            let ip = UInt32(bigEndian: v4.s_addr)
            if ip & 0xFF00_0000 == 0x7F00_0000 { return true } // 127.0.0.0/8 loopback
            if ip & 0xFF00_0000 == 0x0A00_0000 { return true } // 10.0.0.0/8
            if ip & 0xFFF0_0000 == 0xAC10_0000 { return true } // 172.16.0.0/12
            if ip & 0xFFFF_0000 == 0xC0A8_0000 { return true } // 192.168.0.0/16
            if ip & 0xFFFF_0000 == 0xA9FE_0000 { return true } // 169.254.0.0/16 link-local
            return false
        }

        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { raw -> Bool in
                var isLoopback = raw[15] == 1
                if isLoopback {
                    for i in 0..<15 where raw[i] != 0 { isLoopback = false; break }
                }
                if isLoopback { return true }
                if raw[0] == 0xFE && (raw[1] & 0xC0) == 0x80 { return true } // fe80::/10 link-local
                if (raw[0] & 0xFE) == 0xFC { return true }                  // fc00::/7 unique local
                return false
            }
        }
        return false
    }
}
