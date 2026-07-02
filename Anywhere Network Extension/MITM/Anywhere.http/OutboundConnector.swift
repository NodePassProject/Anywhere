//
//  OutboundConnector.swift
//  Anywhere
//
//  Created by NodePassProject on 7/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "OutboundConnector")

enum OutboundConnector {

    struct Dialed {
        let connection: ProxyConnection
        /// Retained for the connection's lifetime so the proxy transport stays alive; nil for direct dials.
        let proxyClient: ProxyClient?
    }

    enum ConnectError: Error, LocalizedError {
        case rejected(String)

        var errorDescription: String? {
            switch self {
            case .rejected(let host): return "rejected by routing rule: \(host)"
            }
        }
    }

    // MARK: - Route resolution

    /// Resolves the route and whether it came from the global default (vs. an explicit rule).
    static func resolveRoute(host: String) -> (target: RouteTarget, viaDefault: Bool) {
        guard let stack = TunnelStack.shared else { return (.direct, false) }
        let router = stack.domainRouter

        let matched: RouteTarget? = isIPLiteral(host) ? router.matchIP(host) : router.matchDomain(host)
        if let matched { return (matched, false) }

        // No explicit rule: keep loopback / LAN destinations off any proxy.
        if isLoopbackOrPrivate(host) { return (.direct, false) }
        return (stack.defaultRouteTarget, true)
    }

    // MARK: - Dial

    /// `completion` always runs on `queue`.
    static func dial(
        host: String,
        port: UInt16,
        queue: DispatchQueue,
        completion: @escaping (Result<Dialed, Error>) -> Void
    ) {
        let (route, viaDefault) = resolveRoute(host: host)
        // The only place script `Anywhere.http` fetches reach the Requests log — they're the
        // extension's own outbound, not captured device traffic. A pooled HTTP/2 connection
        // logs once per dial, shared across its streams.
        TunnelStack.shared?.requestLog.record(
            protocolName: "HTTP", host: host, port: port, routeTarget: route, viaDefault: viaDefault
        )
        switch route {
        case .reject:
            queue.async { completion(.failure(ConnectError.rejected(host))) }
        case .direct:
            dialDirect(host: host, port: port, queue: queue, completion: completion)
        case .proxy:
            guard let stack = TunnelStack.shared,
                  let configuration = resolveConfiguration(for: route, stack: stack) else {
                // An unresolvable proxy configuration dials direct rather than failing outright.
                logger.warning("[OutboundConnector] No configuration resolved for \(host); dialing direct")
                dialDirect(host: host, port: port, queue: queue, completion: completion)
                return
            }
            dialProxy(configuration: configuration, host: host, port: port, queue: queue, completion: completion)
        }
    }

    /// The global default route's configuration lives on the stack, not in the router's map.
    private static func resolveConfiguration(for route: RouteTarget, stack: TunnelStack) -> ProxyConfiguration? {
        if let resolved = stack.domainRouter.resolveConfiguration(action: route) { return resolved }
        if route == stack.defaultRouteTarget { return stack.configuration }
        return nil
    }

    private static func dialDirect(
        host: String, port: UInt16,
        queue: DispatchQueue, completion: @escaping (Result<Dialed, Error>) -> Void
    ) {
        let transport = NWTCPTransport()
        // Direct dial — not a proxied connection, so keep it out of the Dial metric.
        transport.dialTimer.enabled = false
        let connection = DirectProxyConnection(connection: transport)
        transport.connect(host: host, port: port) { error in
            queue.async {
                if let error {
                    connection.cancel()
                    completion(.failure(error))
                } else {
                    completion(.success(Dialed(connection: connection, proxyClient: nil)))
                }
            }
        }
    }

    private static func dialProxy(
        configuration: ProxyConfiguration, host: String, port: UInt16,
        queue: DispatchQueue, completion: @escaping (Result<Dialed, Error>) -> Void
    ) {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: TunnelStack.shared?.isDefaultConfiguration(configuration.id) ?? false
        )
        client.connect(to: host, port: port, initialData: nil) { result in
            queue.async {
                switch result {
                case .success(let connection):
                    completion(.success(Dialed(connection: connection, proxyClient: client)))
                case .failure(let error):
                    client.cancel()
                    completion(.failure(error))
                }
            }
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
