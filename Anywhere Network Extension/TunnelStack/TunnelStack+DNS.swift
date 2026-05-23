//
//  TunnelStack+DNS.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LWIP-DNS")

extension TunnelStack {

    // MARK: - DNS Interception (Fake-IP)
    //
    // DNS queries on UDP/53 are intercepted only when the destination IP is on
    // ``interceptedDNSServers`` — every other resolver (NextDNS, AdGuard, Quad9,
    // user-chosen public DNS) is treated as ordinary UDP and proxied to its real
    // server. Two destinations qualify:
    //
    // - ``DNSDestination/anywhereResolver`` — `10.8.0.1` / `fd00::1`, the
    //   tunnel peer addresses configured in
    //   ``PacketTunnelProvider/buildTunnelSettings``. This is where the system
    //   resolver sends plain DNS. Nothing lives behind these IPs, so A/AAAA are
    //   answered locally with fake IPs, while other query types (SRV/MX/TXT/…)
    //   are forwarded to a real upstream resolver through the proxy — see
    //   ``forwardToUpstreamResolver`` — instead of being answered NODATA.
    //
    // - ``DNSDestination/publicResolver`` — Google Public DNS (`8.8.8.8`,
    //   `8.8.4.4`, and IPv6 equivalents). Several Google products hardcode
    //   these and ignore the system DNS configuration, so we fake-IP A/AAAA
    //   to keep routing working. Other query types (MX/SRV/TXT) are allowed
    //   to fall through and get proxied to the real Google resolver.
    //
    // Two additional behaviours run for any intercepted destination:
    //
    // 1. DDR blocking: When encrypted DNS is disabled, queries for
    //    "_dns.resolver.arpa" (RFC 9462) get a NODATA response. This stops
    //    the system from discovering that the resolver supports DoH/DoT and
    //    auto-upgrading, which would bypass our port-53 interception.
    //
    // 2. Fake-IP for ALL A/AAAA queries: Every domain gets a synthetic fake
    //    IP response. When TCP/UDP connections later arrive at the fake IP we
    //    look up the original domain and make routing decisions
    //    (direct/proxy) at connection time by checking DomainRouter. This
    //    ensures routing rule changes take effect immediately without
    //    waiting for OS DNS cache expiry.

    /// Classifies a DNS destination IP for interception.
    enum DNSDestination {
        /// Anywhere resolver (tunnel peer address). No real upstream behind it:
        /// A/AAAA are answered locally with fake IPs; other query types are
        /// forwarded to a real resolver through the proxy.
        case anywhereResolver
        /// A public resolver an app pointed at directly (e.g., Google Public
        /// DNS). Fake-IP A/AAAA; let other query types pass through to be
        /// proxied to the real server.
        case publicResolver
    }

    /// Destinations whose UDP/53 traffic we intercept. Any other destination
    /// is left alone and proxied as an ordinary UDP flow.
    static let interceptedDNSServers: [String: DNSDestination] = [
        "10.8.0.1": .anywhereResolver,
        "fd00::1": .anywhereResolver,
        "8.8.8.8": .publicResolver,
        "8.8.4.4": .publicResolver,
        "2001:4860:4860::8888": .publicResolver,
        "2001:4860:4860::8844": .publicResolver,
    ]

    /// Returns the interception mode for `dstIP`, or `nil` if the destination
    /// is not on the intercept list.
    static func dnsDestination(for dstIP: String) -> DNSDestination? {
        interceptedDNSServers[dstIP]
    }

    /// Intercepts a DNS query. Returns true if handled (no UDP flow needed).
    func handleDNSQuery(
        payload: Data,
        srcIP: Data,
        srcPort: UInt16,
        dstIP: Data,
        dstPort: UInt16,
        isIPv6: Bool,
        destination: DNSDestination
    ) -> Bool {
        // Parse domain + QTYPE
        guard let parsed = payload.withUnsafeBytes({ ptr -> (domain: String, qtype: UInt16)? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.parseQuery(UnsafeBufferPointer(start: base, count: ptr.count))
        }) else { return false }

        let domain = parsed.domain.lowercased()
        let qtype = parsed.qtype

        // Block DDR (Discovery of Designated Resolvers, RFC 9462) when encrypted DNS is
        // disabled to prevent the system from auto-upgrading to DoH/DoT, which bypasses
        // port-53 interception needed for fake-IP domain routing.
        if !encryptedDNSEnabled, domain == "_dns.resolver.arpa" {
            return sendNODATA(
                payload: payload,
                srcIP: srcIP,
                srcPort: srcPort,
                dstIP: dstIP,
                dstPort: dstPort,
                isIPv6: isIPv6,
                qtype: qtype
            )
        }

        // Block SVCB/HTTPS (qtype=65, RFC 9460) queries with NODATA.
        // When proxied to real DNS, these queries follow CNAME chains
        // (e.g. example.com → example.com.cdn.net), causing the browser to
        // connect using the CNAME target domain instead of the original.
        // Since routing/bypass rules match on the original domain, the CNAME
        // target may not match, sending traffic through the wrong proxy path.
        // Returning NODATA forces the browser to fall back to A/AAAA records,
        // which are intercepted by our fake-IP system with correct routing.
        if qtype == 65 {
            return sendNODATA(
                payload: payload,
                srcIP: srcIP,
                srcPort: srcPort,
                dstIP: dstIP,
                dstPort: dstPort,
                isIPv6: isIPv6,
                qtype: qtype
            )
        }

        // Only fake-IP A (1) and AAAA (28) queries.
        // Other query types (MX/SRV/TXT/...):
        //   - `.anywhereResolver`: nothing lives behind the tunnel peer
        //     address, so the query can't fall through to a UDP flow aimed at
        //     it. Forward it to a real upstream resolver and relay the reply,
        //     dropping back to NODATA only when there's no configuration to
        //     forward through.
        //   - `.publicResolver`: return false so the caller falls through to
        //     a normal UDP flow, which proxies the query to the real server.
        guard qtype == 1 || qtype == 28 else {
            if destination == .anywhereResolver {
                if forwardToUpstreamResolver(
                    domain: domain,
                    payload: payload,
                    srcIP: srcIP,
                    srcPort: srcPort,
                    dstIP: dstIP,
                    dstPort: dstPort,
                    isIPv6: isIPv6,
                    qtype: qtype
                ) {
                    return true
                }
                return sendNODATA(
                    payload: payload,
                    srcIP: srcIP,
                    srcPort: srcPort,
                    dstIP: dstIP,
                    dstPort: dstPort,
                    isIPv6: isIPv6,
                    qtype: qtype
                )
            }
            return false
        }

        // Intercept ALL A/AAAA queries with fake IPs — including rejected domains.
        // Routing decisions (direct/reject/proxy) are all made at connection time
        // by checking domainRouter in resolveFakeIP(). This avoids NODATA responses
        // that could be negatively cached by the OS, making rule changes stick even
        // after the user removes a REJECT assignment.
        let offset = fakeIPPool.allocate(domain: domain)

        // Build fake IP bytes for the response
        var fakeIPBytes: [UInt8]?
        if qtype == 1 {
            // A query → fake IPv4
            let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
            fakeIPBytes = [ipv4.0, ipv4.1, ipv4.2, ipv4.3]
        } else if qtype == 28, advertiseIPv6ToApps {
            // AAAA query + IPv6 enabled → fake IPv6
            fakeIPBytes = FakeIPPool.ipv6Bytes(offset: offset)
        }
        // else: AAAA query + IPv6 disabled → fakeIPBytes stays nil → NODATA response

        // Generate DNS response
        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: fakeIPBytes,
                qtype: qtype
            )
        }) else { return false }

        // Response source = original destination (the resolver the app queried),
        // destination = original source (the app), so the client accepts it.
        writeOutboundUDP(
            srcIP: dstIP, srcPort: dstPort,
            dstIP: srcIP, dstPort: srcPort,
            isIPv6: isIPv6, payload: responseData
        )

        return true
    }

    /// Forwards a query the Anywhere resolver can't answer locally — anything
    /// but A/AAAA (SRV, MX, TXT, …) — to a real upstream resolver and relays
    /// the reply back to the client.
    ///
    /// The Anywhere resolver addresses (`10.8.0.1` / `fd00::1`) are the tunnel
    /// peer: there is no DNS server behind them, so — unlike the
    /// ``DNSDestination/publicResolver`` case — the query can't simply fall
    /// through to a UDP flow aimed at the destination IP; that flow would go
    /// nowhere. Instead we send it out through the default proxy configuration,
    /// mirroring how the public-resolver path proxies SRV/MX/TXT to the real
    /// server. That keeps the lookup off the local network and consistent with
    /// how the answer's targets — resolved later via A/AAAA and fake-IP'd —
    /// will be routed. The flow's reply is sourced from the original
    /// destination, so the client's resolver accepts it as coming from the
    /// server it queried.
    ///
    /// Must be called on ``lwipQueue`` (mutates ``udpFlows``).
    ///
    /// - Returns: `true` once a forwarding flow is started; `false` when there
    ///   is no active configuration to forward through, so the caller can fall
    ///   back to NODATA.
    private func forwardToUpstreamResolver(
        domain: String,
        payload: Data,
        srcIP: Data,
        srcPort: UInt16,
        dstIP: Data,
        dstPort: UInt16,
        isIPv6: Bool,
        qtype: UInt16
    ) -> Bool {
        guard let configuration = self.configuration else { return false }

        // Forward over IPv4: proxy egress reaches it regardless of the client's
        // query family, and the reply family is governed by the flow's
        // `isIPv6`. The IPv6 entries in the list serve the encrypted-DNS
        // fallback consumer, which hands the whole list to the OS resolver.
        let upstream = TunnelConstants.fallbackDNSServers(includeIPv6: false).first ?? "1.1.1.1"

        let srcHost = TunnelStack.ipAddrToString(srcIP, isIPv6: isIPv6)
        let srcIPData = srcIP
        let dstIPData = dstIP

        // Key on the original 5-tuple (destined for the Anywhere resolver) so a
        // retransmitted query from the same socket reuses this flow instead of
        // opening a second proxy association. Every datagram to the resolver
        // re-enters handleDNSQuery, so reuse has to happen here — the callback's
        // fast path is never reached for intercepted destinations. Built from the
        // raw address bytes to match the inline key the fast path constructs.
        let flowKey = UDPFlowKey(srcIP: UDPPacket.loadIP(srcIP), srcPort: srcPort,
                                 dstIP: UDPPacket.loadIP(dstIP), dstPort: dstPort, isIPv6: isIPv6)
        if let existing = udpFlows[flowKey] {
            existing.handleReceivedData(payload, payloadLength: payload.count)
            return true
        }

        let flow = UDPFlow(
            flowKey: flowKey,
            srcHost: srcHost,
            srcPort: srcPort,
            dstHost: upstream,        // outbound → real upstream resolver
            dstPort: dstPort,
            srcIPData: srcIPData,
            dstIPData: dstIPData,     // reply source → the Anywhere resolver address
            isIPv6: isIPv6,
            configuration: configuration,
            forceBypass: false,       // proxy it, mirroring the public-resolver path
            lwipQueue: lwipQueue
        )
        udpFlows[flowKey] = flow
        logger.debug("[DNS] Forwarding qtype \(qtype) for \(domain) → \(upstream):\(dstPort) via \(configuration.name)")
        flow.handleReceivedData(payload, payloadLength: payload.count)
        return true
    }

    /// Sends a NODATA DNS response (ANCOUNT=0) for the given query.
    private func sendNODATA(
        payload: Data,
        srcIP: Data,
        srcPort: UInt16,
        dstIP: Data,
        dstPort: UInt16,
        isIPv6: Bool,
        qtype: UInt16
    ) -> Bool {
        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: nil,
                qtype: qtype
            )
        }) else { return false }

        // Response sourced from the resolver the app queried (original dst).
        writeOutboundUDP(
            srcIP: dstIP, srcPort: dstPort,
            dstIP: srcIP, dstPort: srcPort,
            isIPv6: isIPv6, payload: responseData
        )

        return true
    }
}
