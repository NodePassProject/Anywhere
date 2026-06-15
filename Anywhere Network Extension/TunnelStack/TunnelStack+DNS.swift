//
//  TunnelStack+DNS.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TunnelStack+DNS")

extension TunnelStack {

    // MARK: - DNS Interception (Fake-IP)
    //
    // UDP/53 is intercepted only for ``interceptedDNSServers``. A/AAAA queries
    // get fake-IP answers so routing is decided at connection time — rule
    // changes take effect without waiting for OS DNS cache expiry.

    /// Classifies a DNS destination IP for interception.
    enum DNSDestination {
        /// Tunnel peer address — no real upstream behind it; non-A/AAAA query
        /// types are forwarded via the proxy.
        case anywhereResolver
        /// A public resolver some apps hardcode; non-A/AAAA query types fall
        /// through and get proxied to the real server.
        case publicResolver
    }

    /// Destinations whose UDP/53 traffic we intercept; any other destination
    /// is proxied as an ordinary UDP flow.
    static let interceptedDNSServers: [String: DNSDestination] = [
        "10.8.0.1": .anywhereResolver,
        "fd00::1": .anywhereResolver,
        "8.8.8.8": .publicResolver,
        "8.8.4.4": .publicResolver,
        "2001:4860:4860::8888": .publicResolver,
        "2001:4860:4860::8844": .publicResolver,
    ]

    /// Returns the interception mode for `dstIP`, or `nil` if not intercepted.
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
        guard let parsed = payload.withUnsafeBytes({ ptr -> (domain: String, qtype: UInt16)? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.parseQuery(UnsafeBufferPointer(start: base, count: ptr.count))
        }) else { return false }

        let domain = parsed.domain.lowercased()
        let qtype = parsed.qtype

        // Block DDR (RFC 9462) when encrypted DNS is off — otherwise the system
        // auto-upgrades to DoH/DoT and bypasses port-53 interception.
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

        // NODATA for SVCB/HTTPS (qtype 65, RFC 9460): proxied answers follow
        // CNAME chains that routing rules (matched on the original domain) may
        // miss; this forces fallback to A/AAAA, which we fake-IP.
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

        // Only A (1) and AAAA (28) get fake IPs. Other types:
        // `.anywhereResolver` forwards upstream (NODATA if no config);
        // `.publicResolver` falls through to a proxied UDP flow.
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

        // Fake-IP even rejected domains — a NODATA here could be negatively
        // cached by the OS; rejects are enforced at connection time instead.
        let offset = fakeIPPool.allocate(domain: domain)

        var fakeIPBytes: [UInt8]?
        if qtype == 1 {
            let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
            fakeIPBytes = [ipv4.0, ipv4.1, ipv4.2, ipv4.3]
        } else if qtype == 28, udpConfig().advertiseIPv6ToApps {
            // Snapshot read — DNS runs on udpQueue, not lwipQueue.
            fakeIPBytes = FakeIPPool.ipv6Bytes(offset: offset)
        }
        // else: AAAA with IPv6 disabled → nil → NODATA response

        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: fakeIPBytes,
                qtype: qtype
            )
        }) else { return false }

        // Reply sourced from the resolver the app queried so the client accepts it.
        writeOutboundUDP(
            srcIP: dstIP, srcPort: dstPort,
            dstIP: srcIP, dstPort: srcPort,
            isIPv6: isIPv6, payload: responseData
        )

        return true
    }

    /// Forwards a non-A/AAAA query to a real upstream resolver through the
    /// default proxy and relays the reply (nothing answers behind the tunnel
    /// peer address). Must be called on ``udpQueue``. Returns `false` when
    /// there is no active configuration; the caller falls back to NODATA.
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
        guard let configuration = udpConfig().configuration else { return false }

        // Forward over IPv4 regardless of query family — proxy egress always
        // reaches it; the reply family follows the flow's `isIPv6`.
        let upstream = TunnelConstants.fallbackDNSServers(includeIPv6: false).first ?? "1.1.1.1"

        let srcHost = TunnelStack.ipAddrToString(srcIP, isIPv6: isIPv6)
        let srcIPData = srcIP
        let dstIPData = dstIP

        // Key on the original 5-tuple so a retransmitted query reuses this flow;
        // intercepted destinations re-enter here, never the fast path.
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
            routeTarget: defaultRouteTarget,   // proxied via the default outbound
            flowQueue: udpQueue
        )
        evictUDPFlowsToAdmit()
        udpFlows[flowKey] = flow
        PerformanceMonitor.gauge(.udpFlowCount, udpFlows.count, highWater: TunnelConstants.udpMaxFlows)
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
