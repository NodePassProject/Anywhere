//
//  LWIPStack+DNS.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

extension LWIPStack {

    // MARK: - DNS Interception (Fake-IP)
    //
    // DNS queries on UDP/53 are intercepted only when the destination IP is on
    // ``interceptedDNSServers`` — every other resolver (NextDNS, AdGuard, Quad9,
    // user-chosen public DNS) is treated as ordinary UDP and proxied to its real
    // server. Two destinations qualify:
    //
    // - ``DNSDestination/ours`` — `10.8.0.1` / `fd00::1`, the tunnel peer
    //   addresses configured in ``PacketTunnelProvider/buildTunnelSettings``.
    //   This is where the system resolver sends plain DNS. There is no real
    //   upstream behind these IPs, so every query must be answered locally
    //   (A/AAAA with fake IP; everything else with NODATA).
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
        /// Anywhere resolver (tunnel peer address). No real upstream, so every
        /// query must be answered locally.
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
        srcIP: UnsafeRawPointer,
        srcPort: UInt16,
        dstIP: UnsafeRawPointer,
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
        //   - `.anywhereResolver`: no upstream exists behind the tunnel peer
        //     address, so we must answer locally. NODATA is the safest reply.
        //   - `.publicResolver`: return false so the caller falls through to
        //     a normal UDP flow, which proxies the query to the real server.
        guard qtype == 1 || qtype == 28 else {
            if destination == .anywhereResolver {
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
        } else if qtype == 28, ipv6DNSEnabled {
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

        responseData.withUnsafeBytes { dataPtr in
            guard let dataBase = dataPtr.baseAddress else { return }
            lwip_bridge_udp_sendto(
                dstIP,
                dstPort,
                srcIP,
                srcPort,
                isIPv6 ? 1 : 0,
                dataBase,
                Int32(responseData.count)
            )
        }

        return true
    }

    /// Sends a NODATA DNS response (ANCOUNT=0) for the given query.
    private func sendNODATA(
        payload: Data,
        srcIP: UnsafeRawPointer,
        srcPort: UInt16,
        dstIP: UnsafeRawPointer,
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

        responseData.withUnsafeBytes { dataPtr in
            guard let dataBase = dataPtr.baseAddress else { return }
            lwip_bridge_udp_sendto(
                dstIP,
                dstPort,
                srcIP,
                srcPort,
                isIPv6 ? 1 : 0,
                dataBase,
                Int32(responseData.count)
            )
        }

        return true
    }
}
