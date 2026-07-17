//
//  TunnelStack+DNS.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

extension TunnelStack {

    // MARK: - DNS Interception (Fake-IP)
    //
    // UDP/53 is intercepted only for ``interceptedDNSServers``. The interception
    // itself (A/AAAA fake-IP answers, non-A/AAAA upstream forwarding, NODATA) runs
    // on ``UDPPlane``; this file holds only the static destination table it consults.

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
        TunnelConstants.tunnelAddressIPv4: .anywhereResolver,
        TunnelConstants.tunnelAddressIPv6: .anywhereResolver,
        "8.8.8.8": .publicResolver,
        "8.8.4.4": .publicResolver,
        "2001:4860:4860::8888": .publicResolver,
        "2001:4860:4860::8844": .publicResolver,
    ]

    static func dnsDestination(for dstIP: String) -> DNSDestination? {
        interceptedDNSServers[dstIP]
    }
}
