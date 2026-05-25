//
//  QUICPolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

/// How app-originated UDP/443 (QUIC / HTTP-3) datagrams are handled. Dropping
/// a datagram with an ICMP port-unreachable makes HTTP/3 clients fail fast on
/// the first packet and fall back to HTTP/2 over TCP, where routing and MITM
/// can act on the connection.
///
/// This owns the decision the way ``DomainRouter`` owns routing: the UDP path
/// computes the routing result, then asks a ``QUICPolicy`` value what to do.
enum QUICPolicy: String, CaseIterable {
    /// Drop every app-originated UDP/443 datagram. A QUIC-based proxy's own
    /// transport to its server (e.g. Hysteria) is unaffected — it leaves the
    /// extension on a kernel-excluded socket and never traverses the tunnel.
    case blocked
    /// Drop UDP/443 only when the flow is routed through a proxy or its domain
    /// is MITM-listed; leave direct, non-intercepted QUIC alone.
    case automatic
    /// Never drop UDP/443.
    case unblocked

    /// User-facing label.
    var title: String {
        switch self {
        case .blocked: return "Blocked"
        case .automatic: return "Automatic"
        case .unblocked: return "Unblocked"
        }
    }

    /// Whether every UDP/443 datagram is dropped before routing resolution.
    /// Only ``blocked`` decides this early; ``automatic`` needs the routing
    /// result (see ``blocksResolvedQUIC(isProxied:mitmListed:)``) and
    /// ``unblocked`` never drops.
    var blocksAllQUIC: Bool { self == .blocked }

    /// Whether ``automatic`` should drop a UDP/443 flow once routing is known.
    /// Proxied flows and MITM-listed domains are dropped so they fall back to
    /// TCP; direct, non-MITM traffic keeps QUIC. Always `false` for the other
    /// modes, which decide before routing.
    ///
    /// ``mitmListed`` is an `@autoclosure` so the MITM-trie lookup behind it
    /// runs only when it can change the answer: ``automatic`` mode with a flow
    /// that isn't already dropped for being proxied. In the other modes, or
    /// when ``isProxied`` already forces the drop, it is never evaluated.
    func blocksResolvedQUIC(isProxied: Bool, mitmListed: @autoclosure () -> Bool) -> Bool {
        guard self == .automatic else { return false }
        return isProxied || mitmListed()
    }
}
