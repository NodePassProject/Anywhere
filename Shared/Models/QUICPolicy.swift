//
//  QUICPolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

/// How app-originated UDP/443 (QUIC / HTTP-3) datagrams are handled. Dropping with
/// an ICMP port-unreachable makes HTTP/3 clients fail fast and fall back to
/// HTTP/2 over TCP, where routing and MITM can act on the connection.
enum QUICPolicy: String, CaseIterable {
    /// Drop every app-originated UDP/443 datagram. A QUIC-based proxy's own
    /// transport (e.g. Hysteria) leaves on a kernel-excluded socket and is unaffected.
    case blocked
    /// Drop UDP/443 only when the flow is proxied or its domain is MITM-listed.
    case automatic
    /// Never drop UDP/443.
    case unblocked

    var title: String {
        switch self {
        case .blocked: return "Blocked"
        case .automatic: return "Automatic"
        case .unblocked: return "Unblocked"
        }
    }

    /// Whether every UDP/443 datagram is dropped before routing resolution; only `.blocked` decides this early.
    var blocksAllQUIC: Bool { self == .blocked }

    /// Whether `.automatic` should drop a UDP/443 flow once routing is known.
    /// `mitmListed` is an `@autoclosure` so the MITM-trie lookup runs only when it can change the answer.
    func blocksResolvedQUIC(isProxied: Bool, mitmListed: @autoclosure () -> Bool) -> Bool {
        guard self == .automatic else { return false }
        return isProxied || mitmListed()
    }
}
