//
//  QUICPolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

/// Dropping UDP/443 with ICMP port-unreachable makes HTTP/3 clients fail fast and fall
/// back to HTTP/2 over TCP, where routing and MITM can act on the connection.
enum QUICPolicy: String, CaseIterable {
    /// A QUIC-based proxy's own transport (e.g. Hysteria) leaves on a kernel-excluded socket and is unaffected.
    case blocked
    case automatic
    case unblocked

    var title: String {
        switch self {
        case .blocked: return String(localized: "Blocked")
        case .automatic: return String(localized: "Automatic")
        case .unblocked: return String(localized: "Unblocked")
        }
    }

    /// Decided before routing resolution; only `.blocked` drops this early.
    var blocksAllQUIC: Bool { self == .blocked }

    /// `mitmListed` is an `@autoclosure` so the MITM-trie lookup runs only when it can change the answer.
    func blocksResolvedQUIC(isProxied: Bool, mitmListed: @autoclosure () -> Bool) -> Bool {
        guard self == .automatic else { return false }
        return isProxied || mitmListed()
    }
}
