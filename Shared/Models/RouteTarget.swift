//
//  RouteTarget.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// Stable identity of *where* a connection was routed.
///
/// This is the single source of truth for routing identity across the whole
/// stack — the routing decision, per-connection accounting, traffic stats, and
/// the request log all speak `RouteTarget`. Crucially, the proxy id is the
/// app's **authoritative** id (a `ConfigurationStore` configuration id or a
/// `ChainStore` chain id), assigned at routing-decision time and carried
/// unchanged everywhere. It is never derived from the dialing
/// ``ProxyConfiguration/id``, which gets regenerated when a chain is composited
/// or a routing rule is parsed — so display-name resolution is total and stable.
///
/// Proxies and chains share the `.proxy` case: from a routing/identity point of
/// view a chain is just another configured outbound node, and the app resolves
/// the name from whichever store owns the id (see `RouteTarget.displayName`,
/// which lives app-side since the extension ships ids only).
enum RouteTarget: Hashable, Sendable {
    /// Bypassed / direct — dialed straight out.
    case direct
    /// Rejected — connection refused; carries no payload.
    case reject
    /// Proxied through the node with this app id (a standalone/subscription
    /// configuration, or a chain).
    case proxy(UUID)

    /// The configuration/chain id to dial through, or `nil` for direct/reject.
    var configurationID: UUID? {
        if case .proxy(let id) = self { return id }
        return nil
    }
}

// MARK: - Codable (compact string form)

extension RouteTarget: Codable {
    // Encodes as a single compact string — "direct", "reject", or
    // "proxy:<uuid>" — so it stays small over IPC and human-readable in JSON,
    // rather than the verbose nested form Swift synthesizes for enums with
    // associated values.
    init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        switch raw {
        case "direct": self = .direct
        case "reject": self = .reject
        default:
            guard raw.hasPrefix("proxy:"),
                  let id = UUID(uuidString: String(raw.dropFirst("proxy:".count))) else {
                throw DecodingError.dataCorrupted(.init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Unrecognized RouteTarget: \(raw)"
                ))
            }
            self = .proxy(id)
        }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storageKey)
    }

    /// Stable string form — used as the `Codable` representation and as a
    /// dictionary / `Identifiable` key in the UI.
    var storageKey: String {
        switch self {
        case .direct: return "direct"
        case .reject: return "reject"
        case .proxy(let id): return "proxy:\(id.uuidString)"
        }
    }
}
