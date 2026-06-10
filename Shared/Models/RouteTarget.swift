//
//  RouteTarget.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// Stable identity of where a connection was routed, shared by routing, accounting,
/// stats, and the request log. The `.proxy` id is the app's authoritative configuration
/// or chain id — never the dialing `ProxyConfiguration` id, which gets regenerated.
enum RouteTarget: Hashable, Sendable {
    case direct
    case reject
    /// Proxied through the configuration or chain with this app id.
    case proxy(UUID)

    var configurationID: UUID? {
        if case .proxy(let id) = self { return id }
        return nil
    }
}

// MARK: - Codable (compact string form)

extension RouteTarget: Codable {
    // Encoded as a single compact string — "direct", "reject", or "proxy:<uuid>".
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

    /// Stable string form; also the `Codable` representation.
    var storageKey: String {
        switch self {
        case .direct: return "direct"
        case .reject: return "reject"
        case .proxy(let id): return "proxy:\(id.uuidString)"
        }
    }
}
