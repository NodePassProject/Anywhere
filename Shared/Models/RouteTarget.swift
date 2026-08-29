//
//  RouteTarget.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

nonisolated enum RouteTarget: Hashable, Sendable {
    case `default`       // nothing decided: the default route applies because no rule claimed the connection
    case defaultProxy    // a rule claimed the connection and sent it to the default route
    case direct
    case reject
    case proxy(UUID)

    var configurationID: UUID? {
        if case .proxy(let id) = self { return id }
        return nil
    }
    
    func resolved(against defaultTarget: RouteTarget) -> RouteTarget {
        switch self {
        case .default, .defaultProxy: return defaultTarget
        case .direct, .reject, .proxy: return self
        }
    }
}

// MARK: - Codable

nonisolated extension RouteTarget: Codable {
    init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        switch raw {
        case "default": self = .default
        case "default-proxy": self = .defaultProxy
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
    
    var storageKey: String {
        switch self {
        case .default: return "default"
        case .defaultProxy: return "default-proxy"
        case .direct: return "direct"
        case .reject: return "reject"
        case .proxy(let id): return "proxy:\(id.uuidString)"
        }
    }
}
