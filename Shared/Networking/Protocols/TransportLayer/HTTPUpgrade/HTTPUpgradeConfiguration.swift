//
//  HTTPUpgradeConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

/// HTTP upgrade transport configuration.
struct HTTPUpgradeConfiguration: Codable, Equatable, Hashable {
    /// Host header value (defaults to server address).
    let host: String
    let path: String
    /// Custom HTTP headers to send during the upgrade handshake.
    let headers: [String: String]

    init(
        host: String,
        path: String = "/",
        headers: [String: String] = [:]
    ) {
        self.host = host
        self.path = path
        self.headers = headers
    }

    /// Parse HTTP upgrade parameters from VLESS URL query parameters.
    static func parse(from params: [String: String], serverAddress: String) -> HTTPUpgradeConfiguration? {
        let host = params["host"] ?? serverAddress
        var path = (params["path"] ?? "/").removingPercentEncoding ?? "/"
        if !path.hasPrefix("/") {
            path = "/" + path
        }

        return HTTPUpgradeConfiguration(
            host: host,
            path: path
        )
    }
}

enum HTTPUpgradeError: Error, LocalizedError {
    case upgradeFailed(String)

    var errorDescription: String? {
        switch self {
        case .upgradeFailed(let reason):
            return "HTTP upgrade failed: \(reason)"
        }
    }
}
