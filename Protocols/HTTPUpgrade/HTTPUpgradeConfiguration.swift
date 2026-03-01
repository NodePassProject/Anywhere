//
//  HTTPUpgradeConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// HTTP upgrade transport configuration.
///
/// Matches Xray-core's `httpupgrade.Config` protobuf definition.
struct HTTPUpgradeConfiguration: Codable, Equatable, Hashable {
    /// Host header value (defaults to server address).
    let host: String
    /// HTTP request path (default "/").
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
    ///
    /// Expected parameters: `type=httpupgrade&host=example.com&path=/upgrade`
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

/// HTTP upgrade transport errors.
enum HTTPUpgradeError: Error, LocalizedError {
    case upgradeFailed(String)

    var errorDescription: String? {
        switch self {
        case .upgradeFailed(let reason):
            return "HTTP upgrade failed: \(reason)"
        }
    }
}
