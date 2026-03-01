//
//  WebSocketConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// WebSocket transport configuration.
struct WebSocketConfiguration: Codable, Equatable, Hashable {
    /// Host header value (defaults to server address).
    let host: String
    /// WebSocket path (default "/").
    let path: String
    /// Custom HTTP headers to send during the upgrade handshake.
    let headers: [String: String]
    /// Maximum early data bytes to embed in the upgrade request (0 = disabled).
    let maxEarlyData: Int
    /// Header name used to carry early data (default "Sec-WebSocket-Protocol").
    let earlyDataHeaderName: String
    /// Heartbeat (ping) interval in seconds. 0 = disabled. Matches Xray-core's `heartbeatPeriod`.
    let heartbeatPeriod: UInt32

    init(
        host: String,
        path: String = "/",
        headers: [String: String] = [:],
        maxEarlyData: Int = 0,
        earlyDataHeaderName: String = "Sec-WebSocket-Protocol",
        heartbeatPeriod: UInt32 = 0
    ) {
        self.host = host
        self.path = path
        self.headers = headers
        self.maxEarlyData = maxEarlyData
        self.earlyDataHeaderName = earlyDataHeaderName
        self.heartbeatPeriod = heartbeatPeriod
    }

    /// Parse WebSocket parameters from VLESS URL query parameters.
    ///
    /// Expected parameters: `type=ws&host=example.com&path=/ws&ed=2048`
    static func parse(from params: [String: String], serverAddress: String) -> WebSocketConfiguration? {
        let host = params["host"] ?? serverAddress
        let path = (params["path"] ?? "/").removingPercentEncoding ?? "/"
        let maxEarlyData = Int(params["ed"] ?? "0") ?? 0

        return WebSocketConfiguration(
            host: host,
            path: path,
            maxEarlyData: maxEarlyData
        )
    }
}

/// WebSocket transport errors.
enum WebSocketError: Error, LocalizedError {
    case upgradeFailed(String)
    case invalidFrame(String)
    case connectionClosed(UInt16, String)

    var errorDescription: String? {
        switch self {
        case .upgradeFailed(let reason):
            return "WebSocket upgrade failed: \(reason)"
        case .invalidFrame(let reason):
            return "WebSocket invalid frame: \(reason)"
        case .connectionClosed(let code, let reason):
            return "WebSocket closed (\(code)): \(reason)"
        }
    }
}
