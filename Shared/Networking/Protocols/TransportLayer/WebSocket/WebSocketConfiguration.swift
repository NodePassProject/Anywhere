//
//  WebSocketConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

struct WebSocketConfiguration: Codable, Equatable, Hashable {
    let host: String
    let path: String
    let headers: [String: String]
    /// 0 = disabled.
    let maxEarlyData: Int
    let earlyDataHeaderName: String
    /// Seconds; 0 = disabled.
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

    var normalizedPath: String {
        if path.isEmpty { return "/" }
        return path.hasPrefix("/") ? path : "/" + path
    }

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
