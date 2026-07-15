//
//  NaiveTunnelAdapter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

// MARK: - NaiveProxyHeaders

enum NaiveProxyHeaders {

    /// Browser-like User-Agent; probe-resistant proxy servers may reject requests without one.
    static let userAgent = "Mozilla/5.0 (iPhone16,2; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Resorts/4.7.5"

    /// HTTP/2 CONNECT headers; field names must be lowercase per HTTP/2.
    static func http2(basicAuth: String?) -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = []
        if let basicAuth {
            headers.append((name: "proxy-authorization", value: "Basic \(basicAuth)"))
        }
        headers.append((name: "user-agent", value: userAgent))
        headers.append(contentsOf: NaivePaddingNegotiator.requestHeaders())
        return headers
    }

    /// HTTP/1.1 CONNECT headers; no padding (HTTP/1.1 tunnels don't negotiate it).
    static func http11(basicAuth: String?) -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = [
            (name: "User-Agent", value: userAgent)
        ]
        if let basicAuth {
            headers.append((name: "Proxy-Authorization", value: "Basic \(basicAuth)"))
        }
        return headers
    }
}

// MARK: - NaiveTunnelAdapter

/// Derives the negotiated padding type from CONNECT response headers.
nonisolated final class NaiveTunnelAdapter: NaiveTunnel {

    private let tunnel: HTTPTunnel
    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    init(_ tunnel: HTTPTunnel) {
        self.tunnel = tunnel
    }

    var isConnected: Bool { tunnel.isConnected }

    func openTunnel() async throws {
        try await tunnel.openTunnel()
        negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers: tunnel.responseHeaders)
    }

    func sendData(_ data: Data) async throws {
        try await tunnel.sendData(data)
    }

    func receiveData() async throws -> Data? {
        try await tunnel.receiveData()
    }

    func close() {
        tunnel.close()
    }
}
