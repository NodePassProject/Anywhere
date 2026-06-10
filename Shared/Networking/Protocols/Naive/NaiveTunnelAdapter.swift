//
//  NaiveTunnelAdapter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

// MARK: - NaiveProxyHeaders

/// Builds NaiveProxy's CONNECT request headers for each HTTP version.
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

/// Adapts a generic HTTPTunnel (HTTP/1.1 or HTTP/2) to NaiveTunnel, deriving
/// the negotiated padding type from CONNECT response headers.
nonisolated final class NaiveTunnelAdapter: NaiveTunnel {

    private let tunnel: HTTPTunnel
    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    init(_ tunnel: HTTPTunnel) {
        self.tunnel = tunnel
    }

    var isConnected: Bool { tunnel.isConnected }

    func openTunnel(completion: @escaping (Error?) -> Void) {
        tunnel.openTunnel { [weak self] error in
            if error == nil, let self {
                self.negotiatedPaddingType =
                    NaivePaddingNegotiator.parseResponse(headers: self.tunnel.responseHeaders)
            }
            completion(error)
        }
    }

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        tunnel.sendData(data, completion: completion)
    }

    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        tunnel.receiveData(completion: completion)
    }

    func close() {
        tunnel.close()
    }
}
