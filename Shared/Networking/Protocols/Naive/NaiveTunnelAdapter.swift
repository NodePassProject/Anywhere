//
//  NaiveTunnelAdapter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

// MARK: - NaiveProxyHeaders

/// Builds NaiveProxy's CONNECT request headers (credentials, User-Agent, and
/// padding negotiation) for each HTTP version. This is where the proxy-protocol
/// specifics live that the generic ``HTTPTunnel`` implementations deliberately
/// omit; callers inject the result so the HTTP layers stay reusable.
enum NaiveProxyHeaders {

    /// Browser-like User-Agent sent on CONNECT requests for probe resistance:
    /// some probe-resistant proxy servers reject requests that omit one.
    static let userAgent = "Mozilla/5.0 (iPhone16,2; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Resorts/4.7.5"

    /// HTTP/2 CONNECT headers: lowercase field names (required by HTTP/2), with
    /// a freshly randomized `padding` header generated per call.
    static func http2(basicAuth: String?) -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = []
        if let basicAuth {
            headers.append((name: "proxy-authorization", value: "Basic \(basicAuth)"))
        }
        headers.append((name: "user-agent", value: userAgent))
        headers.append(contentsOf: NaivePaddingNegotiator.requestHeaders())
        return headers
    }

    /// HTTP/1.1 CONNECT headers: title-case field names and no padding (HTTP/1.1
    /// tunnels don't negotiate padding). Order: User-Agent, then
    /// Proxy-Authorization.
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

/// Adapts a generic ``HTTPTunnel`` (HTTP/1.1 or HTTP/2) to ``NaiveTunnel`` by
/// layering NaiveProxy's padding negotiation on top: once the tunnel opens, it
/// derives ``negotiatedPaddingType`` from the CONNECT response headers the
/// tunnel exposes.
///
/// This is the seam that keeps the HTTP/1.1 and HTTP/2 implementations free of
/// any NaiveProxy specifics. (HTTP/3's ``HTTP3Stream`` is NaiveProxy-specific
/// glue and conforms to ``NaiveTunnel`` directly, so it needs no adapter.)
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
