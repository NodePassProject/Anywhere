//
//  ProxyClient+Naive.swift
//  Anywhere
//
//  Created by NodePassProject on 4/15/26.
//

import Foundation

extension ProxyClient {
    /// Connects through a CONNECT tunnel using HTTP/1.1, HTTP/2, or HTTP/3.
    func connectWithNaive(
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let scheme: NaiveConfiguration.NaiveScheme
        let username: String?
        let password: String?
        switch configuration.outbound {
        case .http11(let u, let p): scheme = .http11; username = u; password = p
        case .http2(let u, let p):  scheme = .http2;  username = u; password = p
        case .http3(let u, let p):  scheme = .http3;  username = u; password = p
        default:                    scheme = .http2;  username = nil; password = nil
        }

        let naiveConfig = NaiveConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            username: username,
            password: password,
            sni: nil,
            scheme: scheme
        )

        // RFC 3986 §3.2.2: IPv6 literals must be bracketed in authority strings.
        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

        // Use serverAddress, not connectAddress: the latter may hold a FakeIPPool
        // IP under an active VPN, routing the dial through the tunnel.
        let proxyHost = configuration.serverAddress

        switch scheme {
        case .http11:
            let transport = TLSStreamTransport(
                host: proxyHost,
                port: configuration.serverPort,
                sni: naiveConfig.effectiveSNI,
                alpn: ["http/1.1"],
                tunnel: self.tunnel
            )
            let http11 = HTTP11Connection(
                transport: transport,
                extraHeaders: NaiveProxyHeaders.http11(basicAuth: naiveConfig.basicAuth),
                destination: destination
            )
            openTunnelAndWrap(NaiveTunnelAdapter(http11), completion: completion)

        case .http2:
            HTTP2SessionPool.shared.acquireStream(
                host: proxyHost,
                port: configuration.serverPort,
                sni: naiveConfig.effectiveSNI,
                tunnel: self.tunnel,
                connectHeaders: { NaiveProxyHeaders.http2(basicAuth: naiveConfig.basicAuth) },
                destination: destination
            ) { [self] stream in
                openTunnelAndWrap(NaiveTunnelAdapter(stream), completion: completion)
            }

        case .http3:
            acquireHTTP3StreamWithRetry(
                proxyHost: proxyHost,
                naiveConfig: naiveConfig,
                destination: destination,
                retriesLeft: 1,
                completion: completion
            )
        }
    }

    /// Acquires an HTTP/3 stream and opens the CONNECT tunnel, retrying once on
    /// session-level QUIC failures; the pool evicts the dead session on close.
    private func acquireHTTP3StreamWithRetry(
        proxyHost: String,
        naiveConfig: NaiveConfiguration,
        destination: String,
        retriesLeft: Int,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        HTTP3SessionPool.shared.acquireStream(
            host: proxyHost,
            port: configuration.serverPort,
            sni: naiveConfig.effectiveSNI,
            configuration: naiveConfig,
            destination: destination
        ) { [self] stream in
            stream.openTunnel { [self] error in
                if let error {
                    stream.close()
                    if retriesLeft > 0 && Self.isRetryableHTTP3Error(error) {
                        self.acquireHTTP3StreamWithRetry(
                            proxyHost: proxyHost,
                            naiveConfig: naiveConfig,
                            destination: destination,
                            retriesLeft: retriesLeft - 1,
                            completion: completion
                        )
                        return
                    }
                    completion(.failure(error))
                    return
                }
                let connection = NaiveProxyConnection(
                    tunnel: stream,
                    paddingType: stream.negotiatedPaddingType
                )
                completion(.success(connection))
            }
        }
    }

    /// Session-level failures warrant a fresh-session retry; stream-level
    /// protocol errors (407, tunnel status) would fail identically.
    private static func isRetryableHTTP3Error(_ error: Error) -> Bool {
        if error is QUICConnection.QUICError { return true }
        if case HTTP3Error.streamIdBlocked = error { return true }
        if case HTTP3Error.streamClosed = error { return true }
        if case let HTTP3Error.connectionFailed(msg) = error {
            // connectionFailed mixes session and protocol errors; our session errors start with "Session ".
            return msg.hasPrefix("Session ")
        }
        return false
    }

    private func openTunnelAndWrap(
        _ tunnel: NaiveTunnel,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        tunnel.openTunnel { error in
            if let error {
                tunnel.close()
                completion(.failure(error))
                return
            }
            let connection = NaiveProxyConnection(
                tunnel: tunnel,
                paddingType: tunnel.negotiatedPaddingType
            )
            completion(.success(connection))
        }
    }
}
