//
//  ProxyClient+Naive.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/15/26.
//

import Foundation

extension ProxyClient {
    /// Connects through a CONNECT tunnel using HTTP/1.1, HTTP/2, or HTTP/3.
    ///
    /// The scheme is determined by ``OutboundProtocol``:
    /// - `.http11` → HTTP/1.1 CONNECT over TLS
    /// - `.http2` → HTTP/2 CONNECT over TLS (NaiveProxy)
    /// - `.quic`  → HTTP/3 CONNECT over QUIC (NaiveProxy)
    ///
    /// All schemes produce a ``NaiveProxyConnection`` wrapping the appropriate ``NaiveTunnel``.
    func connectWithNaive(
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let scheme: NaiveConfiguration.NaiveScheme
        switch configuration.outboundProtocol {
        case .http11: scheme = .http11
        case .http2:  scheme = .http2
        case .http3:  scheme = .http3
        default:      scheme = .http2
        }

        let naiveConfig = NaiveConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            username: configuration.activeUsername,
            password: configuration.activePassword,
            sni: nil,
            scheme: scheme
        )

        // RFC 3986 §3.2.2: IPv6 literals must be bracketed in authority strings.
        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

        // Use serverAddress (hostname) instead of connectAddress (which may
        // contain a fake IP from FakeIPPool when switching proxies while the
        // VPN is active).  The Network Extension resolves hostnames via the
        // real network interface, bypassing the tunnel.
        let proxyHost = configuration.serverAddress

        switch scheme {
        case .http11:
            let transport = NaiveTLSTransport(
                host: proxyHost,
                port: configuration.serverPort,
                sni: naiveConfig.effectiveSNI,
                alpn: ["http/1.1"],
                tunnel: self.tunnel
            )
            let tunnel = HTTP11Connection(
                transport: transport,
                configuration: naiveConfig,
                destination: destination
            )
            openTunnelAndWrap(tunnel, completion: completion)

        case .http2:
            HTTP2SessionPool.shared.acquireStream(
                host: proxyHost,
                port: configuration.serverPort,
                sni: naiveConfig.effectiveSNI,
                tunnel: self.tunnel,
                configuration: naiveConfig,
                destination: destination
            ) { [self] stream in
                openTunnelAndWrap(stream, completion: completion)
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

    /// Acquires an HTTP/3 stream and opens the CONNECT tunnel, retrying once
    /// on a fresh session for failures that kill the underlying QUIC
    /// connection — handshake timeout, DRAINING, IDLE_CLOSE, or peer
    /// `STREAM_ID_BLOCKED`. Without this, a single bad handshake fails every
    /// concurrent `acquireStream` caller queued on the same `readyCallbacks`
    /// list; the pool evicts the dead session on `onClose`, so the retry
    /// lands on a freshly-built one (or joins a newer connecting session).
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

    /// Session-level failures that warrant one fresh-session retry.
    /// Excludes stream-level protocol errors (407 auth, tunnel status, etc.)
    /// which would fail the same way on any new session.
    private static func isRetryableHTTP3Error(_ error: Error) -> Bool {
        if error is QUICConnection.QUICError { return true }
        if case HTTP3Error.streamIdBlocked = error { return true }
        if case HTTP3Error.streamClosed = error { return true }
        if case let HTTP3Error.connectionFailed(msg) = error {
            // `connectionFailed` covers both "Session closed" / "Session
            // draining" (retry worthwhile) and malformed-frame protocol
            // errors (retry pointless). Distinguish by the message we emit.
            return msg.hasPrefix("Session ")
        }
        return false
    }

    /// Opens a ``NaiveTunnel`` and wraps it in a ``NaiveProxyConnection``.
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
