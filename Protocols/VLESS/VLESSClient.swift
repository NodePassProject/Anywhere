//
//  VLESSClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "Proxy")

// MARK: - ProxyClient

/// Client for establishing proxy connections over TCP or UDP.
///
/// Supports both direct BSD socket connections and Reality-wrapped connections.
/// For the XTLS Vision flow, the connection is wrapped in a ``VLESSVisionConnection``.
class ProxyClient {
    private let configuration: ProxyConfiguration
    private var connection: BSDSocket?
    private var realityClient: RealityClient?
    private var realityConnection: TLSRecordConnection?
    private var tlsClient: TLSClient?
    private var tlsConnection: TLSRecordConnection?
    private var webSocketConnection: WebSocketConnection?
    private var httpUpgradeConnection: HTTPUpgradeConnection?
    private var xhttpConnection: XHTTPConnection?

    /// Retry configuration matching Xray-core: ExponentialBackoff(5, 200)
    /// Delays: 0, 200, 400, 600, 800 ms (linear backoff)
    private static let maxRetryAttempts = 5
    private static let retryBaseDelay = 200 // milliseconds

    /// The base Vision flow string sent on the wire (suffix stripped).
    private static let visionFlow = "xtls-rprx-vision"

    /// Whether the configured flow is a Vision variant.
    private var isVisionFlow: Bool {
        configuration.flow == Self.visionFlow || configuration.flow == Self.visionFlow + "-udp443"
    }

    /// Whether UDP port 443 is allowed (only with the `-udp443` suffix).
    private var allowUDP443: Bool {
        configuration.flow == Self.visionFlow + "-udp443"
    }

    /// Creates a new proxy client with the given configuration.
    ///
    /// - Parameter configuration: The proxy server configuration.
    init(configuration: ProxyConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API

    /// Connects to a destination through the VLESS server using TCP.
    ///
    /// - Parameters:
    ///   - destinationHost: The destination hostname or IP address.
    ///   - destinationPort: The destination port number.
    ///   - initialData: Optional initial data to send with the VLESS request header.
    ///   - completion: Called with the established ``ProxyConnection`` or an error.
    func connect(
        to destinationHost: String,
        port destinationPort: UInt16,
        initialData: Data? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectWithCommand(
            command: .tcp,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: initialData,
            completion: completion
        )
    }

    /// Connects to a destination through the VLESS server using UDP.
    ///
    /// - Parameters:
    ///   - destinationHost: The destination hostname or IP address.
    ///   - destinationPort: The destination port number.
    ///   - completion: Called with the established ``ProxyConnection`` or an error.
    func connectUDP(
        to destinationHost: String,
        port destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectWithCommand(
            command: .udp,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: nil,
            completion: completion
        )
    }

    /// Connects a mux control channel through the VLESS server.
    ///
    /// Uses `command=.mux` with destination `v1.mux.cool:666` (matching Xray-core).
    /// When Vision flow is active, the mux connection is wrapped with Vision.
    ///
    /// - Parameter completion: Called with the established ``ProxyConnection`` or an error.
    func connectMux(completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        connectWithCommand(
            command: .mux,
            destinationHost: "v1.mux.cool",
            destinationPort: 666,
            initialData: nil,
            completion: completion
        )
    }

    /// Cancels the connection and releases all resources.
    func cancel() {
        xhttpConnection?.cancel()
        xhttpConnection = nil
        httpUpgradeConnection?.cancel()
        httpUpgradeConnection = nil
        webSocketConnection?.cancel()
        webSocketConnection = nil
        connection?.forceCancel()
        connection = nil
        realityConnection?.cancel()
        realityConnection = nil
        realityClient?.cancel()
        realityClient = nil
        tlsConnection?.cancel()
        tlsConnection = nil
        tlsClient?.cancel()
        tlsClient = nil
    }

    // MARK: - Connection Routing

    /// Routes the connection through either Reality or direct TCP based on configuration.
    private func connectWithCommand(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        // Vision silently drops UDP/443 (QUIC) unless the -udp443 flow variant is used
        if command == .udp && destinationPort == 443 && isVisionFlow && !allowUDP443 {
            completion(.failure(ProxyError.dropped))
            return
        }

        // SS restrictions: no Mux, no Reality, no Vision
        if isShadowsocks {
            if command == .mux {
                completion(.failure(ProxyError.protocolError("Mux is not supported with Shadowsocks")))
                return
            }
            if configuration.reality != nil {
                completion(.failure(ProxyError.protocolError("Reality is not supported with Shadowsocks")))
                return
            }
        }

        if configuration.transport == "ws" {
            // Vision over WebSocket is not supported
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over WebSocket transport")))
                return
            }
            connectWithWebSocket(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
        } else if configuration.transport == "httpupgrade" {
            // Vision over HTTP upgrade is not supported
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over HTTP upgrade transport")))
                return
            }
            connectWithHTTPUpgrade(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
        } else if configuration.transport == "xhttp" {
            // Vision over XHTTP is not supported
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over XHTTP transport")))
                return
            }
            connectWithXHTTP(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
        } else if let tlsConfiguration = configuration.tls {
            connectWithTLS(
                tlsConfig: tlsConfiguration,
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
        } else if let realityConfiguration = configuration.reality {
            connectWithReality(
                realityConfig: realityConfiguration,
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
        } else {
            connectDirect(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
        }
    }

    // MARK: - WebSocket Connection

    /// Connects to the VLESS server using WebSocket transport.
    /// Routes to WSS (TLS + WebSocket) or plain WS based on TLS configuration.
    private func connectWithWebSocket(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let wsConfiguration = configuration.websocket else {
            completion(.failure(ProxyError.connectionFailed("WebSocket transport specified but no WebSocket configuration")))
            return
        }

        if configuration.tls != nil {
            connectWSSWithRetry(attempt: 0, lastError: nil, wsConfig: wsConfiguration, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else {
            connectWSWithRetry(attempt: 0, lastError: nil, wsConfig: wsConfiguration, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        }
    }

    // MARK: Plain WS (TCP → WebSocket → VLESS)

    private func connectWSWithRetry(
        attempt: Int,
        lastError: Error?,
        wsConfig: WebSocketConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let socket = BSDSocket()
            self.connection = socket

            socket.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort, queue: .global()) { [weak self] error in
                if let error {
                    logger.warning("WS connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self?.connectWSWithRetry(attempt: attempt + 1, lastError: error, wsConfig: wsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                    return
                }

                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                let wsConnection = WebSocketConnection(socket: socket, configuration: wsConfig)
                self.webSocketConnection = wsConnection

                wsConnection.performUpgrade { [weak self] upgradeError in
                    if let upgradeError {
                        logger.warning("WS upgrade attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(upgradeError.localizedDescription)")
                        self?.connectWSWithRetry(attempt: attempt + 1, lastError: upgradeError, wsConfig: wsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                        return
                    }

                    self?.performWebSocketHandshake(
                        wsConnection: wsConnection,
                        command: command,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort,
                        initialData: initialData,
                        completion: completion
                    )
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: WSS (TCP → TLS → WebSocket → VLESS)

    private func connectWSSWithRetry(
        attempt: Int,
        lastError: Error?,
        wsConfig: WebSocketConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            guard let tlsConfiguration = self.configuration.tls else {
                completion(.failure(ProxyError.connectionFailed("WSS requires TLS configuration")))
                return
            }

            // Force ALPN to http/1.1 for WebSocket — matches Xray-core's
            // tls.WithNextProto("http/1.1") in websocket/dialer.go.
            // HTTP/2 negotiation would break the WebSocket upgrade handshake.
            let wsTlsConfiguration = TLSConfiguration(
                serverName: tlsConfiguration.serverName,
                alpn: ["http/1.1"],
                allowInsecure: tlsConfiguration.allowInsecure,
                fingerprint: tlsConfiguration.fingerprint
            )

            let tlsClient = TLSClient(configuration: wsTlsConfiguration)

            tlsClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection

                    let wsConnection = WebSocketConnection(tlsConnection: tlsConnection, configuration: wsConfig)
                    self.webSocketConnection = wsConnection

                    wsConnection.performUpgrade { [weak self] upgradeError in
                        if let upgradeError {
                            logger.warning("WSS upgrade attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(upgradeError.localizedDescription)")
                            self?.connectWSSWithRetry(attempt: attempt + 1, lastError: upgradeError, wsConfig: wsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                            return
                        }

                        self?.performWebSocketHandshake(
                            wsConnection: wsConnection,
                            command: command,
                            destinationHost: destinationHost,
                            destinationPort: destinationPort,
                            initialData: initialData,
                            completion: completion
                        )
                    }

                case .failure(let error):
                    logger.warning("WSS TLS attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self.connectWSSWithRetry(attempt: attempt + 1, lastError: error, wsConfig: wsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: WebSocket VLESS Handshake

    /// Performs the VLESS handshake over an established WebSocket connection.
    private func performWebSocketHandshake(
        wsConnection: WebSocketConnection,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if isShadowsocks {
            let inner = WebSocketProxyConnection(wsConnection: wsConnection)
            inner.responseHeaderReceived = true
            let result = wrapWithShadowsocks(inner: inner, command: command, destinationHost: destinationHost, destinationPort: destinationPort)
            completion(result)
            return
        }

        var requestData = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: nil // Vision is rejected before reaching here
        )

        if let initialData {
            requestData.append(initialData)
        }

        wsConnection.send(data: requestData) { error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            var proxyConnection: ProxyConnection
            if command == .udp {
                proxyConnection = WebSocketUDPProxyConnection(wsConnection: wsConnection)
            } else {
                proxyConnection = WebSocketProxyConnection(wsConnection: wsConnection)
            }

            completion(.success(proxyConnection))
        }
    }

    // MARK: - HTTP Upgrade Connection

    /// Connects to the VLESS server using HTTP upgrade transport.
    /// Routes to HTTPS upgrade (TLS + HTTP upgrade) or plain HTTP upgrade based on TLS configuration.
    private func connectWithHTTPUpgrade(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let httpUpgradeConfiguration = configuration.httpUpgrade else {
            completion(.failure(ProxyError.connectionFailed("HTTP upgrade transport specified but no configuration")))
            return
        }

        if configuration.tls != nil {
            connectHTTPSUpgradeWithRetry(attempt: 0, lastError: nil, huConfig: httpUpgradeConfiguration, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else {
            connectHTTPUpgradeWithRetry(attempt: 0, lastError: nil, huConfig: httpUpgradeConfiguration, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        }
    }

    // MARK: Plain HTTP Upgrade (TCP → HTTP Upgrade → raw TCP → VLESS)

    private func connectHTTPUpgradeWithRetry(
        attempt: Int,
        lastError: Error?,
        huConfig: HTTPUpgradeConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let socket = BSDSocket()
            self.connection = socket

            socket.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort, queue: .global()) { [weak self] error in
                if let error {
                    logger.warning("HTTP upgrade connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self?.connectHTTPUpgradeWithRetry(attempt: attempt + 1, lastError: error, huConfig: huConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                    return
                }

                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                let huConnection = HTTPUpgradeConnection(socket: socket, configuration: huConfig)
                self.httpUpgradeConnection = huConnection

                huConnection.performUpgrade { [weak self] upgradeError in
                    if let upgradeError {
                        logger.warning("HTTP upgrade attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(upgradeError.localizedDescription)")
                        self?.connectHTTPUpgradeWithRetry(attempt: attempt + 1, lastError: upgradeError, huConfig: huConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                        return
                    }

                    self?.performHTTPUpgradeHandshake(
                        huConnection: huConnection,
                        command: command,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort,
                        initialData: initialData,
                        completion: completion
                    )
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: HTTPS Upgrade (TCP → TLS → HTTP Upgrade → raw TCP over TLS → VLESS)

    private func connectHTTPSUpgradeWithRetry(
        attempt: Int,
        lastError: Error?,
        huConfig: HTTPUpgradeConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            guard let tlsConfiguration = self.configuration.tls else {
                completion(.failure(ProxyError.connectionFailed("HTTPS upgrade requires TLS configuration")))
                return
            }

            let tlsClient = TLSClient(configuration: tlsConfiguration)

            tlsClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection

                    let huConnection = HTTPUpgradeConnection(tlsConnection: tlsConnection, configuration: huConfig)
                    self.httpUpgradeConnection = huConnection

                    huConnection.performUpgrade { [weak self] upgradeError in
                        if let upgradeError {
                            logger.warning("HTTPS upgrade attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(upgradeError.localizedDescription)")
                            self?.connectHTTPSUpgradeWithRetry(attempt: attempt + 1, lastError: upgradeError, huConfig: huConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                            return
                        }

                        self?.performHTTPUpgradeHandshake(
                            huConnection: huConnection,
                            command: command,
                            destinationHost: destinationHost,
                            destinationPort: destinationPort,
                            initialData: initialData,
                            completion: completion
                        )
                    }

                case .failure(let error):
                    logger.warning("HTTPS upgrade TLS attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self.connectHTTPSUpgradeWithRetry(attempt: attempt + 1, lastError: error, huConfig: huConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: HTTP Upgrade VLESS Handshake

    /// Performs the VLESS handshake over an established HTTP upgrade connection.
    private func performHTTPUpgradeHandshake(
        huConnection: HTTPUpgradeConnection,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if isShadowsocks {
            let inner = HTTPUpgradeProxyConnection(huConnection: huConnection)
            inner.responseHeaderReceived = true
            let result = wrapWithShadowsocks(inner: inner, command: command, destinationHost: destinationHost, destinationPort: destinationPort)
            completion(result)
            return
        }

        var requestData = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: nil // Vision is rejected before reaching here
        )

        if let initialData {
            requestData.append(initialData)
        }

        huConnection.send(data: requestData) { error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            var proxyConnection: ProxyConnection
            if command == .udp {
                proxyConnection = HTTPUpgradeUDPProxyConnection(huConnection: huConnection)
            } else {
                proxyConnection = HTTPUpgradeProxyConnection(huConnection: huConnection)
            }

            completion(.success(proxyConnection))
        }
    }

    // MARK: - XHTTP Connection

    /// Connects to the VLESS server using XHTTP transport.
    /// Routes to plain HTTP or HTTPS based on security configuration.
    ///
    /// Reality is not supported: Xray-core forces HTTP/2 for Reality (dialer.go:80-82),
    /// and we only implement HTTP/1.1 over raw sockets.
    ///
    /// Mode auto-resolution (matching Xray-core dialer.go:280-289):
    /// - Reality → stream-one with HTTP/2 (Xray-core forces h2 for Reality)
    /// - TLS/none → packet-up (CDN-safe, GET + POST over HTTP/1.1)
    private func connectWithXHTTP(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let xhttpConfiguration = configuration.xhttp else {
            completion(.failure(ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")))
            return
        }

        // Resolve mode: auto → actual mode based on security
        let resolvedMode: XHTTPMode
        if xhttpConfiguration.mode == .auto {
            // Reality → stream-one (direct connection, HTTP/2)
            // TLS/none → packet-up (CDN-safe, HTTP/1.1)
            resolvedMode = configuration.reality != nil ? .streamOne : .packetUp
        } else {
            resolvedMode = xhttpConfiguration.mode
        }

        // Generate session ID for packet-up and stream-up modes
        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? UUID().uuidString : ""

        if let realityConfiguration = configuration.reality {
            connectXHTTPRealityWithRetry(attempt: 0, lastError: nil, realityConfig: realityConfiguration, xhttpConfig: xhttpConfiguration, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if configuration.tls != nil {
            connectXHTTPSWithRetry(attempt: 0, lastError: nil, xhttpConfig: xhttpConfiguration, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else {
            connectXHTTPWithRetry(attempt: 0, lastError: nil, xhttpConfig: xhttpConfiguration, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        }
    }

    // MARK: Plain XHTTP (TCP → XHTTP → VLESS)

    private func connectXHTTPWithRetry(
        attempt: Int,
        lastError: Error?,
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let socket = BSDSocket()
            self.connection = socket

            socket.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort, queue: .global()) { [weak self] error in
                if let error {
                    logger.warning("XHTTP connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self?.connectXHTTPWithRetry(attempt: attempt + 1, lastError: error, xhttpConfig: xhttpConfig, mode: mode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                    return
                }

                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                // Upload connection factory for packet-up and stream-up modes
                let needsUpload = mode == .packetUp || mode == .streamUp
                let uploadFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = needsUpload ? { [weak self] factoryCompletion in
                    guard let self else {
                        factoryCompletion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    let uploadSocket = BSDSocket()
                    uploadSocket.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort, queue: .global()) { error in
                        if let error {
                            factoryCompletion(.failure(error))
                            return
                        }
                        let closures = TransportClosures(
                            send: { data, completion in uploadSocket.send(data: data, completion: completion) },
                            receive: { completion in uploadSocket.receive(maximumLength: 65536, completion: completion) },
                            cancel: { uploadSocket.forceCancel() }
                        )
                        factoryCompletion(.success(closures))
                    }
                } : nil

                let xhttpConn = XHTTPConnection(socket: socket, configuration: xhttpConfig, mode: mode, sessionId: sessionId, uploadConnectionFactory: uploadFactory)
                self.xhttpConnection = xhttpConn

                xhttpConn.performSetup { [weak self] setupError in
                    if let setupError {
                        logger.warning("XHTTP setup attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(setupError.localizedDescription)")
                        self?.connectXHTTPWithRetry(attempt: attempt + 1, lastError: setupError, xhttpConfig: xhttpConfig, mode: mode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                        return
                    }

                    self?.performXHTTPHandshake(
                        xhttpConnection: xhttpConn,
                        command: command,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort,
                        initialData: initialData,
                        completion: completion
                    )
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: XHTTPS (TCP → TLS → XHTTP → VLESS)

    private func connectXHTTPSWithRetry(
        attempt: Int,
        lastError: Error?,
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            guard let baseTLSConfiguration = self.configuration.tls else {
                completion(.failure(ProxyError.connectionFailed("XHTTPS requires TLS configuration")))
                return
            }

            // Force ALPN to http/1.1 for XHTTP over TLS.
            // Xray-core uses HTTP/2 when ALPN negotiates h2 (dialer.go:78-95),
            // but we only support HTTP/1.1. CDNs and direct servers both accept http/1.1.
            let tlsConfiguration = TLSConfiguration(
                serverName: baseTLSConfiguration.serverName,
                alpn: ["http/1.1"],
                allowInsecure: baseTLSConfiguration.allowInsecure,
                fingerprint: baseTLSConfiguration.fingerprint
            )

            let tlsClient = TLSClient(configuration: tlsConfiguration)

            tlsClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection

                    // Upload connection factory for packet-up and stream-up modes
                    let needsUpload = mode == .packetUp || mode == .streamUp
                    let uploadFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = needsUpload ? { [weak self] factoryCompletion in
                        guard let self else {
                            factoryCompletion(.failure(ProxyError.connectionFailed("Client deallocated")))
                            return
                        }
                        // Use same http/1.1-forced TLS configuration for upload connection
                        let uploadTLSClient = TLSClient(configuration: tlsConfiguration)
                        uploadTLSClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { result in
                            switch result {
                            case .success(let uploadTLSConnection):
                                let closures = TransportClosures(
                                    send: { data, completion in uploadTLSConnection.send(data: data, completion: completion) },
                                    receive: { completion in uploadTLSConnection.receive { data, error in completion(data, false, error) } },
                                    cancel: { uploadTLSConnection.cancel() }
                                )
                                factoryCompletion(.success(closures))
                            case .failure(let error):
                                factoryCompletion(.failure(error))
                            }
                        }
                    } : nil

                    let xhttpConn = XHTTPConnection(tlsConnection: tlsConnection, configuration: xhttpConfig, mode: mode, sessionId: sessionId, uploadConnectionFactory: uploadFactory)
                    self.xhttpConnection = xhttpConn

                    xhttpConn.performSetup { [weak self] setupError in
                        if let setupError {
                            logger.warning("XHTTPS setup attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(setupError.localizedDescription)")
                            self?.connectXHTTPSWithRetry(attempt: attempt + 1, lastError: setupError, xhttpConfig: xhttpConfig, mode: mode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                            return
                        }

                        self?.performXHTTPHandshake(
                            xhttpConnection: xhttpConn,
                            command: command,
                            destinationHost: destinationHost,
                            destinationPort: destinationPort,
                            initialData: initialData,
                            completion: completion
                        )
                    }

                case .failure(let error):
                    logger.warning("XHTTPS TLS attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self.connectXHTTPSWithRetry(attempt: attempt + 1, lastError: error, xhttpConfig: xhttpConfig, mode: mode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: XHTTP Reality (TCP → Reality TLS → HTTP/2 → XHTTP → VLESS)

    private func connectXHTTPRealityWithRetry(
        attempt: Int,
        lastError: Error?,
        realityConfig: RealityConfiguration,
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let realityClient = RealityClient(configuration: realityConfig)

            realityClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { [weak self, realityClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                switch result {
                case .success(let realityConnection):
                    self.realityClient = realityClient
                    self.realityConnection = realityConnection

                    // Reality + xhttp uses HTTP/2 (Xray-core dialer.go:80-82)
                    let xhttpConn = XHTTPConnection(
                        tlsConnection: realityConnection,
                        configuration: xhttpConfig,
                        mode: mode,
                        sessionId: sessionId,
                        useHTTP2: true
                    )
                    self.xhttpConnection = xhttpConn

                    xhttpConn.performSetup { [weak self] setupError in
                        if let setupError {
                            logger.warning("XHTTP Reality setup attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(setupError.localizedDescription)")
                            self?.connectXHTTPRealityWithRetry(attempt: attempt + 1, lastError: setupError, realityConfig: realityConfig, xhttpConfig: xhttpConfig, mode: mode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                            return
                        }

                        self?.performXHTTPHandshake(
                            xhttpConnection: xhttpConn,
                            command: command,
                            destinationHost: destinationHost,
                            destinationPort: destinationPort,
                            initialData: initialData,
                            completion: completion
                        )
                    }

                case .failure(let error):
                    logger.warning("XHTTP Reality connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self.connectXHTTPRealityWithRetry(attempt: attempt + 1, lastError: error, realityConfig: realityConfig, xhttpConfig: xhttpConfig, mode: mode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: XHTTP VLESS Handshake

    /// Performs the VLESS handshake over an established XHTTP connection.
    private func performXHTTPHandshake(
        xhttpConnection: XHTTPConnection,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if isShadowsocks {
            let inner = XHTTPProxyConnection(xhttpConnection: xhttpConnection)
            inner.responseHeaderReceived = true
            let result = wrapWithShadowsocks(inner: inner, command: command, destinationHost: destinationHost, destinationPort: destinationPort)
            completion(result)
            return
        }

        var requestData = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: nil // Vision is rejected before reaching here
        )

        if let initialData {
            requestData.append(initialData)
        }

        xhttpConnection.send(data: requestData) { error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            var proxyConnection: ProxyConnection
            if command == .udp {
                proxyConnection = XHTTPUDPProxyConnection(xhttpConnection: xhttpConnection)
            } else {
                proxyConnection = XHTTPProxyConnection(xhttpConnection: xhttpConnection)
            }

            completion(.success(proxyConnection))
        }
    }

    // MARK: - Direct Connection

    /// Connects directly to the VLESS server using a BSD socket.
    /// Retries with linear backoff (0, 200, 400, 600, 800 ms) on connection failure, matching Xray-core.
    private func connectDirect(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectDirectWithRetry(attempt: 0, lastError: nil, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
    }

    private func connectDirectWithRetry(
        attempt: Int,
        lastError: Error?,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let socket = BSDSocket()
            self.connection = socket

            socket.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort, queue: .global()) { [weak self] error in
                if let error {
                    logger.warning("Connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self?.connectDirectWithRetry(attempt: attempt + 1, lastError: error, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                    return
                }

                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                self.performHandshake(
                    command: command,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    initialData: initialData,
                    completion: completion
                )
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: - Reality Connection

    /// Connects to the VLESS server through the Reality protocol.
    /// Retries with linear backoff (0, 200, 400, 600, 800 ms) on connection failure, matching Xray-core.
    private func connectWithReality(
        realityConfig: RealityConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectRealityWithRetry(attempt: 0, lastError: nil, realityConfig: realityConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
    }

    private func connectRealityWithRetry(
        attempt: Int,
        lastError: Error?,
        realityConfig: RealityConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let realityClient = RealityClient(configuration: realityConfig)

            realityClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { [weak self, realityClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                switch result {
                case .success(let realityConnection):
                    self.realityClient = realityClient
                    self.realityConnection = realityConnection
                    self.performRealityHandshake(
                        command: command,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort,
                        initialData: initialData,
                        completion: completion
                    )

                case .failure(let error):
                    logger.warning("Reality connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self.connectRealityWithRetry(attempt: attempt + 1, lastError: error, realityConfig: realityConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    // MARK: - TLS Connection

    /// Connects to the VLESS server through standard TLS.
    /// Retries with linear backoff (0, 200, 400, 600, 800 ms) on connection failure, matching Xray-core.
    private func connectWithTLS(
        tlsConfig: TLSConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectTLSWithRetry(attempt: 0, lastError: nil, tlsConfig: tlsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
    }

    private func connectTLSWithRetry(
        attempt: Int,
        lastError: Error?,
        tlsConfig: TLSConfiguration,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard attempt < Self.maxRetryAttempts else {
            completion(.failure(lastError ?? ProxyError.connectionFailed("All retry attempts failed")))
            return
        }

        let delay = Self.retryBaseDelay * attempt
        let work = { [weak self] in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let tlsClient = TLSClient(configuration: tlsConfig)

            tlsClient.connect(host: self.configuration.connectAddress, port: self.configuration.serverPort) { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }

                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection
                    self.performTLSHandshake(
                        command: command,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort,
                        initialData: initialData,
                        completion: completion
                    )

                case .failure(let error):
                    logger.warning("TLS connection attempt \(attempt + 1)/\(Self.maxRetryAttempts) failed: \(error.localizedDescription)")
                    self.connectTLSWithRetry(attempt: attempt + 1, lastError: error, tlsConfig: tlsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
                }
            }
        }

        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay), execute: work)
        } else {
            work()
        }
    }

    /// Performs the VLESS handshake over a TLS connection.
    ///
    /// Sends the VLESS request header through the TLS tunnel and returns
    /// a ``ProxyConnection`` wrapper.
    private func performTLSHandshake(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if isShadowsocks {
            guard let tlsConnection else {
                completion(.failure(ProxyError.connectionFailed("Connection cancelled")))
                return
            }
            let inner = TLSProxyConnection(tlsConnection: tlsConnection)
            inner.responseHeaderReceived = true
            let result = wrapWithShadowsocks(inner: inner, command: command, destinationHost: destinationHost, destinationPort: destinationPort)
            completion(result)
            return
        }

        let isVision = isVisionFlow && (command == .tcp || command == .mux)

        var requestData = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: isVision ? Self.visionFlow : nil
        )

        if let initialData, !isVision {
            requestData.append(initialData)
        }

        guard let tlsConnection else {
            completion(.failure(ProxyError.connectionFailed("Connection cancelled")))
            return
        }
        tlsConnection.send(data: requestData) { [weak self, weak tlsConnection] error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            guard let tlsConnection else {
                completion(.failure(ProxyError.connectionFailed("Connection deallocated")))
                return
            }

            var proxyConnection: ProxyConnection
            if command == .udp {
                proxyConnection = TLSUDPProxyConnection(tlsConnection: tlsConnection)
            } else {
                proxyConnection = TLSProxyConnection(tlsConnection: tlsConnection)
            }

            if isVision {
                // Verify outer TLS is 1.3 (matches Xray-core outbound.go:346-355)
                if let tlsError = self.validateOuterTLSForVision(proxyConnection) {
                    completion(.failure(tlsError))
                    return
                }
                let vision = self.wrapWithVision(proxyConnection)
                if let initialData {
                    vision.send(data: initialData)
                } else {
                    vision.sendEmptyPadding()
                }
                proxyConnection = vision
            }

            completion(.success(proxyConnection))
        }
    }

    // MARK: - Handshake

    /// Performs the VLESS handshake over a direct BSD socket connection.
    ///
    /// Sends the VLESS request header and returns a ``ProxyConnection`` wrapper.
    /// For Vision flow, the connection is additionally wrapped in ``VLESSVisionConnection``.
    private func performHandshake(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if isShadowsocks {
            guard let connection else {
                completion(.failure(ProxyError.connectionFailed("Connection cancelled")))
                return
            }
            let inner = DirectProxyConnection(connection: connection)
            inner.responseHeaderReceived = true
            let result = wrapWithShadowsocks(inner: inner, command: command, destinationHost: destinationHost, destinationPort: destinationPort)
            completion(result)
            return
        }

        let isVision = isVisionFlow && (command == .tcp || command == .mux)

        var requestData = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: isVision ? Self.visionFlow : nil
        )

        // For Vision flow, initial data needs separate padding — don't append to header
        if let initialData, !isVision {
            requestData.append(initialData)
        }

        guard let connection else {
            completion(.failure(ProxyError.connectionFailed("Connection cancelled")))
            return
        }
        connection.send(data: requestData) { [weak self, weak connection] error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            guard let connection else {
                completion(.failure(ProxyError.connectionFailed("Connection deallocated")))
                return
            }

            var proxyConnection: ProxyConnection
            if command == .udp {
                proxyConnection = DirectUDPProxyConnection(connection: connection)
            } else {
                proxyConnection = DirectProxyConnection(connection: connection)
            }

            if isVision {
                // Verify outer TLS is 1.3 (matches Xray-core outbound.go:346-355)
                if let tlsError = self.validateOuterTLSForVision(proxyConnection) {
                    completion(.failure(tlsError))
                    return
                }
                let vision = self.wrapWithVision(proxyConnection)
                if let initialData {
                    vision.send(data: initialData)
                } else {
                    vision.sendEmptyPadding()
                }
                proxyConnection = vision
            }

            completion(.success(proxyConnection))
        }
    }

    /// Performs the VLESS handshake over a Reality connection.
    ///
    /// Sends the VLESS request header through the Reality tunnel and returns
    /// a ``ProxyConnection`` wrapper.
    private func performRealityHandshake(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let isVision = isVisionFlow && (command == .tcp || command == .mux)

        var requestData = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: isVision ? Self.visionFlow : nil
        )

        if let initialData, !isVision {
            requestData.append(initialData)
        }

        guard let realityConnection else {
            completion(.failure(ProxyError.connectionFailed("Connection cancelled")))
            return
        }
        realityConnection.send(data: requestData) { [weak self, weak realityConnection] error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            guard let realityConnection else {
                completion(.failure(ProxyError.connectionFailed("Connection deallocated")))
                return
            }

            var proxyConnection: ProxyConnection
            if command == .udp {
                proxyConnection = RealityUDPProxyConnection(realityConnection: realityConnection)
            } else {
                proxyConnection = RealityProxyConnection(realityConnection: realityConnection)
            }

            if isVision {
                // Verify outer TLS is 1.3 (matches Xray-core outbound.go:346-355)
                if let tlsError = self.validateOuterTLSForVision(proxyConnection) {
                    completion(.failure(tlsError))
                    return
                }
                let vision = self.wrapWithVision(proxyConnection)
                if let initialData {
                    vision.send(data: initialData)
                } else {
                    vision.sendEmptyPadding()
                }
                proxyConnection = vision
            }

            completion(.success(proxyConnection))
        }
    }

    // MARK: - TLS Version Check

    /// Validates that the outer TLS connection is TLS 1.3 when using Vision flow.
    /// Matches Xray-core `outbound.go` lines 346-355.
    /// Returns an error if the check fails, nil if OK or not applicable.
    private func validateOuterTLSForVision(_ connection: ProxyConnection) -> Error? {
        guard let version = connection.outerTLSVersion else {
            // No TLS (raw TCP) — nothing to check
            return nil
        }
        if version != .tls13 {
            return ProxyError.protocolError("Vision requires outer TLS 1.3, found \(version)")
        }
        return nil
    }

    // MARK: - Vision Wrapping

    /// Wraps a VLESS connection with the XTLS Vision layer.
    ///
    /// - Parameter connection: The base VLESS connection to wrap.
    /// - Returns: A ``VLESSVisionConnection`` wrapping the provided connection.
    private func wrapWithVision(_ connection: ProxyConnection) -> VLESSVisionConnection {
        let uuidBytes = configuration.uuid.uuid
        let uuidData = Data([
            uuidBytes.0, uuidBytes.1, uuidBytes.2, uuidBytes.3,
            uuidBytes.4, uuidBytes.5, uuidBytes.6, uuidBytes.7,
            uuidBytes.8, uuidBytes.9, uuidBytes.10, uuidBytes.11,
            uuidBytes.12, uuidBytes.13, uuidBytes.14, uuidBytes.15
        ])
        return VLESSVisionConnection(connection: connection, userUUID: uuidData, testseed: configuration.testseed)
    }

    // MARK: - Shadowsocks

    /// Whether this client is configured for Shadowsocks outbound.
    private var isShadowsocks: Bool {
        configuration.outboundProtocol == .shadowsocks
    }

    /// Wraps a bare transport connection with Shadowsocks AEAD encryption for TCP.
    private func wrapWithShadowsocks(
        inner: ProxyConnection,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) -> Result<ProxyConnection, Error> {
        guard let method = configuration.ssMethod,
              let cipher = ShadowsocksCipher(method: method) else {
            return .failure(ProxyError.protocolError("Invalid Shadowsocks method: \(configuration.ssMethod ?? "nil")"))
        }
        guard let password = configuration.ssPassword else {
            return .failure(ProxyError.protocolError("Shadowsocks password not set"))
        }

        if cipher.isSS2022 {
            // Shadowsocks 2022: base64-encoded PSK(s), BLAKE3 key derivation
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: password, keySize: cipher.keySize) else {
                return .failure(ProxyError.protocolError("Invalid Shadowsocks 2022 PSK"))
            }

            if command == .udp {
                if cipher == .blake3chacha20poly1305 {
                    let ssConn = Shadowsocks2022ChaChaUDPConnection(
                        inner: inner, psk: pskList.last!, dstHost: destinationHost, dstPort: destinationPort
                    )
                    return .success(ssConn)
                } else {
                    let ssConn = Shadowsocks2022AESUDPConnection(
                        inner: inner, cipher: cipher, pskList: pskList,
                        dstHost: destinationHost, dstPort: destinationPort
                    )
                    return .success(ssConn)
                }
            } else {
                let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)
                let ssConn = Shadowsocks2022Connection(
                    inner: inner, cipher: cipher, pskList: pskList,
                    addressHeader: addressHeader
                )
                return .success(ssConn)
            }
        } else {
            // Legacy Shadowsocks: password-based EVP_BytesToKey derivation
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)

            if command == .udp {
                let ssConn = ShadowsocksUDPConnection(
                    inner: inner, cipher: cipher, masterKey: masterKey,
                    dstHost: destinationHost, dstPort: destinationPort
                )
                return .success(ssConn)
            } else {
                let ssConn = ShadowsocksConnection(
                    inner: inner, cipher: cipher, masterKey: masterKey,
                    addressHeader: addressHeader
                )
                return .success(ssConn)
            }
        }
    }
}
