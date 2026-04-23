//
//  ProxyClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Proxy")

// MARK: - ProxyClient

/// Client for establishing proxy connections over TCP or UDP.
///
///
/// Supports multiple transports (TCP, WebSocket, HTTP Upgrade, XHTTP) and security layers
/// (TLS, Reality). For the XTLS Vision flow, the connection is wrapped in a ``VLESSVisionConnection``.
class ProxyClient {
    let configuration: ProxyConfiguration
    private let useResolvedAddressForDirectDial: Bool
    var connection: RawTCPSocket?
    private var realityClient: RealityClient?
    private var realityConnection: TLSRecordConnection?
    var tlsClient: TLSClient?
    var tlsConnection: TLSRecordConnection?
    private var webSocketConnection: WebSocketConnection?
    private var httpUpgradeConnection: HTTPUpgradeConnection?
    private var grpcConnection: GRPCConnection?
    private var xhttpConnection: XHTTPConnection?

    /// Proxy tunnel from a previous chain link (for proxy chaining).
    /// When set, all transport connections use this tunnel instead of creating a ``RawTCPSocket``.
    var tunnel: ProxyConnection?
    /// Intermediate chain proxy clients (retained for lifecycle management).
    private var chainClients: [ProxyClient] = []

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
    /// - Parameters:
    ///   - configuration: The proxy server configuration.
    ///   - tunnel: Optional tunnel from a previous chain link (for proxy chaining).
    ///   - useResolvedAddressForDirectDial: Whether direct first-hop transports should
    ///     prefer `resolvedIP` over `serverAddress`. Intended for latency testing only.
    init(
        configuration: ProxyConfiguration,
        tunnel: ProxyConnection? = nil,
        useResolvedAddressForDirectDial: Bool = false
    ) {
        self.configuration = configuration
        self.tunnel = tunnel
        self.useResolvedAddressForDirectDial = useResolvedAddressForDirectDial
    }

    /// Host used for direct first-hop transport dials when not already tunneled through
    /// another proxy. Normal VPN traffic keeps using the configured hostname so DNS can
    /// refresh naturally; latency tests may opt into the pre-resolved IP.
    var directDialHost: String {
        useResolvedAddressForDirectDial ? configuration.connectAddress : configuration.serverAddress
    }

    // MARK: - Public API

    /// Connects to a destination through the proxy server using TCP.
    func connect(
        to destinationHost: String,
        port destinationPort: UInt16,
        initialData: Data? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectThroughChainIfNeeded(
            command: .tcp,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: initialData,
            completion: completion
        )
    }

    /// Connects to a destination through the proxy server using UDP.
    func connectUDP(
        to destinationHost: String,
        port destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectThroughChainIfNeeded(
            command: .udp,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: nil,
            completion: completion
        )
    }

    /// Connects a mux control channel through the proxy server.
    ///
    /// Uses `command=.mux` with destination `v1.mux.cool:666` (matching Xray-core).
    func connectMux(completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        connectThroughChainIfNeeded(
            command: .mux,
            destinationHost: "v1.mux.cool",
            destinationPort: 666,
            initialData: nil,
            completion: completion
        )
    }

    /// If the configuration has a chain, builds the chain tunnel first, then connects.
    /// Otherwise, connects directly.
    private func connectThroughChainIfNeeded(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let chain = configuration.chain, !chain.isEmpty, tunnel == nil else {
            // No chain, or tunnel already provided — connect directly
            connectWithCommand(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
            return
        }

        // Build chain tunnel: connect through each proxy in the chain to reach this proxy's server
        buildChainTunnel(chain: chain, index: 0, currentTunnel: nil) { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let chainTunnel):
                self.tunnel = chainTunnel
                self.connectWithCommand(
                    command: command,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    initialData: initialData,
                    completion: completion
                )
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    /// Recursively builds a chain tunnel by connecting through each proxy in the chain.
    ///
    /// - Parameters:
    ///   - chain: The ordered list of chain proxies (outermost first).
    ///   - index: The current chain link index being connected.
    ///   - currentTunnel: The tunnel from the previous chain link (nil for the first).
    ///   - completion: Called with the final tunnel connection to this proxy's server.
    private func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let chainConfig = chain[index]

        // Target for this chain link: next link's server, or this proxy's server
        let nextHost: String
        let nextPort: UInt16
        if index + 1 < chain.count {
            nextHost = chain[index + 1].serverAddress
            nextPort = chain[index + 1].serverPort
        } else {
            nextHost = configuration.serverAddress
            nextPort = configuration.serverPort
        }
        
        let chainClient = ProxyClient(
            configuration: chainConfig,
            tunnel: currentTunnel,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial
        )
        chainClients.append(chainClient)

        chainClient.connect(to: nextHost, port: nextPort) { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let connection):
                if index + 1 < chain.count {
                    self.buildChainTunnel(chain: chain, index: index + 1, currentTunnel: connection, completion: completion)
                } else {
                    completion(.success(connection))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    /// Cancels the connection and releases all resources.
    func cancel() {
        webSocketConnection?.cancel()
        webSocketConnection = nil
        httpUpgradeConnection?.cancel()
        httpUpgradeConnection = nil
        grpcConnection?.cancel()
        grpcConnection = nil
        xhttpConnection?.cancel()
        xhttpConnection = nil
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
        // Cancel chain link clients
        for client in chainClients { client.cancel() }
        chainClients.removeAll()
        tunnel = nil
    }

    // MARK: - Protocol Handshake

    /// Wraps an established transport connection in the appropriate outbound
    /// protocol (VLESS or Shadowsocks) for the requested command.
    ///
    /// - Shadowsocks: returns a Shadowsocks{,2022,UDP} connection that owns
    ///   its own wire encryption and framing.
    /// - VLESS: wraps in ``VLESSConnection``, writes the VLESS request header
    ///   (plus `initialData` for non-Vision TCP), then layers
    ///   ``VLESSUDPConnection`` (UDP) or ``VLESSVisionConnection`` (Vision)
    ///   on top as needed.
    private func sendProtocolHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        supportsVision: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if isShadowsocks {
            completion(wrapWithShadowsocks(
                inner: connection, command: command,
                destinationHost: destinationHost, destinationPort: destinationPort
            ))
            return
        }

        // VLESS path
        let isVision = supportsVision && isVisionFlow && (command == .tcp || command == .mux)

        let requestHeader = VLESSProtocol.encodeRequestHeader(
            uuid: configuration.uuid,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: isVision ? Self.visionFlow : nil
        )

        let vless = VLESSConnection(inner: connection)
        // For Vision flow, initial data needs separate padding — don't append to the header.
        let handshakeInitialData = isVision ? nil : initialData
        vless.sendHandshake(requestHeader: requestHeader, initialData: handshakeInitialData) { [weak self] error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let proxyConnection: ProxyConnection = (command == .udp)
                ? VLESSUDPConnection(inner: vless)
                : vless

            if isVision {
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
                completion(.success(vision))
            } else {
                completion(.success(proxyConnection))
            }
        }
    }

    // MARK: - Connection Routing

    /// Routes the connection through the appropriate transport and security layers.
    private func connectWithCommand(
        command: ProxyCommand,
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

        // Centralised capability check — only VLESS carries mux framing.
        if command == .mux, !configuration.outboundProtocol.supportsMux {
            completion(.failure(ProxyError.protocolError(
                "Mux is not supported with \(configuration.outboundProtocol.name)"
            )))
            return
        }

        if configuration.outboundProtocol == .hysteria {
            connectWithHysteria(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                completion: completion
            )
            return
        }

        if configuration.outboundProtocol == .trojan {
            connectWithTrojan(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
            return
        }

        if isShadowsocks {
            connectDirect(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            return
        }

        if configuration.outboundProtocol == .socks5 {
            connectWithSOCKS5(command: command, destinationHost: destinationHost, destinationPort: destinationPort, completion: completion)
            return
        }

        if configuration.outboundProtocol.isNaive {
            if command != .tcp {
                completion(.failure(ProxyError.dropped))
                return
            }
            connectWithNaive(destinationHost: destinationHost, destinationPort: destinationPort, completion: completion)
            return
        }

        // Only VLESS reaches this point
        switch configuration.transportLayer {
        case .ws:
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over WebSocket transport")))
                return
            }
            connectWithWebSocket(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .httpUpgrade:
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over HTTP upgrade transport")))
                return
            }
            connectWithHTTPUpgrade(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .grpc:
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over gRPC transport")))
                return
            }
            connectWithGRPC(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .xhttp:
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over XHTTP transport")))
                return
            }
            connectWithXHTTP(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .tcp:
            if let tlsConfig = configuration.tls {
                connectWithTLS(tlsConfig: tlsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            } else if let realityConfig = configuration.reality {
                connectWithReality(realityConfig: realityConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            } else {
                connectDirect(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            }
        }
    }

    // MARK: - Direct Connection

    private func connectDirect(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if let tunnel = self.tunnel {
            // Chained: use tunnel instead of RawTCPSocket
            let directProxyConnection = DirectProxyConnection(connection: TunneledTransport(tunnel: tunnel))
            sendProtocolHandshake(
                over: directProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: false, completion: completion
            )
        } else {
            let transport = RawTCPSocket()
            self.connection = transport

            transport.connect(host: directDialHost, port: configuration.serverPort) { [weak self] error in
                if let error {
                    completion(.failure(error))
                    return
                }
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                let directProxyConnection = DirectProxyConnection(connection: transport)
                self.sendProtocolHandshake(
                    over: directProxyConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData,
                    supportsVision: false, completion: completion
                )
            }
        }
    }

    // MARK: - TLS Connection

    private func connectWithTLS(
        tlsConfig: TLSConfiguration,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let tlsClient = TLSClient(configuration: tlsConfig)

        let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, tlsClient] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let tlsConnection):
                self.tlsClient = tlsClient
                self.tlsConnection = tlsConnection
                let tlsProxyConnection = TLSProxyConnection(tlsConnection: tlsConnection)
                self.sendProtocolHandshake(
                    over: tlsProxyConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData,
                    supportsVision: true, completion: completion
                )
            case .failure(let error):
                completion(.failure(error))
            }
        }

        if let tunnel = self.tunnel {
            tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
        } else {
            tlsClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleTLSResult)
        }
    }

    // MARK: - Reality Connection

    private func connectWithReality(
        realityConfig: RealityConfiguration,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let realityClient = RealityClient(configuration: realityConfig)

        let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, realityClient] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let realityConnection):
                self.realityClient = realityClient
                self.realityConnection = realityConnection
                let realityProxyConnection = RealityProxyConnection(realityConnection: realityConnection)
                self.sendProtocolHandshake(
                    over: realityProxyConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData,
                    supportsVision: true, completion: completion
                )
            case .failure(let error):
                completion(.failure(error))
            }
        }

        if let tunnel = self.tunnel {
            realityClient.connect(overTunnel: tunnel, completion: handleRealityResult)
        } else {
            realityClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleRealityResult)
        }
    }

    // MARK: - WebSocket Connection

    /// Connects using WebSocket transport. Routes to WSS (TLS) or plain WS.
    private func connectWithWebSocket(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let wsConfig = configuration.websocket else {
            completion(.failure(ProxyError.connectionFailed("WebSocket transport specified but no WebSocket configuration")))
            return
        }

        if let baseTLSConfig = configuration.tls {
            // WSS: TCP → TLS → WebSocket → VLESS
            // Force ALPN to http/1.1 (Xray-core tls.WithNextProto("http/1.1"))
            let wsTlsConfig = TLSConfiguration(
                serverName: baseTLSConfig.serverName,
                alpn: ["http/1.1"],
                fingerprint: baseTLSConfig.fingerprint
            )
            let tlsClient = TLSClient(configuration: wsTlsConfig)

            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection
                    let wsConnection = WebSocketConnection(tlsConnection: tlsConnection, configuration: wsConfig)
                    self.performWebSocketUpgrade(
                        wsConnection: wsConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                case .failure(let error):
                    completion(.failure(error))
                }
            }

            if let tunnel = self.tunnel {
                tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
            } else {
                tlsClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleTLSResult)
            }
        } else {
            if let tunnel = self.tunnel {
                // Chained plain WS: Tunnel → WebSocket → VLESS
                let wsConnection = WebSocketConnection(tunnel: tunnel, configuration: wsConfig)
                performWebSocketUpgrade(
                    wsConnection: wsConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData, completion: completion
                )
            } else {
                // Plain WS: TCP → WebSocket → VLESS
                let transport = RawTCPSocket()
                self.connection = transport

                transport.connect(host: directDialHost, port: configuration.serverPort) { [weak self] error in
                    if let error {
                        completion(.failure(error))
                        return
                    }
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    let wsConnection = WebSocketConnection(transport: transport, configuration: wsConfig)
                    self.performWebSocketUpgrade(
                        wsConnection: wsConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                }
            }
        }
    }

    /// Performs WebSocket upgrade then sends the protocol handshake.
    private func performWebSocketUpgrade(
        wsConnection: WebSocketConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        self.webSocketConnection = wsConnection

        wsConnection.performUpgrade { [weak self] error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            let webSocketProxyConnection = WebSocketProxyConnection(wsConnection: wsConnection)
            self.sendProtocolHandshake(
                over: webSocketProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: false, completion: completion
            )
        }
    }

    // MARK: - HTTP Upgrade Connection

    /// Connects using HTTP upgrade transport. Routes to HTTPS or plain HTTP.
    private func connectWithHTTPUpgrade(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let huConfig = configuration.httpUpgrade else {
            completion(.failure(ProxyError.connectionFailed("HTTP upgrade transport specified but no configuration")))
            return
        }

        if let tlsConfiguration = configuration.tls {
            // HTTPS Upgrade: TCP → TLS → HTTP Upgrade → raw TCP over TLS → VLESS
            let tlsClient = TLSClient(configuration: tlsConfiguration)

            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection
                    let huConnection = HTTPUpgradeConnection(tlsConnection: tlsConnection, configuration: huConfig)
                    self.performHTTPUpgrade(
                        huConnection: huConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                case .failure(let error):
                    completion(.failure(error))
                }
            }

            if let tunnel = self.tunnel {
                tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
            } else {
                tlsClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleTLSResult)
            }
        } else {
            if let tunnel = self.tunnel {
                // Chained plain HTTP Upgrade: Tunnel → HTTP Upgrade → VLESS
                let huConnection = HTTPUpgradeConnection(tunnel: tunnel, configuration: huConfig)
                performHTTPUpgrade(
                    huConnection: huConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData, completion: completion
                )
            } else {
                // Plain HTTP Upgrade: TCP → HTTP Upgrade → raw TCP → VLESS
                let transport = RawTCPSocket()
                self.connection = transport

                transport.connect(host: directDialHost, port: configuration.serverPort) { [weak self] error in
                    if let error {
                        completion(.failure(error))
                        return
                    }
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    let huConnection = HTTPUpgradeConnection(transport: transport, configuration: huConfig)
                    self.performHTTPUpgrade(
                        huConnection: huConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                }
            }
        }
    }

    /// Performs HTTP upgrade then sends the protocol handshake.
    private func performHTTPUpgrade(
        huConnection: HTTPUpgradeConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        self.httpUpgradeConnection = huConnection

        huConnection.performUpgrade { [weak self] error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            let httpUpgradeProxyConnection = HTTPUpgradeProxyConnection(huConnection: huConnection)
            self.sendProtocolHandshake(
                over: httpUpgradeProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: false, completion: completion
            )
        }
    }

    // MARK: - gRPC Connection

    /// Returns the TLS configuration to use for gRPC. ALPN is forced to `h2` because
    /// gRPC requires HTTP/2.
    private func sanitizedGRPCTLSConfiguration(from base: TLSConfiguration) -> TLSConfiguration {
        TLSConfiguration(
            serverName: base.serverName,
            alpn: ["h2"],
            fingerprint: base.fingerprint
        )
    }

    /// Connects using gRPC transport, opening a single bidirectional gRPC stream over
    /// HTTP/2. Routes through Reality, TLS, or plain TCP based on configuration.
    private func connectWithGRPC(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let grpcConfig = configuration.grpc else {
            completion(.failure(ProxyError.connectionFailed("gRPC transport specified but no gRPC configuration")))
            return
        }

        // Resolve the :authority to send over HTTP/2 from the TLS / Reality SNI when
        // no explicit override is configured.
        let tlsServerName: String?
        if case .tls(let tls) = configuration.securityLayer { tlsServerName = tls.serverName }
        else { tlsServerName = nil }
        let realityServerName: String?
        if case .reality(let reality) = configuration.securityLayer { realityServerName = reality.serverName }
        else { realityServerName = nil }
        let authority = grpcConfig.resolvedAuthority(
            tlsServerName: tlsServerName,
            realityServerName: realityServerName,
            serverAddress: configuration.serverAddress
        )

        if let realityConfig = configuration.reality {
            // Reality + gRPC: Reality handles its own ALPN internally; layer gRPC on top.
            let realityClient = RealityClient(configuration: realityConfig)

            let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, realityClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let realityConnection):
                    self.realityClient = realityClient
                    self.realityConnection = realityConnection
                    let grpcConnection = GRPCConnection(
                        tlsConnection: realityConnection,
                        configuration: grpcConfig,
                        authority: authority
                    )
                    self.performGRPCSetup(
                        grpcConnection: grpcConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                case .failure(let error):
                    completion(.failure(error))
                }
            }

            if let tunnel = self.tunnel {
                realityClient.connect(overTunnel: tunnel, completion: handleRealityResult)
            } else {
                realityClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleRealityResult)
            }
            return
        }

        if let baseTLSConfig = configuration.tls {
            // gRPC over TLS: force ALPN `h2`, handshake, then open the HTTP/2 stream.
            let grpcTLSConfig = sanitizedGRPCTLSConfiguration(from: baseTLSConfig)
            let tlsClient = TLSClient(configuration: grpcTLSConfig)

            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, tlsClient] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tlsConnection):
                    self.tlsClient = tlsClient
                    self.tlsConnection = tlsConnection
                    let grpcConnection = GRPCConnection(
                        tlsConnection: tlsConnection,
                        configuration: grpcConfig,
                        authority: authority
                    )
                    self.performGRPCSetup(
                        grpcConnection: grpcConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                case .failure(let error):
                    completion(.failure(error))
                }
            }

            if let tunnel = self.tunnel {
                tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
            } else {
                tlsClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleTLSResult)
            }
            return
        }

        // Plain gRPC (no TLS).
        if let tunnel = self.tunnel {
            let grpcConnection = GRPCConnection(tunnel: tunnel, configuration: grpcConfig, authority: authority)
            performGRPCSetup(
                grpcConnection: grpcConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData, completion: completion
            )
        } else {
            let transport = RawTCPSocket()
            self.connection = transport
            transport.connect(host: directDialHost, port: configuration.serverPort) { [weak self] error in
                if let error {
                    completion(.failure(error))
                    return
                }
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                let grpcConnection = GRPCConnection(transport: transport, configuration: grpcConfig, authority: authority)
                self.performGRPCSetup(
                    grpcConnection: grpcConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData, completion: completion
                )
            }
        }
    }

    /// Performs the gRPC HTTP/2 setup then sends the VLESS protocol handshake.
    private func performGRPCSetup(
        grpcConnection: GRPCConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        self.grpcConnection = grpcConnection

        grpcConnection.performSetup { [weak self] error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            let grpcProxyConnection = GRPCProxyConnection(grpcConnection: grpcConnection)
            self.sendProtocolHandshake(
                over: grpcProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: false, completion: completion
            )
        }
    }

    // MARK: - XHTTP Connection

    /// HTTP version selected for XHTTP, matching Xray-core's split HTTP dialer.
    private enum XHTTPHTTPVersion {
        case http11
        case http2
        case http3

        var logName: String {
            switch self {
            case .http11:
                return "http/1.1"
            case .http2:
                return "h2"
            case .http3:
                return "h3"
            }
        }
    }

    /// Mirrors Xray-core's `decideHTTPVersion` for split HTTP.
    ///
    /// - Reality always uses HTTP/2.
    /// - No TLS means plain HTTP/1.1.
    /// - TLS with a single `http/1.1` ALPN stays on HTTP/1.1.
    /// - TLS with a single `h3` ALPN expects QUIC/HTTP/3.
    /// - Everything else uses HTTP/2.
    private func decideXHTTPHTTPVersion() -> XHTTPHTTPVersion {
        if configuration.reality != nil {
            return .http2
        }

        guard let tlsConfig = configuration.tls else {
            return .http11
        }

        let alpn = tlsConfig.alpn ?? []
        guard alpn.count == 1 else {
            return .http2
        }

        switch alpn[0].lowercased() {
        case "http/1.1":
            return .http11
        case "h3":
            return .http3
        default:
            return .http2
        }
    }

    /// Removes unsupported ALPN entries from XHTTP-over-TCP handshakes.
    ///
    /// This client only implements XHTTP over TCP as HTTP/1.1 or HTTP/2. The
    /// TLS handshake for that path should not advertise protocols such as `h3`
    /// that require a different transport underneath.
    private func sanitizedXHTTPTLSConfiguration(
        from base: TLSConfiguration,
        httpVersion: XHTTPHTTPVersion
    ) -> TLSConfiguration {
        let sanitizedALPN: [String]?

        switch httpVersion {
        case .http11:
            sanitizedALPN = ["http/1.1"]
        case .http2:
            if let configuredALPN = base.alpn {
                let filtered = configuredALPN.filter {
                    $0.caseInsensitiveCompare("h2") == .orderedSame ||
                    $0.caseInsensitiveCompare("http/1.1") == .orderedSame
                }
                if filtered.isEmpty || (filtered.count == 1 && filtered[0].caseInsensitiveCompare("http/1.1") == .orderedSame) {
                    sanitizedALPN = ["h2", "http/1.1"]
                } else {
                    sanitizedALPN = filtered
                }
            } else {
                sanitizedALPN = nil
            }
        case .http3:
            sanitizedALPN = ["h3"]
        }

        return TLSConfiguration(
            serverName: base.serverName,
            alpn: sanitizedALPN,
            fingerprint: base.fingerprint
        )
    }

    /// Connects using XHTTP transport. Routes to plain HTTP, HTTPS, or Reality.
    ///
    /// Mode & HTTP version resolution follows Xray-core's split HTTP dialer:
    /// - Reality → stream-one with HTTP/2
    /// - TLS → HTTP/1.1, HTTP/2, or HTTP/3 based on ALPN
    /// - none → packet-up with HTTP/1.1
    private func connectWithXHTTP(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let xhttpConfig = configuration.xhttp else {
            completion(.failure(ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")))
            return
        }

        // HTTP/3 is intentionally unsupported: XHTTP-over-QUIC would require a
        // full QUIC stack (DATAGRAM frames, 0-RTT resumption, connection
        // migration). Server configs that negotiate ALPN "h3" must be rejected
        // here; clients should downgrade to h2 in the XHTTP config.
        let httpVersion = decideXHTTPHTTPVersion()
        if httpVersion == .http3 {
            completion(.failure(ProxyError.connectionFailed(
                "XHTTP over TLS with ALPN h3 requires QUIC/HTTP/3, which is not implemented"
            )))
            return
        }

        // Resolve mode: auto → actual mode
        let resolvedMode: XHTTPMode
        if xhttpConfig.mode == .auto {
            if configuration.reality != nil {
                resolvedMode = .streamOne
            } else {
                resolvedMode = .packetUp
            }
        } else {
            resolvedMode = xhttpConfig.mode
        }

        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? UUID().uuidString.lowercased() : ""

        if let realityConfig = configuration.reality {
            connectXHTTPReality(realityConfig: realityConfig, xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if configuration.tls != nil {
            connectXHTTPS(xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, httpVersion: httpVersion, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else {
            connectXHTTPPlain(xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        }
    }

    // MARK: Plain XHTTP (TCP → XHTTP → VLESS)

    private func connectXHTTPPlain(
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let setupXHTTP: (any RawTransport) -> Void = { [weak self] transport in
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
                self.createUploadTransport(factoryCompletion)
            } : nil

            let xhttpConnection: XHTTPConnection
            if let tunnel = self.tunnel {
                xhttpConnection = XHTTPConnection(tunnel: tunnel, configuration: xhttpConfig, mode: mode, sessionId: sessionId, uploadConnectionFactory: uploadFactory)
            } else {
                guard let socket = transport as? RawTCPSocket else {
                    completion(.failure(ProxyError.connectionFailed("Expected RawTCPSocket for plain XHTTP")))
                    return
                }
                xhttpConnection = XHTTPConnection(transport: socket, configuration: xhttpConfig, mode: mode, sessionId: sessionId, uploadConnectionFactory: uploadFactory)
            }
            self.xhttpConnection = xhttpConnection
            self.performXHTTPSetup(
                xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData, completion: completion
            )
        }

        if let tunnel = self.tunnel {
            setupXHTTP(TunneledTransport(tunnel: tunnel))
        } else {
            let transport = RawTCPSocket()
            self.connection = transport
            transport.connect(host: directDialHost, port: configuration.serverPort) { error in
                if let error {
                    completion(.failure(error))
                    return
                }
                setupXHTTP(transport)
            }
        }
    }

    /// Creates transport closures for an XHTTP upload connection.
    /// For chained connections, builds a new chain tunnel for the upload.
    private func createUploadTransport(_ factoryCompletion: @escaping (Result<TransportClosures, Error>) -> Void) {
        if let chain = configuration.chain, !chain.isEmpty {
            // Build a new chain tunnel for the upload connection
            buildChainTunnel(chain: chain, index: 0, currentTunnel: nil) { result in
                switch result {
                case .success(let uploadTunnel):
                    factoryCompletion(.success(TransportClosures(tunnel: uploadTunnel)))
                case .failure(let error):
                    factoryCompletion(.failure(error))
                }
            }
        } else {
            let uploadTransport = RawTCPSocket()
            uploadTransport.connect(host: directDialHost, port: configuration.serverPort) { error in
                if let error {
                    factoryCompletion(.failure(error))
                    return
                }
                factoryCompletion(.success(TransportClosures(rawTCP: uploadTransport)))
            }
        }
    }

    // MARK: XHTTPS (TCP → TLS → XHTTP → VLESS)

    private func connectXHTTPS(
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        httpVersion: XHTTPHTTPVersion,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let baseTLSConfig = configuration.tls else {
            completion(.failure(ProxyError.connectionFailed("XHTTPS requires TLS configuration")))
            return
        }

        guard httpVersion != .http3 else {
            completion(.failure(ProxyError.connectionFailed(
                "XHTTP over TLS with ALPN h3 requires QUIC/HTTP/3, which is not implemented yet"
            )))
            return
        }

        // Keep the original fingerprint/SNI, but do not advertise h3 on the TCP path.
        let tlsConfiguration = sanitizedXHTTPTLSConfiguration(from: baseTLSConfig, httpVersion: httpVersion)
        let tlsClient = TLSClient(configuration: tlsConfiguration)

        let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, tlsClient] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let tlsConnection):
                self.tlsClient = tlsClient
                self.tlsConnection = tlsConnection

                if httpVersion == .http2 {
                    // HTTP/2 uses a single TLS connection with H2 framing for all XHTTP modes.
                    let xhttpConnection = XHTTPConnection(
                        tlsConnection: tlsConnection,
                        configuration: xhttpConfig,
                        mode: mode,
                        sessionId: sessionId,
                        useHTTP2: true
                    )
                    self.xhttpConnection = xhttpConnection
                    self.performXHTTPSetup(
                        xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                } else {
                    // HTTP/1.1: separate upload connection for packet-up and stream-up
                    let needsUpload = mode == .packetUp || mode == .streamUp
                    let uploadFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = needsUpload ? { [weak self] factoryCompletion in
                        guard let self else {
                            factoryCompletion(.failure(ProxyError.connectionFailed("Client deallocated")))
                            return
                        }
                        let uploadTLSClient = TLSClient(configuration: tlsConfiguration)
                        if let chain = self.configuration.chain, !chain.isEmpty {
                            self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil) { tunnelResult in
                                switch tunnelResult {
                                case .success(let uploadTunnel):
                                    uploadTLSClient.connect(overTunnel: uploadTunnel) { result in
                                        switch result {
                                        case .success(let uploadTLSConnection):
                                            factoryCompletion(.success(TransportClosures(tls: uploadTLSConnection)))
                                        case .failure(let error):
                                            factoryCompletion(.failure(error))
                                        }
                                    }
                                case .failure(let error):
                                    factoryCompletion(.failure(error))
                                }
                            }
                        } else {
                            uploadTLSClient.connect(host: self.directDialHost, port: self.configuration.serverPort) { result in
                                switch result {
                                case .success(let uploadTLSConnection):
                                    factoryCompletion(.success(TransportClosures(tls: uploadTLSConnection)))
                                case .failure(let error):
                                    factoryCompletion(.failure(error))
                                }
                            }
                        }
                    } : nil

                    let xhttpConnection = XHTTPConnection(tlsConnection: tlsConnection, configuration: xhttpConfig, mode: mode, sessionId: sessionId, uploadConnectionFactory: uploadFactory)
                    self.xhttpConnection = xhttpConnection
                    self.performXHTTPSetup(
                        xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                }

            case .failure(let error):
                completion(.failure(error))
            }
        }

        if let tunnel = self.tunnel {
            tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
        } else {
            tlsClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleTLSResult)
        }
    }

    // MARK: XHTTP Reality (TCP → Reality TLS → HTTP/2 → XHTTP → VLESS)

    private func connectXHTTPReality(
        realityConfig: RealityConfiguration,
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let realityClient = RealityClient(configuration: realityConfig)

        let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self, realityClient] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let realityConnection):
                self.realityClient = realityClient
                self.realityConnection = realityConnection

                // Reality + XHTTP uses HTTP/2 (Xray-core dialer.go:80-82)
                let xhttpConnection = XHTTPConnection(
                    tlsConnection: realityConnection,
                    configuration: xhttpConfig,
                    mode: mode,
                    sessionId: sessionId,
                    useHTTP2: true
                )
                self.xhttpConnection = xhttpConnection
                self.performXHTTPSetup(
                    xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData, completion: completion
                )

            case .failure(let error):
                completion(.failure(error))
            }
        }

        if let tunnel {
            realityClient.connect(overTunnel: tunnel, completion: handleRealityResult)
        } else {
            realityClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleRealityResult)
        }
    }

    /// Performs XHTTP setup then sends the protocol handshake.
    private func performXHTTPSetup(
        xhttpConnection: XHTTPConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        xhttpConnection.performSetup { [weak self] error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            let xhttpProxyConnection = XHTTPProxyConnection(xhttpConnection: xhttpConnection)
            self.sendProtocolHandshake(
                over: xhttpProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: false, completion: completion
            )
        }
    }

    // MARK: - Vision

    /// Validates that the outer TLS connection is TLS 1.3 when using Vision flow.
    /// Matches Xray-core `outbound.go` lines 346-355.
    private func validateOuterTLSForVision(_ connection: ProxyConnection) -> Error? {
        guard let version = connection.outerTLSVersion else {
            return ProxyError.protocolError("Vision requires outer TLS or REALITY transport")
        }
        if version != .tls13 {
            return ProxyError.protocolError("Vision requires outer TLS 1.3, found \(version)")
        }
        return nil
    }

    /// Wraps a VLESS connection with the XTLS Vision layer.
    private func wrapWithVision(_ connection: ProxyConnection) -> VLESSVisionConnection {
        let uuidBytes = configuration.uuid.uuid
        let uuidData = Data([
            uuidBytes.0, uuidBytes.1, uuidBytes.2, uuidBytes.3,
            uuidBytes.4, uuidBytes.5, uuidBytes.6, uuidBytes.7,
            uuidBytes.8, uuidBytes.9, uuidBytes.10, uuidBytes.11,
            uuidBytes.12, uuidBytes.13, uuidBytes.14, uuidBytes.15
        ])
        return VLESSVisionConnection(connection: connection, userUUID: uuidData)
    }
    
    // MARK: - Shadowsocks

    /// Whether this client is configured for Shadowsocks outbound.
    private var isShadowsocks: Bool {
        configuration.outboundProtocol == .shadowsocks
    }

    /// Wraps a bare transport connection with Shadowsocks AEAD encryption.
    private func wrapWithShadowsocks(
        inner: ProxyConnection,
        command: ProxyCommand,
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
                    return .success(Shadowsocks2022ChaChaUDPConnection(
                        inner: inner, psk: pskList.last!, dstHost: destinationHost, dstPort: destinationPort
                    ))
                } else {
                    return .success(Shadowsocks2022AESUDPConnection(
                        inner: inner, cipher: cipher, pskList: pskList,
                        dstHost: destinationHost, dstPort: destinationPort
                    ))
                }
            } else {
                let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)
                return .success(Shadowsocks2022Connection(
                    inner: inner, cipher: cipher, pskList: pskList,
                    addressHeader: addressHeader
                ))
            }
        } else {
            // Legacy Shadowsocks: password-based EVP_BytesToKey derivation
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)

            if command == .udp {
                return .success(ShadowsocksUDPConnection(
                    inner: inner, cipher: cipher, masterKey: masterKey,
                    dstHost: destinationHost, dstPort: destinationPort
                ))
            } else {
                return .success(ShadowsocksConnection(
                    inner: inner, cipher: cipher, masterKey: masterKey,
                    addressHeader: addressHeader
                ))
            }
        }
    }
}
