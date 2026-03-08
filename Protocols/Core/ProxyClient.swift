//
//  ProxyClient.swift
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
///
/// Supports multiple transports (TCP, WebSocket, HTTP Upgrade, XHTTP) and security layers
/// (TLS, Reality). For the XTLS Vision flow, the connection is wrapped in a ``VLESSVisionConnection``.
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

    /// Proxy tunnel from a previous chain link (for proxy chaining).
    /// When set, all transport connections use this tunnel instead of creating a ``BSDSocket``.
    private var tunnel: ProxyConnection?
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
    init(configuration: ProxyConfiguration, tunnel: ProxyConnection? = nil) {
        self.configuration = configuration
        self.tunnel = tunnel
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
        command: VLESSCommand,
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

        let chainClient = ProxyClient(configuration: chainConfig, tunnel: currentTunnel)
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
        // Cancel chain link clients
        for client in chainClients { client.cancel() }
        chainClients.removeAll()
        tunnel = nil
    }

    // MARK: - Protocol Handshake

    /// Sends the VLESS or Shadowsocks protocol handshake over an established transport connection.
    ///
    /// For UDP commands, wraps the connection with ``UDPProxyConnection``.
    /// For Vision flow, validates TLS 1.3 and wraps with ``VLESSVisionConnection``.
    private func sendProtocolHandshake(
        over connection: ProxyConnection,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        supportsVision: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        // Shadowsocks wraps the TCP connection directly (handles UDP internally)
        if isShadowsocks {
            connection.responseHeaderReceived = true
            completion(wrapWithShadowsocks(
                inner: connection, command: command,
                destinationHost: destinationHost, destinationPort: destinationPort
            ))
            return
        }

        // VLESS path
        let isVision = supportsVision && isVisionFlow && (command == .tcp || command == .mux)

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

        connection.sendRaw(data: requestData) { [weak self] error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            // Wrap for UDP (VLESS uses length-prefixed framing)
            var conn: ProxyConnection = connection
            if command == .udp {
                conn = UDPProxyConnection(inner: connection)
            }

            if isVision {
                if let tlsError = self.validateOuterTLSForVision(conn) {
                    completion(.failure(tlsError))
                    return
                }
                let vision = self.wrapWithVision(conn)
                if let initialData {
                    vision.send(data: initialData)
                } else {
                    vision.sendEmptyPadding()
                }
                completion(.success(vision))
            } else {
                completion(.success(conn))
            }
        }
    }

    // MARK: - Connection Routing

    /// Routes the connection through the appropriate transport and security layers.
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

        // SS restrictions: no Mux, no Reality
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
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over WebSocket transport")))
                return
            }
            connectWithWebSocket(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if configuration.transport == "httpupgrade" {
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over HTTP upgrade transport")))
                return
            }
            connectWithHTTPUpgrade(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if configuration.transport == "xhttp" {
            if isVisionFlow {
                completion(.failure(ProxyError.protocolError("Vision flow is not supported over XHTTP transport")))
                return
            }
            connectWithXHTTP(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if let tlsConfig = configuration.tls {
            connectWithTLS(tlsConfig: tlsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if let realityConfig = configuration.reality {
            connectWithReality(realityConfig: realityConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else {
            connectDirect(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        }
    }

    // MARK: - Direct Connection

    private func connectDirect(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if let tunnel = self.tunnel {
            // Chained: use tunnel instead of BSDSocket
            let directProxyConnection = DirectProxyConnection(connection: TunneledTransport(tunnel: tunnel))
            sendProtocolHandshake(
                over: directProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: true, completion: completion
            )
        } else {
            let socket = BSDSocket()
            self.connection = socket

            socket.connect(host: configuration.serverAddress, port: configuration.serverPort, queue: .global()) { [weak self] error in
                if let error {
                    completion(.failure(error))
                    return
                }
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                let directProxyConnection = DirectProxyConnection(connection: socket)
                self.sendProtocolHandshake(
                    over: directProxyConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData,
                    supportsVision: true, completion: completion
                )
            }
        }
    }

    // MARK: - TLS Connection

    private func connectWithTLS(
        tlsConfig: TLSConfiguration,
        command: VLESSCommand,
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
            tlsClient.connect(host: configuration.serverAddress, port: configuration.serverPort, completion: handleTLSResult)
        }
    }

    // MARK: - Reality Connection

    private func connectWithReality(
        realityConfig: RealityConfiguration,
        command: VLESSCommand,
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
            realityClient.connect(host: configuration.serverAddress, port: configuration.serverPort, completion: handleRealityResult)
        }
    }

    // MARK: - WebSocket Connection

    /// Connects using WebSocket transport. Routes to WSS (TLS) or plain WS.
    private func connectWithWebSocket(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let wsConfig = configuration.websocket else {
            completion(.failure(ProxyError.connectionFailed("WebSocket transport specified but no WebSocket configuration")))
            return
        }

        let useTLS = configuration.tls != nil

        if let baseTLSConfig = configuration.tls {
            // WSS: TCP → TLS → WebSocket → VLESS
            // Force ALPN to http/1.1 (Xray-core tls.WithNextProto("http/1.1"))
            let wsTlsConfig = TLSConfiguration(
                serverName: baseTLSConfig.serverName,
                alpn: ["http/1.1"],
                allowInsecure: baseTLSConfig.allowInsecure,
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
                tlsClient.connect(host: configuration.serverAddress, port: configuration.serverPort, completion: handleTLSResult)
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
                let socket = BSDSocket()
                self.connection = socket

                socket.connect(host: configuration.serverAddress, port: configuration.serverPort, queue: .global()) { [weak self] error in
                    if let error {
                        completion(.failure(error))
                        return
                    }
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    let wsConnection = WebSocketConnection(socket: socket, configuration: wsConfig)
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
        command: VLESSCommand,
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
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let huConfig = configuration.httpUpgrade else {
            completion(.failure(ProxyError.connectionFailed("HTTP upgrade transport specified but no configuration")))
            return
        }

        let useTLS = configuration.tls != nil

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
                tlsClient.connect(host: configuration.serverAddress, port: configuration.serverPort, completion: handleTLSResult)
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
                let socket = BSDSocket()
                self.connection = socket

                socket.connect(host: configuration.serverAddress, port: configuration.serverPort, queue: .global()) { [weak self] error in
                    if let error {
                        completion(.failure(error))
                        return
                    }
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    let huConnection = HTTPUpgradeConnection(socket: socket, configuration: huConfig)
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
        command: VLESSCommand,
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

    // MARK: - XHTTP Connection

    /// Connects using XHTTP transport. Routes to plain HTTP, HTTPS, or Reality.
    ///
    /// Mode auto-resolution (matching Xray-core dialer.go:280-289):
    /// - Reality → stream-one with HTTP/2
    /// - TLS/none → packet-up (CDN-safe, GET + POST over HTTP/1.1)
    private func connectWithXHTTP(
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let xhttpConfig = configuration.xhttp else {
            completion(.failure(ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")))
            return
        }

        // Resolve mode: auto → actual mode based on security
        let resolvedMode: XHTTPMode
        if xhttpConfig.mode == .auto {
            resolvedMode = configuration.reality != nil ? .streamOne : .packetUp
        } else {
            resolvedMode = xhttpConfig.mode
        }

        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? UUID().uuidString : ""

        if let realityConfig = configuration.reality {
            connectXHTTPReality(realityConfig: realityConfig, xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if configuration.tls != nil {
            connectXHTTPS(xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else {
            connectXHTTPPlain(xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        }
    }

    // MARK: Plain XHTTP (TCP → XHTTP → VLESS)

    private func connectXHTTPPlain(
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: VLESSCommand,
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
                xhttpConnection = XHTTPConnection(socket: transport as! BSDSocket, configuration: xhttpConfig, mode: mode, sessionId: sessionId, uploadConnectionFactory: uploadFactory)
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
            let socket = BSDSocket()
            self.connection = socket
            socket.connect(host: configuration.serverAddress, port: configuration.serverPort, queue: .global()) { error in
                if let error {
                    completion(.failure(error))
                    return
                }
                setupXHTTP(socket)
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
                    factoryCompletion(.success(TransportClosures(
                        send: { data, completion in uploadTunnel.sendRaw(data: data, completion: completion) },
                        receive: { completion in
                            uploadTunnel.receiveRaw { data, error in
                                if let error { completion(nil, true, error) }
                                else if let data, !data.isEmpty { completion(data, false, nil) }
                                else { completion(nil, true, nil) }
                            }
                        },
                        cancel: { uploadTunnel.cancel() }
                    )))
                case .failure(let error):
                    factoryCompletion(.failure(error))
                }
            }
        } else {
            let uploadSocket = BSDSocket()
            uploadSocket.connect(host: configuration.serverAddress, port: configuration.serverPort, queue: .global()) { error in
                if let error {
                    factoryCompletion(.failure(error))
                    return
                }
                factoryCompletion(.success(TransportClosures(
                    send: { data, completion in uploadSocket.send(data: data, completion: completion) },
                    receive: { completion in uploadSocket.receive(maximumLength: 65536, completion: completion) },
                    cancel: { uploadSocket.forceCancel() }
                )))
            }
        }
    }

    // MARK: XHTTPS (TCP → TLS → XHTTP → VLESS)

    private func connectXHTTPS(
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: VLESSCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let baseTLSConfig = configuration.tls else {
            completion(.failure(ProxyError.connectionFailed("XHTTPS requires TLS configuration")))
            return
        }

        // Force ALPN to http/1.1 for XHTTP over TLS
        let tlsConfiguration = TLSConfiguration(
            serverName: baseTLSConfig.serverName,
            alpn: ["http/1.1"],
            allowInsecure: baseTLSConfig.allowInsecure,
            fingerprint: baseTLSConfig.fingerprint
        )

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

                // Upload connection factory for packet-up and stream-up modes
                let needsUpload = mode == .packetUp || mode == .streamUp
                let uploadFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = needsUpload ? { [weak self] factoryCompletion in
                    guard let self else {
                        factoryCompletion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    // Use same http/1.1-forced TLS configuration for upload connection
                    let uploadTLSClient = TLSClient(configuration: tlsConfiguration)
                    if let chain = self.configuration.chain, !chain.isEmpty {
                        self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil) { tunnelResult in
                            switch tunnelResult {
                            case .success(let uploadTunnel):
                                uploadTLSClient.connect(overTunnel: uploadTunnel) { result in
                                    switch result {
                                    case .success(let uploadTLSConnection):
                                        factoryCompletion(.success(TransportClosures(
                                            send: { data, completion in uploadTLSConnection.send(data: data, completion: completion) },
                                            receive: { completion in uploadTLSConnection.receive { data, error in completion(data, false, error) } },
                                            cancel: { uploadTLSConnection.cancel() }
                                        )))
                                    case .failure(let error):
                                        factoryCompletion(.failure(error))
                                    }
                                }
                            case .failure(let error):
                                factoryCompletion(.failure(error))
                            }
                        }
                    } else {
                        uploadTLSClient.connect(host: self.configuration.serverAddress, port: self.configuration.serverPort) { result in
                            switch result {
                            case .success(let uploadTLSConnection):
                                factoryCompletion(.success(TransportClosures(
                                    send: { data, completion in uploadTLSConnection.send(data: data, completion: completion) },
                                    receive: { completion in uploadTLSConnection.receive { data, error in completion(data, false, error) } },
                                    cancel: { uploadTLSConnection.cancel() }
                                )))
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

            case .failure(let error):
                completion(.failure(error))
            }
        }

        if let tunnel = self.tunnel {
            tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
        } else {
            tlsClient.connect(host: configuration.serverAddress, port: configuration.serverPort, completion: handleTLSResult)
        }
    }

    // MARK: XHTTP Reality (TCP → Reality TLS → HTTP/2 → XHTTP → VLESS)

    private func connectXHTTPReality(
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
            realityClient.connect(host: configuration.serverAddress, port: configuration.serverPort, completion: handleRealityResult)
        }
    }

    /// Performs XHTTP setup then sends the protocol handshake.
    private func performXHTTPSetup(
        xhttpConnection: XHTTPConnection,
        command: VLESSCommand,
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
        guard let version = connection.outerTLSVersion else { return nil }
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
        return VLESSVisionConnection(connection: connection, userUUID: uuidData, testseed: configuration.testseed)
    }

    // MARK: - Shadowsocks

    /// Whether this client is configured for Shadowsocks outbound.
    private var isShadowsocks: Bool {
        configuration.outboundProtocol == .shadowsocks
    }

    /// Wraps a bare transport connection with Shadowsocks AEAD encryption.
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
