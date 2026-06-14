//
//  ProxyClient.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

/// Fans in `remaining` async-teardown callbacks into a single `completion`.
private final class TeardownCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var remaining: Int
    private let completion: @Sendable () -> Void

    init(remaining: Int, completion: @escaping @Sendable () -> Void) {
        self.remaining = remaining
        self.completion = completion
    }

    func decrement() {
        lock.lock()
        remaining -= 1
        let done = remaining == 0
        lock.unlock()
        if done { completion() }
    }
}

// MARK: - ProxyClient

/// Establishes proxy connections over the supported transports and security layers.
nonisolated class ProxyClient {
    let configuration: ProxyConfiguration
    let useResolvedAddressForDirectDial: Bool
    var connection: RawTCPSocket?
    private var realityClient: RealityClient?
    private var realityConnection: TLSRecordConnection?
    var tlsClient: TLSClient?
    var tlsConnection: TLSRecordConnection?

    /// Sockets/TLS/Reality clients dialed for XHTTP legs, retained for the connection's lifetime.
    private var retainedXHTTPObjects: [AnyObject] = []
    private var webSocketConnection: WebSocketConnection?
    private var httpUpgradeConnection: HTTPUpgradeConnection?
    private var grpcConnection: GRPCConnection?
    private var xhttpConnection: XHTTPConnection?

    /// Proxy tunnel from a previous chain link (for proxy chaining).
    var tunnel: ProxyConnection?
    private var chainClients: [ProxyClient] = []

    /// For a chain link, the chain prefix leading to this link's server, so it can rebuild
    /// that prefix for an extra dial (e.g. SOCKS5's UDP-ASSOCIATE relay). Empty otherwise.
    let parentChain: [ProxyConfiguration]

    /// Whether this client dials the default outbound, gating the live Dial/Handshake stats;
    /// chain hops, rule-routed proxies, and latency probes leave it `false`.
    let isDefaultProxy: Bool

    init(
        configuration: ProxyConfiguration,
        tunnel: ProxyConnection? = nil,
        useResolvedAddressForDirectDial: Bool = false,
        parentChain: [ProxyConfiguration] = [],
        isDefaultProxy: Bool = false
    ) {
        self.configuration = configuration
        self.tunnel = tunnel
        self.useResolvedAddressForDirectDial = useResolvedAddressForDirectDial
        self.parentChain = parentChain
        self.isDefaultProxy = isDefaultProxy
    }

    /// Host for direct first-hop dials: the hostname normally, the pre-resolved IP for latency tests.
    var directDialHost: String {
        useResolvedAddressForDirectDial ? configuration.connectAddress : configuration.serverAddress
    }

    // MARK: - Public API
    
    var isQUICTransport: Bool {
        configuration.outboundProtocol == .hysteria
            || configuration.outboundProtocol == .nowhere
            || configuration.isXHTTPOverHTTP3
    }
    
    private var poolsQUICSession: Bool {
        configuration.outboundProtocol == .hysteria
            || configuration.outboundProtocol == .nowhere
    }
    
    private func handshakeTimed(
        _ completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) -> (Result<ProxyConnection, Error>) -> Void {
        // Perf span covers every dial (not only the default proxy), stopped on success.
        let span = PerformanceMonitor.span(.proxyHandshake)
        let timed: (Result<ProxyConnection, Error>) -> Void = { result in
            if case .success = result { span.stop() }
            completion(result)
        }
        guard isDefaultProxy else { return timed }
        if poolsQUICSession { return timed }
        let metric: ConnectionMetrics.Metric = isQUICTransport ? .handshakeNoDial : .handshake
        return MetricTimer.timing(metric, timed)
    }
    
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
            completion: handshakeTimed(completion)
        )
    }
    
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
            completion: handshakeTimed(completion)
        )
    }
    
    func connectMux(completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        connectThroughChainIfNeeded(
            command: .mux,
            destinationHost: "v1.mux.cool",
            destinationPort: 666,
            initialData: nil,
            completion: handshakeTimed(completion)
        )
    }
    
    private func connectThroughChainIfNeeded(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let chain = configuration.chain, !chain.isEmpty, tunnel == nil else {
            connectWithCommand(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
            return
        }
        
        if isQUICTransport {
            connectWithCommand(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
            return
        }

        let hopCommands: [ProxyCommand]
        switch Self.computeChainHopCommands(chain: chain, outerProtocol: configuration.outboundProtocol, outerCommand: command) {
        case .success(let computed):
            hopCommands = computed
        case .failure(let error):
            completion(.failure(error))
            return
        }

        buildChainTunnel(
            chain: chain, index: 0, currentTunnel: nil,
            hopCommands: hopCommands
        ) { [weak self] result in
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

    /// Per-hop transport commands for a chain wrapped by `outerProtocol`; fails when a
    /// link can't service what the link above it demands.
    static func computeChainHopCommands(
        chain: [ProxyConfiguration],
        outerProtocol: OutboundProtocol,
        outerCommand: ProxyCommand
    ) -> Result<[ProxyCommand], Error> {
        guard !chain.isEmpty else { return .success([]) }

        guard let lastDeliver = outerProtocol.upstreamCommand(for: outerCommand) else {
            return .failure(ProxyError.protocolError(
                "\(outerProtocol.name) doesn't support \(outerCommand)"
            ))
        }

        return computeChainHopCommands(chain: chain, lastDeliver: lastDeliver)
    }

    /// Variant for chains without a wrapping outer protocol; the caller specifies the last hop's output.
    static func computeChainHopCommands(
        chain: [ProxyConfiguration],
        lastDeliver: ProxyCommand
    ) -> Result<[ProxyCommand], Error> {
        guard !chain.isEmpty else { return .success([]) }

        var commands = [ProxyCommand](repeating: .tcp, count: chain.count)
        commands[chain.count - 1] = lastDeliver

        if chain.count > 1 {
            for i in stride(from: chain.count - 2, through: 0, by: -1) {
                let nextHop = chain[i + 1]
                let downstreamCmd = commands[i + 1]
                // Config-aware: a VLESS hop over XHTTP-h3 rides QUIC, so it needs .udp from below.
                guard let req = nextHop.upstreamCommand(for: downstreamCmd) else {
                    return .failure(ProxyError.protocolError(
                        "Chain hop \(nextHop.outboundProtocol.name) doesn't support \(downstreamCmd) downstream — needed by the hop above it"
                    ))
                }
                commands[i] = req
            }
        }
        return .success(commands)
    }

    func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16)? = nil,
        track: ((ProxyClient) -> Void)? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let resolvedDestination: (host: String, port: UInt16) = finalDestination
            ?? (host: configuration.serverAddress, port: configuration.serverPort)
        let resolvedTrack: (ProxyClient) -> Void = track ?? { [weak self] client in
            self?.chainClients.append(client)
        }
        Self.dispatchChainHop(
            chain: chain,
            index: index,
            currentTunnel: currentTunnel,
            hopCommands: hopCommands,
            finalDestination: resolvedDestination,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            track: resolvedTrack,
            completion: completion
        )
    }

    /// Chain build for pooled transports where the pool retains the hops and the
    /// build may outlive the first caller.
    static func buildDetachedChainTunnel(
        chain: [ProxyConfiguration],
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        dispatchChainHop(
            chain: chain,
            index: 0,
            currentTunnel: nil,
            hopCommands: hopCommands,
            finalDestination: finalDestination,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            track: track,
            completion: completion
        )
    }

    /// Self-free recursive hop dispatch shared by the instance and detached chain builders.
    private static func dispatchChainHop(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let chainConfig = chain[index]
        let isLastHop = (index + 1 == chain.count)

        let nextHost: String
        let nextPort: UInt16
        if !isLastHop {
            nextHost = chain[index + 1].serverAddress
            nextPort = chain[index + 1].serverPort
        } else {
            nextHost = finalDestination.host
            nextPort = finalDestination.port
        }

        let chainClient = ProxyClient(
            configuration: chainConfig,
            tunnel: currentTunnel,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            parentChain: Array(chain[0..<index])
        )
        track(chainClient)

        let hopCompletion: (Result<ProxyConnection, Error>) -> Void = { result in
            switch result {
            case .success(let connection):
                if !isLastHop {
                    dispatchChainHop(
                        chain: chain, index: index + 1, currentTunnel: connection,
                        hopCommands: hopCommands,
                        finalDestination: finalDestination,
                        useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
                        track: track,
                        completion: completion
                    )
                } else {
                    completion(.success(connection))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }

        let hopCommand = hopCommands[index]
        if hopCommand == .udp {
            chainClient.connectUDP(to: nextHost, port: nextPort, completion: hopCompletion)
        } else {
            chainClient.connect(to: nextHost, port: nextPort, completion: hopCompletion)
        }
    }

    func cancel() {
        cancel(completion: {})
    }

    /// Fires `completion` once every underlying socket has fully torn down (fd closed).
    func cancel(completion: @escaping @Sendable () -> Void) {
        // Higher-level wrappers don't hold fds — teardown is synchronous bookkeeping.
        webSocketConnection?.cancel()
        webSocketConnection = nil
        httpUpgradeConnection?.cancel()
        httpUpgradeConnection = nil
        grpcConnection?.cancel()
        grpcConnection = nil
        xhttpConnection?.cancel()
        xhttpConnection = nil
        // XHTTP sockets are torn down via xhttpConnection.cancel(); just drop the references.
        retainedXHTTPObjects.removeAll()
        realityConnection?.cancel()
        realityConnection = nil
        realityClient?.cancel()
        realityClient = nil
        tlsConnection?.cancel()
        tlsConnection = nil
        tlsClient?.cancel()
        tlsClient = nil
        tunnel = nil

        // Awaitable teardowns: the raw socket and each chain client (each owns its own raw socket).
        let socket = connection
        connection = nil
        let chains = chainClients
        chainClients.removeAll()

        let total = (socket != nil ? 1 : 0) + chains.count
        if total == 0 {
            completion()
            return
        }

        let counter = TeardownCounter(remaining: total, completion: completion)
        socket?.forceCancel { counter.decrement() }
        for client in chains {
            client.cancel { counter.decrement() }
        }
    }

    // MARK: - Protocol Handshake

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
            sendShadowsocksProtocolHandshake(
                over: connection,
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                completion: completion
            )
        } else {
            sendVLESSProtocolHandshake(
                over: connection,
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                supportsVision: supportsVision,
                completion: completion
            )
        }
    }

    // MARK: - Connection Routing

    private func connectWithCommand(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        // Vision silently drops UDP/443 (QUIC).
        if command == .udp && destinationPort == 443 && isVisionFlow {
            completion(.failure(ProxyError.dropped))
            return
        }

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

        if configuration.outboundProtocol == .nowhere {
            connectWithNowhere(
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

        if configuration.outboundProtocol == .anytls {
            connectWithAnyTLS(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
            return
        }

        if isShadowsocks {
            if command == .udp {
                connectShadowsocksRealUDP(
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    completion: completion
                )
                return
            }
            connectDirect(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            return
        }

        if configuration.outboundProtocol == .socks5 {
            connectWithSOCKS5(command: command, destinationHost: destinationHost, destinationPort: destinationPort, completion: completion)
            return
        }

        if configuration.outboundProtocol == .sudoku {
            connectWithSudoku(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
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

        // Only VLESS reaches this point; Vision needs a TLS-record-like layer
        // (VLESS Encryption, or a raw TCP transport carrying TLS/Reality).
        switch configuration.transportLayer {
        case .ws:
            connectWithWebSocket(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .httpUpgrade:
            connectWithHTTPUpgrade(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .grpc:
            connectWithGRPC(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .xhttp:
            connectWithXHTTP(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        case .tcp:
            switch configuration.securityLayer {
            case .tls(let tlsConfig):
                connectWithTLS(tlsConfig: tlsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            case .reality(let realityConfig):
                connectWithReality(realityConfig: realityConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            case .none:
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
            let directProxyConnection = DirectProxyConnection(connection: TunneledTransport(tunnel: tunnel))
            sendProtocolHandshake(
                over: directProxyConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData,
                supportsVision: transportSupportsVision, completion: completion
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
                    supportsVision: transportSupportsVision, completion: completion
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
        self.tlsClient = tlsClient

        let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let tlsConnection):
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
        self.realityClient = realityClient

        let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let realityConnection):
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

    private func connectWithWebSocket(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .ws(let wsConfig) = configuration.transportLayer else {
            completion(.failure(ProxyError.connectionFailed("WebSocket transport specified but no WebSocket configuration")))
            return
        }

        if case .tls(let baseTLSConfig) = configuration.securityLayer {
            // Force ALPN to http/1.1 (Xray-core tls.WithNextProto("http/1.1")).
            let wsTlsConfig = TLSConfiguration(
                serverName: baseTLSConfig.serverName,
                alpn: ["http/1.1"],
                echConfig: baseTLSConfig.echConfig,
                fingerprint: baseTLSConfig.fingerprint
            )
            let tlsClient = TLSClient(configuration: wsTlsConfig)
            self.tlsClient = tlsClient

            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tlsConnection):
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
                let wsConnection = WebSocketConnection(tunnel: tunnel, configuration: wsConfig)
                performWebSocketUpgrade(
                    wsConnection: wsConnection, command: command, destinationHost: destinationHost,
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
                    let wsConnection = WebSocketConnection(transport: transport, configuration: wsConfig)
                    self.performWebSocketUpgrade(
                        wsConnection: wsConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                }
            }
        }
    }

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
                supportsVision: transportSupportsVision, completion: completion
            )
        }
    }

    // MARK: - HTTP Upgrade Connection

    private func connectWithHTTPUpgrade(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .httpUpgrade(let huConfig) = configuration.transportLayer else {
            completion(.failure(ProxyError.connectionFailed("HTTP upgrade transport specified but no configuration")))
            return
        }

        if case .tls(let tlsConfiguration) = configuration.securityLayer {
            let tlsClient = TLSClient(configuration: tlsConfiguration)
            self.tlsClient = tlsClient

            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tlsConnection):
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
                let huConnection = HTTPUpgradeConnection(tunnel: tunnel, configuration: huConfig)
                performHTTPUpgrade(
                    huConnection: huConnection, command: command, destinationHost: destinationHost,
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
                    let huConnection = HTTPUpgradeConnection(transport: transport, configuration: huConfig)
                    self.performHTTPUpgrade(
                        huConnection: huConnection, command: command, destinationHost: destinationHost,
                        destinationPort: destinationPort, initialData: initialData, completion: completion
                    )
                }
            }
        }
    }

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
                supportsVision: transportSupportsVision, completion: completion
            )
        }
    }

    // MARK: - gRPC Connection

    /// ALPN is forced to `h2` because gRPC requires HTTP/2.
    private func sanitizedGRPCTLSConfiguration(from base: TLSConfiguration) -> TLSConfiguration {
        TLSConfiguration(
            serverName: base.serverName,
            alpn: ["h2"],
            echConfig: base.echConfig,
            fingerprint: base.fingerprint
        )
    }

    private func connectWithGRPC(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .grpc(let grpcConfig) = configuration.transportLayer else {
            completion(.failure(ProxyError.connectionFailed("gRPC transport specified but no gRPC configuration")))
            return
        }

        // The :authority falls back to the TLS/Reality SNI when no override is configured.
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

        if case .reality(let realityConfig) = configuration.securityLayer {
            // Reality handles its own ALPN internally; layer gRPC on top.
            let realityClient = RealityClient(configuration: realityConfig)
            self.realityClient = realityClient

            let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let realityConnection):
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

        if case .tls(let baseTLSConfig) = configuration.securityLayer {
            let grpcTLSConfig = sanitizedGRPCTLSConfiguration(from: baseTLSConfig)
            let tlsClient = TLSClient(configuration: grpcTLSConfig)
            self.tlsClient = tlsClient

            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tlsConnection):
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
                supportsVision: transportSupportsVision, completion: completion
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
    private func decideXHTTPHTTPVersion(for securityLayer: SecurityLayer? = nil) -> XHTTPHTTPVersion {
        let security = securityLayer ?? configuration.securityLayer
        if case .reality = security {
            return .http2
        }

        guard case .tls(let tlsConfig) = security else {
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

    /// Strips ALPN entries (e.g. `h3`) that the chosen HTTP version can't satisfy over TCP.
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
            echConfig: base.echConfig,
            fingerprint: base.fingerprint
        )
    }

    /// Mode and HTTP version resolution follow Xray-core's split HTTP dialer.
    private func connectWithXHTTP(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .xhttp(let xhttpConfig) = configuration.transportLayer else {
            completion(.failure(ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")))
            return
        }

        let httpVersion = decideXHTTPHTTPVersion()

        var resolvedMode: XHTTPMode
        if xhttpConfig.mode == .auto {
            if case .reality = configuration.securityLayer {
                resolvedMode = .streamOne
            } else {
                resolvedMode = .packetUp
            }
        } else {
            resolvedMode = xhttpConfig.mode
        }

        // Up/download detach splits GET and POST across servers, correlated by a shared
        // session ID; stream-one can't split, so promote it to stream-up.
        if let downloadSettings = xhttpConfig.downloadSettings {
            if resolvedMode == .streamOne { resolvedMode = .streamUp }
            let downloadHTTPVersion = decideXHTTPHTTPVersion(for: downloadSettings.securityLayer)
            connectXHTTPDetached(
                xhttpConfig: xhttpConfig, downloadSettings: downloadSettings,
                mode: resolvedMode, sessionId: xhttpConfig.generateSessionID(),
                mainHTTPVersion: httpVersion, downloadHTTPVersion: downloadHTTPVersion,
                command: command, destinationHost: destinationHost, destinationPort: destinationPort,
                initialData: initialData, completion: completion
            )
            return
        }

        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? xhttpConfig.generateSessionID() : ""
        connectXHTTPCombined(
            xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, httpVersion: httpVersion,
            command: command, destinationHost: destinationHost, destinationPort: destinationPort,
            initialData: initialData, completion: completion
        )
    }

    // MARK: Combined XHTTP (single server)

    /// HTTP/1.1 can't multiplex, so packet-up/stream-up dial a second connection for
    /// the upload POST; HTTP/2 and HTTP/3 carry both directions over one transport.
    private func connectXHTTPCombined(
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
        let route = consumeMainXHTTPRoute()
        let needsUploadFactory = httpVersion == .http11 && (mode == .packetUp || mode == .streamUp)
        let uploadFactory = needsUploadFactory
            ? makeXHTTPUploadFactory(security: configuration.securityLayer, httpVersion: httpVersion)
            : nil
        dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(), httpVersion: httpVersion, route: route,
            xhttp: xhttpConfig, mode: mode, sessionId: sessionId, role: .combined, uploadFactory: uploadFactory
        ) { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let xhttpConnection):
                self.xhttpConnection = xhttpConnection
                self.performXHTTPSetup(
                    xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
                    destinationPort: destinationPort, initialData: initialData, completion: completion
                )
            }
        }
    }

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
                supportsVision: transportSupportsVision, completion: completion
            )
        }
    }

    // MARK: XHTTP up/download detach

    /// Dials separate upload (POST) and download (GET) legs joined by a shared session ID.
    /// The download leg is the coordinator and always dials its own server directly.
    private func connectXHTTPDetached(
        xhttpConfig: XHTTPConfiguration,
        downloadSettings: XHTTPDownloadSettings,
        mode: XHTTPMode,
        sessionId: String,
        mainHTTPVersion: XHTTPHTTPVersion,
        downloadHTTPVersion: XHTTPHTTPVersion,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let uploadRoute = consumeMainXHTTPRoute()
        dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(), httpVersion: mainHTTPVersion, route: uploadRoute,
            xhttp: xhttpConfig, mode: mode, sessionId: sessionId, role: .uploadOnly, uploadFactory: nil
        ) { [weak self] uploadResult in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch uploadResult {
            case .failure(let error):
                completion(.failure(error))
            case .success(let uploadLeg):
                self.dialXHTTPLeg(
                    endpoint: self.downloadXHTTPEndpoint(downloadSettings), httpVersion: downloadHTTPVersion,
                    route: .direct, xhttp: downloadSettings.xhttp, mode: mode, sessionId: sessionId,
                    role: .downloadOnly, uploadFactory: nil
                ) { [weak self] downloadResult in
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    switch downloadResult {
                    case .failure(let error):
                        // The upload leg never joined xhttpConnection, so a later cancel()
                        // can't reach it — tear it down here to avoid a leak.
                        uploadLeg.cancel()
                        completion(.failure(error))
                    case .success(let downloadLeg):
                        // Download leg is the coordinator; it owns the upload leg.
                        downloadLeg.uploadChannel = uploadLeg
                        self.xhttpConnection = downloadLeg
                        self.performXHTTPSetup(
                            xhttpConnection: downloadLeg, command: command,
                            destinationHost: destinationHost, destinationPort: destinationPort,
                            initialData: initialData, completion: completion
                        )
                    }
                }
            }
        }
    }

    // MARK: XHTTP leg factory (shared by combined & detach)

    /// Where one XHTTP leg's server lives and how the connection to it is secured.
    private struct XHTTPEndpoint {
        /// Host for a direct kernel dial (a pre-resolved IP when latency testing).
        let directHost: String
        /// Logical server identity, used as the HTTP/3 host when chained.
        let chainHost: String
        /// SNI / HTTP/3 server name.
        let serverName: String
        let port: UInt16
        let security: SecurityLayer
    }

    /// How an XHTTP leg reaches its server.
    private enum XHTTPLegRoute {
        case direct
        case overTunnel(ProxyConnection)
        case buildChain([ProxyConfiguration])
    }

    /// The dialed transport for one XHTTP leg: a byte stream or an HTTP/3 QUIC session.
    private enum XHTTPDialedTransport {
        case byteStream(TransportClosures)
        case http3(HTTP3Session)
    }

    private func mainXHTTPEndpoint() -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: directDialHost,
            chainHost: configuration.serverAddress,
            serverName: configuration.securityLayer.serverName(fallback: configuration.serverAddress),
            port: configuration.serverPort,
            security: configuration.securityLayer
        )
    }

    private func downloadXHTTPEndpoint(_ downloadSettings: XHTTPDownloadSettings) -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: downloadSettings.serverAddress,
            chainHost: downloadSettings.serverAddress,
            serverName: downloadSettings.securityLayer.serverName(fallback: downloadSettings.serverAddress),
            port: downloadSettings.serverPort,
            security: downloadSettings.securityLayer
        )
    }

    /// Resolves the main leg's route, consuming `self.tunnel` so it is dialed exactly once.
    private func consumeMainXHTTPRoute() -> XHTTPLegRoute {
        if let tunnel = self.tunnel {
            self.tunnel = nil
            return .overTunnel(tunnel)
        }
        if let chain = configuration.chain, !chain.isEmpty {
            return .buildChain(chain)
        }
        return .direct
    }

    /// Dials one XHTTP leg and wraps it in an `XHTTPConnection` with the given role.
    private func dialXHTTPLeg(
        endpoint: XHTTPEndpoint,
        httpVersion: XHTTPHTTPVersion,
        route: XHTTPLegRoute,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole,
        uploadFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)?,
        completion: @escaping (Result<XHTTPConnection, Error>) -> Void
    ) {
        dialXHTTPTransport(endpoint: endpoint, httpVersion: httpVersion, route: route) { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let transport):
                let connection: XHTTPConnection
                switch transport {
                case .byteStream(let closures):
                    connection = XHTTPConnection(
                        download: closures, configuration: xhttp, mode: mode, sessionId: sessionId,
                        useHTTP2: httpVersion == .http2, uploadConnectionFactory: uploadFactory
                    )
                case .http3(let session):
                    connection = XHTTPConnection(
                        h3Session: session, configuration: xhttp, mode: mode, sessionId: sessionId
                    )
                }
                connection.role = role
                completion(.success(connection))
            }
        }
    }

    /// HTTP/1.1 and HTTP/2 ride a byte stream; HTTP/3 rides a QUIC session whose
    /// datagram transport encodes the route.
    private func dialXHTTPTransport(
        endpoint: XHTTPEndpoint,
        httpVersion: XHTTPHTTPVersion,
        route: XHTTPLegRoute,
        completion: @escaping (Result<XHTTPDialedTransport, Error>) -> Void
    ) {
        if httpVersion == .http3 {
            dialXHTTPHTTP3Session(endpoint: endpoint, route: route, completion: completion)
            return
        }
        switch route {
        case .direct:
            dialXHTTPByteStream(host: endpoint.directHost, port: endpoint.port, security: endpoint.security,
                                httpVersion: httpVersion, overTunnel: nil, completion: completion)
        case .overTunnel(let tunnel):
            dialXHTTPByteStream(host: endpoint.chainHost, port: endpoint.port, security: endpoint.security,
                                httpVersion: httpVersion, overTunnel: tunnel, completion: completion)
        case .buildChain(let chain):
            // XHTTP requires a TCP stream end-to-end.
            let hopCommands = [ProxyCommand](repeating: .tcp, count: chain.count)
            buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands) { [weak self] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let tunnel):
                    self.dialXHTTPByteStream(host: endpoint.chainHost, port: endpoint.port, security: endpoint.security,
                                             httpVersion: httpVersion, overTunnel: tunnel, completion: completion)
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    private func dialXHTTPByteStream(
        host: String,
        port: UInt16,
        security: SecurityLayer,
        httpVersion: XHTTPHTTPVersion,
        overTunnel: ProxyConnection?,
        completion: @escaping (Result<XHTTPDialedTransport, Error>) -> Void
    ) {
        switch security {
        case .none:
            if let tunnel = overTunnel {
                completion(.success(.byteStream(TransportClosures(tunnel: tunnel))))
            } else {
                let socket = RawTCPSocket()
                retainedXHTTPObjects.append(socket)
                socket.connect(host: host, port: port) { error in
                    if let error { completion(.failure(error)); return }
                    completion(.success(.byteStream(TransportClosures(rawTCP: socket))))
                }
            }
        case .tls(let tlsConfig):
            let client = TLSClient(configuration: sanitizedXHTTPTLSConfiguration(from: tlsConfig, httpVersion: httpVersion))
            retainedXHTTPObjects.append(client)
            let handle: (Result<TLSRecordConnection, Error>) -> Void = { result in
                completion(result.map { .byteStream(TransportClosures(tls: $0)) })
            }
            if let tunnel = overTunnel {
                client.connect(overTunnel: tunnel, completion: handle)
            } else {
                client.connect(host: host, port: port, completion: handle)
            }
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            retainedXHTTPObjects.append(client)
            let handle: (Result<TLSRecordConnection, Error>) -> Void = { result in
                completion(result.map { .byteStream(TransportClosures(tls: $0)) })
            }
            if let tunnel = overTunnel {
                client.connect(overTunnel: tunnel, completion: handle)
            } else {
                client.connect(host: host, port: port, completion: handle)
            }
        }
    }

    /// QUIC performs TLS natively, so the route is encoded as the session's datagram
    /// transport instead of a TLS/Reality client.
    private func dialXHTTPHTTP3Session(
        endpoint: XHTTPEndpoint,
        route: XHTTPLegRoute,
        completion: @escaping (Result<XHTTPDialedTransport, Error>) -> Void
    ) {
        let makeSession: (String, QUICDatagramTransport?) -> XHTTPDialedTransport = { host, transport in
            .http3(HTTP3Session(host: host, port: endpoint.port, serverName: endpoint.serverName, transport: transport))
        }
        switch route {
        case .direct:
            completion(.success(makeSession(endpoint.directHost, nil)))
        case .overTunnel(let tunnel):
            completion(.success(makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))))
        case .buildChain(let chain):
            let hopCommands: [ProxyCommand]
            switch Self.computeChainHopCommands(chain: chain, lastDeliver: .udp) {
            case .success(let cmds):
                hopCommands = cmds
            case .failure(let error):
                completion(.failure(error))
                return
            }
            buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands) { result in
                switch result {
                case .success(let tunnel):
                    completion(.success(makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    /// Upload-connection factory for combined HTTP/1.1 sessions; the download leg already
    /// consumed any inbound tunnel, so this routes direct or through a fresh chain.
    private func makeXHTTPUploadFactory(
        security: SecurityLayer,
        httpVersion: XHTTPHTTPVersion
    ) -> (@escaping (Result<TransportClosures, Error>) -> Void) -> Void {
        return { [weak self] completion in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            let route: XHTTPLegRoute
            if let chain = self.configuration.chain, !chain.isEmpty {
                route = .buildChain(chain)
            } else {
                route = .direct
            }
            self.dialXHTTPTransport(endpoint: self.mainXHTTPEndpoint(), httpVersion: httpVersion, route: route) { result in
                switch result {
                case .success(.byteStream(let closures)):
                    completion(.success(closures))
                case .success(.http3):
                    completion(.failure(ProxyError.connectionFailed("HTTP/3 has no separate upload connection")))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

}
