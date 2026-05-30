//
//  ProxyClient.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

/// Counts down `remaining` callbacks and fires `completion` when the last one
/// arrives. Used to fan in async-teardown notifications from a `ProxyClient`'s
/// raw socket plus its chain clients into a single completion.
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

/// Client for establishing proxy connections over TCP or UDP.
///
///
/// Supports multiple transports (TCP, WebSocket, HTTP Upgrade, XHTTP) and security layers
/// (TLS, Reality). For the XTLS Vision flow, the connection is wrapped in a ``VLESSVisionConnection``.
nonisolated class ProxyClient {
    let configuration: ProxyConfiguration
    let useResolvedAddressForDirectDial: Bool
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

    /// For a chain link, the prefix `chain[0..<index]` that brought traffic to
    /// this link's server. Lets the link rebuild that prefix for an extra dial
    /// (e.g. SOCKS5 opening its UDP-ASSOCIATE relay socket). Empty otherwise.
    let parentChain: [ProxyConfiguration]

    /// Creates a new proxy client with the given configuration.
    ///
    /// - Parameters:
    ///   - configuration: The proxy server configuration.
    ///   - tunnel: Optional tunnel from a previous chain link (for proxy chaining).
    ///   - useResolvedAddressForDirectDial: Whether direct first-hop transports should
    ///     prefer `resolvedIP` over `serverAddress`. Intended for latency testing only.
    ///   - parentChain: Chain prefix leading to this link's server. Empty for non-chain-link clients.
    init(
        configuration: ProxyConfiguration,
        tunnel: ProxyConnection? = nil,
        useResolvedAddressForDirectDial: Bool = false,
        parentChain: [ProxyConfiguration] = []
    ) {
        self.configuration = configuration
        self.tunnel = tunnel
        self.useResolvedAddressForDirectDial = useResolvedAddressForDirectDial
        self.parentChain = parentChain
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

        // QUIC-based transports ride the chain's UDP relay as a datagram
        // transport, so they build (or adopt) the chain inside their own
        // protocol-specific dispatch rather than the generic TCP chain below.
        // Hysteria/Nowhere are QUIC end to end; VLESS-over-XHTTP negotiates QUIC
        // only when it selects HTTP/3 (ALPN h3) — see `connectXHTTP3`.
        if configuration.outboundProtocol == .hysteria
            || configuration.outboundProtocol == .nowhere
            || configuration.isXHTTPOverHTTP3 {
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

    /// Per-hop transport commands for a chain wrapped by `outerProtocol`.
    /// Walks backwards from the outer protocol's required upstream command.
    /// Fails when any link can't service what the link above it demands.
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

    /// Variant for chains that don't sit under a wrapping outer protocol;
    /// the caller specifies the last hop's required output transport.
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
                // Config-aware (not just protocol-level): a VLESS hop reached
                // over XHTTP-h3 rides QUIC, so it needs a `.udp` relay from
                // below even though plain VLESS would ask for `.tcp`.
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

    /// Builds a chain tunnel by connecting through each proxy in the chain.
    /// Thin wrapper that supplies instance-state defaults to the self-free
    /// recursive helper.
    ///
    /// - Parameters:
    ///   - chain: The ordered list of chain proxies (outermost first).
    ///   - index: The current chain link index being connected.
    ///   - currentTunnel: The tunnel from the previous chain link (nil for the first).
    ///   - hopCommands: Per-hop transport command (`.tcp` or `.udp`) for each chain link.
    ///   - finalDestination: Overrides the last hop's target (defaults to this proxy's server).
    ///   - track: If set, takes ownership of each created chain-hop client
    ///     instead of appending to `self.chainClients`.
    ///   - completion: Called with the final tunnel connection.
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

    /// Self-free chain build for callers that don't anchor hops in a
    /// `ProxyClient`'s `chainClients` (e.g. the pooled chained Hysteria
    /// path, where ``HysteriaClient`` retains the hops). Surviving the
    /// first caller's lifetime matters because the build is shared across
    /// concurrent `acquireChained` waiters.
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

    /// Self-free recursive hop dispatch. Shared by ``buildChainTunnel``
    /// (instance) and ``buildDetachedChainTunnel`` (static).
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

    /// Cancels the connection and releases all resources. Returns synchronously;
    /// the underlying TCP teardown happens asynchronously. Callers that need
    /// to wait for the file descriptor to actually close should use
    /// ``cancel(completion:)``.
    func cancel() {
        cancel(completion: {})
    }

    /// Awaitable variant of ``cancel()``. Fires `completion` once every
    /// underlying socket (this client's `connection` and any `chainClients`
    /// it owns) has fully torn down — fd closed, dispatch-source cancel
    /// handlers fired. Higher-level wrappers (TLS, WebSocket, gRPC, etc.) are
    /// torn down synchronously here since they don't own fds of their own.
    func cancel(completion: @escaping @Sendable () -> Void) {
        // Synchronous teardown of higher-level wrappers — they don't hold fds
        // directly; their cancels are fast bookkeeping.
        webSocketConnection?.cancel()
        webSocketConnection = nil
        httpUpgradeConnection?.cancel()
        httpUpgradeConnection = nil
        grpcConnection?.cancel()
        grpcConnection = nil
        xhttpConnection?.cancel()
        xhttpConnection = nil
        realityConnection?.cancel()
        realityConnection = nil
        realityClient?.cancel()
        realityClient = nil
        tlsConnection?.cancel()
        tlsConnection = nil
        tlsClient?.cancel()
        tlsClient = nil
        tunnel = nil

        // Awaitable teardowns: the raw socket and any chain clients (each of
        // which owns its own raw socket).
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

    /// Wraps an established transport connection in the appropriate outbound
    /// protocol (VLESS or Shadowsocks) for the requested command. The
    /// per-protocol bodies live in ``ProxyClient+VLESS.swift`` and
    /// ``ProxyClient+Shadowsocks.swift``.
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

        // Only VLESS reaches this point.
        //
        // Vision needs a TLS-1.3-record-like layer to drive its padding /
        // direct-copy state machine, supplied by either VLESS Encryption (any
        // transport) or a raw TCP transport carrying TLS/REALITY — see
        // ``transportSupportsVision``.
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
            // Chained: use tunnel instead of RawTCPSocket
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

    /// Connects using WebSocket transport. Routes to WSS (TLS) or plain WS.
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
            // WSS: TCP → TLS → WebSocket → VLESS
            // Force ALPN to http/1.1 (Xray-core tls.WithNextProto("http/1.1"))
            let wsTlsConfig = TLSConfiguration(
                serverName: baseTLSConfig.serverName,
                alpn: ["http/1.1"],
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
                supportsVision: transportSupportsVision, completion: completion
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
        guard case .httpUpgrade(let huConfig) = configuration.transportLayer else {
            completion(.failure(ProxyError.connectionFailed("HTTP upgrade transport specified but no configuration")))
            return
        }

        if case .tls(let tlsConfiguration) = configuration.securityLayer {
            // HTTPS Upgrade: TCP → TLS → HTTP Upgrade → raw TCP over TLS → VLESS
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
                supportsVision: transportSupportsVision, completion: completion
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
        guard case .grpc(let grpcConfig) = configuration.transportLayer else {
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

        if case .reality(let realityConfig) = configuration.securityLayer {
            // Reality + gRPC: Reality handles its own ALPN internally; layer gRPC on top.
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
            // gRPC over TLS: force ALPN `h2`, handshake, then open the HTTP/2 stream.
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
    ///
    /// - Reality always uses HTTP/2.
    /// - No TLS means plain HTTP/1.1.
    /// - TLS with a single `http/1.1` ALPN stays on HTTP/1.1.
    /// - TLS with a single `h3` ALPN expects QUIC/HTTP/3.
    /// - Everything else uses HTTP/2.
    private func decideXHTTPHTTPVersion() -> XHTTPHTTPVersion {
        if case .reality = configuration.securityLayer {
            return .http2
        }

        guard case .tls(let tlsConfig) = configuration.securityLayer else {
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
        guard case .xhttp(let xhttpConfig) = configuration.transportLayer else {
            completion(.failure(ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")))
            return
        }

        // ALPN "h3" routes XHTTP over HTTP/3-over-QUIC (see connectXHTTP3); every
        // other ALPN uses HTTP/1.1 or HTTP/2 over TCP+TLS.
        let httpVersion = decideXHTTPHTTPVersion()

        // Resolve mode: auto → actual mode
        let resolvedMode: XHTTPMode
        if xhttpConfig.mode == .auto {
            if case .reality = configuration.securityLayer {
                resolvedMode = .streamOne
            } else {
                resolvedMode = .packetUp
            }
        } else {
            resolvedMode = xhttpConfig.mode
        }

        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? UUID().uuidString.lowercased() : ""

        if case .reality(let realityConfig) = configuration.securityLayer {
            connectXHTTPReality(realityConfig: realityConfig, xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
        } else if case .tls(let tlsConfig) = configuration.securityLayer {
            if httpVersion == .http3 {
                // ALPN "h3" selects an HTTP/3 transport, which runs over QUIC (UDP).
                connectXHTTP3(tlsConfig: tlsConfig, xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            } else {
                connectXHTTPS(xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, httpVersion: httpVersion, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData, completion: completion)
            }
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
            // XHTTP requires a TCP stream end-to-end.
            let hopCommands = [ProxyCommand](repeating: .tcp, count: chain.count)
            buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands) { result in
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
        guard case .tls(let baseTLSConfig) = configuration.securityLayer else {
            completion(.failure(ProxyError.connectionFailed("XHTTPS requires TLS configuration")))
            return
        }

        // Keep the original fingerprint/SNI, but do not advertise h3 on the TCP path.
        let tlsConfiguration = sanitizedXHTTPTLSConfiguration(from: baseTLSConfig, httpVersion: httpVersion)
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
                            let hopCommands = [ProxyCommand](repeating: .tcp, count: chain.count)
                            self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands) { tunnelResult in
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
        self.realityClient = realityClient

        let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let realityConnection):
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

    // MARK: XHTTP/3 (QUIC → HTTP/3 → XHTTP → VLESS)

    /// Connects XHTTP over HTTP/3-over-QUIC, used when the TLS ALPN is exactly
    /// `h3`: that ALPN selects an HTTP/3 transport, which runs over QUIC (UDP)
    /// rather than TLS-over-TCP. The TLS 1.3 handshake is performed natively by
    /// the QUIC stack (``QUICTLSHandler``), so no ``TLSClient`` runs here; the
    /// ALPN reaches the wire as the QUIC connection's `["h3"]`.
    ///
    /// Chaining mirrors Hysteria/Nowhere: QUIC rides a ``QUICDatagramTransport``
    /// instead of a kernel socket. As a chain link (`tunnel` set) the inbound
    /// UDP-relay tunnel *is* that transport; as the chain exit (`chain` set) we
    /// build a chain whose last hop opens a `.udp` relay to this server and ride
    /// the result. Direct dials pass `transport: nil` and open a real UDP
    /// socket. Xray-core does the equivalent — its h3 dialer wraps a
    /// `dialerProxy` connection in a `FakePacketConn` for QUIC to ride.
    private func connectXHTTP3(
        tlsConfig: TLSConfiguration,
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        // Builds the XHTTP-over-h3 connection on a QUIC session riding
        // `transport` (nil → direct kernel UDP socket).
        let startSession: (QUICDatagramTransport?) -> Void = { [weak self] transport in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            // Direct dials may target the pre-resolved IP (latency testing);
            // a chained/tunneled session rides the relay, so the host is just
            // the server's logical identity (SNI is passed through explicitly).
            let host = (transport == nil) ? self.directDialHost : self.configuration.serverAddress
            let session = HTTP3Session(
                host: host,
                port: self.configuration.serverPort,
                serverName: tlsConfig.serverName,
                transport: transport
            )
            let xhttpConnection = XHTTPConnection(
                h3Session: session, configuration: xhttpConfig, mode: mode, sessionId: sessionId
            )
            self.xhttpConnection = xhttpConnection
            self.performXHTTPSetup(
                xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData, completion: completion
            )
        }

        // Chain link: the inbound UDP-relay tunnel carries our QUIC datagrams.
        if let tunnel = self.tunnel {
            self.tunnel = nil
            startSession(ProxyConnectionDatagramTransport(connection: tunnel))
            return
        }

        // Chain exit: build a chain whose last hop opens a `.udp` relay to this
        // server, then ride it. Hops are retained in `self.chainClients`.
        if let chain = configuration.chain, !chain.isEmpty {
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
                case .success(let chainTunnel):
                    startSession(ProxyConnectionDatagramTransport(connection: chainTunnel))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
            return
        }

        // Direct: open a real UDP socket inside the QUIC stack.
        startSession(nil)
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
                supportsVision: transportSupportsVision, completion: completion
            )
        }
    }

}
