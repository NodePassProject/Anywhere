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

    /// Sockets/TLS/Reality clients dialed for an XHTTP connection — the single
    /// combined leg, or both legs of an up/download-detached session. Retained
    /// here for the connection's lifetime; released when the ``ProxyClient`` is
    /// torn down (the sockets themselves are closed via ``XHTTPConnection/cancel()``).
    private var retainedXHTTPObjects: [AnyObject] = []
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

    /// Whether this client dials the **default outbound** — the single signal the
    /// live Dial/Handshake gauges key off (see ``handshakeTimed``). The caller on
    /// the connection path decides it from the tunnel's `isDefaultConfiguration`;
    /// chain hops, rule-routed proxies, and latency probes leave it `false` so
    /// their timings stay out of the home stats.
    let isDefaultProxy: Bool

    /// Creates a new proxy client with the given configuration.
    ///
    /// - Parameters:
    ///   - configuration: The proxy server configuration.
    ///   - tunnel: Optional tunnel from a previous chain link (for proxy chaining).
    ///   - useResolvedAddressForDirectDial: Whether direct first-hop transports should
    ///     prefer `resolvedIP` over `serverAddress`. Intended for latency testing only.
    ///   - parentChain: Chain prefix leading to this link's server. Empty for non-chain-link clients.
    ///   - isDefaultProxy: Whether this client dials the default outbound, gating
    ///     the live Dial/Handshake stats. Defaults to `false`; only the connection
    ///     path's top-level client (and the default-only mux carrier) sets it.
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

    /// Host used for direct first-hop transport dials when not already tunneled through
    /// another proxy. Normal VPN traffic keeps using the configured hostname so DNS can
    /// refresh naturally; latency tests may opt into the pre-resolved IP.
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
        // Bracket the full proxy setup as a perf span for every dial (not only
        // the default proxy), stopping on success — matches MetricTimer.timing.
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
        // The XHTTP leg(s)' sockets are torn down via xhttpConnection.cancel()
        // above; drop the extra client references kept alive during the session.
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
        // Vision silently drops UDP/443 (QUIC).
        if command == .udp && destinationPort == 443 && isVisionFlow {
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

        // ALPN "h3" routes XHTTP over HTTP/3-over-QUIC; every other ALPN uses
        // HTTP/1.1 or HTTP/2 over TCP+TLS. Each leg's transport is dialed by the
        // shared XHTTP leg factory (see `dialXHTTPTransport`).
        let httpVersion = decideXHTTPHTTPVersion()

        // Resolve mode: auto → actual mode
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

        // Up/download detach: when `downloadSettings` is set, the GET (download)
        // stream is dialed to a separate server while the POST (upload) stays on
        // this node, the two correlated by a shared session ID. stream-one is a
        // single bidirectional stream and can't carry a split, so promote it to
        // stream-up. Each leg independently picks its HTTP version (1.1/2/3) and
        // may be direct or chained — the shared leg factory handles every
        // combination.
        if let downloadSettings = xhttpConfig.downloadSettings {
            if resolvedMode == .streamOne { resolvedMode = .streamUp }
            let downloadHTTPVersion = decideXHTTPHTTPVersion(for: downloadSettings.securityLayer)
            connectXHTTPDetached(
                xhttpConfig: xhttpConfig, downloadSettings: downloadSettings,
                mode: resolvedMode, sessionId: UUID().uuidString.lowercased(),
                mainHTTPVersion: httpVersion, downloadHTTPVersion: downloadHTTPVersion,
                command: command, destinationHost: destinationHost, destinationPort: destinationPort,
                initialData: initialData, completion: completion
            )
            return
        }

        // Normal single-server connection. The transport (plain/TLS/Reality/HTTP3)
        // and route (direct/tunnel/chain) are resolved by the leg factory.
        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? UUID().uuidString.lowercased() : ""
        connectXHTTPCombined(
            xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, httpVersion: httpVersion,
            command: command, destinationHost: destinationHost, destinationPort: destinationPort,
            initialData: initialData, completion: completion
        )
    }

    // MARK: Combined XHTTP (single server)

    /// Connects a normal (non-detached) XHTTP session to this node's own server.
    /// The transport — plain TCP, TLS, Reality, or HTTP/3-over-QUIC — and the
    /// route (direct, over an inbound tunnel, or through a freshly built chain)
    /// are resolved by the shared leg factory. HTTP/1.1 can't multiplex, so
    /// packet-up / stream-up dial a second connection for the upload POST via the
    /// upload factory; HTTP/2 and HTTP/3 carry both directions over one transport.
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

    // MARK: XHTTP up/download detach

    /// Connects an XHTTP session whose download (GET) and upload (POST) legs use
    /// different servers/transports, joined by a shared session ID. The download
    /// leg is the coordinator the VLESS layer rides on — its `receive` is the
    /// downlink — and it owns the upload leg, whose `send` is the uplink. Each leg
    /// independently picks its HTTP version (1.1/2/3); the upload leg follows this
    /// node's route (direct or chained), while the download leg always dials its
    /// own server directly — a distinct download source is the whole point of the
    /// split, so it is never routed back through this node's chain.
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
        // 1. Upload (main) leg → this node's own server, over our route.
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
                // 2. Download leg → the downloadSettings server, always direct.
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
                        // The upload leg was dialed but never joined to
                        // `xhttpConnection`, so a later `cancel()` can't reach it.
                        // Tear it down here (closes its socket / H3 session) so an
                        // unreachable download server can't leak the upload leg.
                        uploadLeg.cancel()
                        completion(.failure(error))
                    case .success(let downloadLeg):
                        // 3. Join the legs: the download leg is the coordinator the
                        //    VLESS layer rides on, and it owns the upload leg.
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
        /// Host for a direct kernel dial — a pre-resolved IP when latency testing,
        /// otherwise the server address.
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
        /// Open a fresh kernel socket (TCP) or UDP socket (HTTP/3) to the server.
        case direct
        /// Ride an already-established proxy tunnel (this node is a chain link).
        case overTunnel(ProxyConnection)
        /// Build a chain to the server, then ride its last hop.
        case buildChain([ProxyConfiguration])
    }

    /// The dialed transport for one XHTTP leg: a byte stream (HTTP/1.1 or HTTP/2)
    /// or an HTTP/3 QUIC session.
    private enum XHTTPDialedTransport {
        case byteStream(TransportClosures)
        case http3(HTTP3Session)
    }

    /// The endpoint for this node's own XHTTP server (the combined connection, or a
    /// detached session's upload leg).
    private func mainXHTTPEndpoint() -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: directDialHost,
            chainHost: configuration.serverAddress,
            serverName: xhttpServerName(for: configuration.securityLayer, fallback: configuration.serverAddress),
            port: configuration.serverPort,
            security: configuration.securityLayer
        )
    }

    /// The endpoint for a detached session's download server.
    private func downloadXHTTPEndpoint(_ downloadSettings: XHTTPDownloadSettings) -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: downloadSettings.serverAddress,
            chainHost: downloadSettings.serverAddress,
            serverName: xhttpServerName(for: downloadSettings.securityLayer, fallback: downloadSettings.serverAddress),
            port: downloadSettings.serverPort,
            security: downloadSettings.securityLayer
        )
    }

    /// SNI / HTTP/3 server name carried by a security layer (the address itself
    /// when the leg is unsecured).
    private func xhttpServerName(for security: SecurityLayer, fallback: String) -> String {
        switch security {
        case .tls(let tlsConfig): return tlsConfig.serverName
        case .reality(let realityConfig): return realityConfig.serverName
        case .none: return fallback
        }
    }

    /// Resolves how the main (this-node) leg reaches its server, consuming
    /// `self.tunnel` if present so it is dialed exactly once. A chain link rides the
    /// inbound tunnel; the chain exit builds a tunnel from `configuration.chain`;
    /// otherwise the leg dials directly.
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

    /// Dials one XHTTP leg and wraps it in an ``XHTTPConnection`` with the given
    /// role. Shared by the combined single-server connection (`.combined`) and each
    /// leg of a detached session (`.uploadOnly` / `.downloadOnly`).
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

    /// Dials the underlying transport for one XHTTP leg, applying the endpoint's
    /// security and the leg's HTTP version, routed direct / over an existing tunnel
    /// / through a freshly built chain. HTTP/1.1 and HTTP/2 ride a byte stream (TCP,
    /// TLS, or Reality); HTTP/3 rides a QUIC session whose datagram transport
    /// encodes the route. Dialed sockets/clients are retained via
    /// ``retainedXHTTPObjects``; chain hops via ``chainClients``.
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

    /// Dials a single byte-stream XHTTP transport — plain TCP, TLS, or Reality —
    /// either directly (`overTunnel == nil`) or riding an existing proxy tunnel.
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

    /// Builds the HTTP/3 QUIC session for one XHTTP leg. QUIC performs TLS
    /// natively, so there is no TLSClient/RealityClient here — the route is encoded
    /// as the session's datagram transport: `direct` opens a real UDP socket, while
    /// a tunnel (or a freshly built `.udp` chain) carries the QUIC datagrams.
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

    /// Builds the upload-connection factory for a combined HTTP/1.1 session: a
    /// second byte stream to this node's own server (HTTP/1.1 can't multiplex the
    /// upload POST onto the download GET's connection). Mirrors the main leg's
    /// security; routes through a freshly built chain when configured, else direct
    /// (an inbound tunnel is already consumed by the download connection).
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
