//
//  ProxyClient.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Synchronization

nonisolated class ProxyClient: @unchecked Sendable {
    let configuration: ProxyConfiguration
    let useResolvedAddressForDirectDial: Bool
    
    private struct OwnedState {
        var resources: [any ProxyClientOwned] = []
        var cancelled = false
    }

    private let ownedState = Mutex(OwnedState())

    /// Proxy tunnel from a previous chain link (for proxy chaining).
    var tunnel: ProxyConnection?

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

    // MARK: - Resource Ownership

    /// Registers a resource at creation time, before dialing, so `cancel()` reaches it
    /// even mid-dial.
    @discardableResult
    func own(_ resource: any ProxyClientOwned) -> Bool {
        let accepted: Bool = ownedState.withLock { state in
            guard !state.cancelled else { return false }
            state.resources.append(resource)
            return true
        }
        if !accepted {
            // Outside the lock: the release may do arbitrary work.
            resource.releaseOwned()
        }
        return accepted
    }

    /// Owns the delivered connection before returning it; a delivery that races teardown
    /// is cancelled and surfaced as a failure instead. The async analogue of the former
    /// `owningDelivered` completion decorator.
    private func owningDelivered(
        _ dial: () async throws -> ProxyConnection
    ) async throws -> ProxyConnection {
        let connection = try await dial()
        guard own(connection) else {
            connection.cancel()
            throw ProxyError.connectionFailed("Client released during connect")
        }
        return connection
    }

    // MARK: - Public API
    
    var isQUICTransport: Bool {
        configuration.outboundProtocol == .hysteria
            || (configuration.outboundProtocol == .nowhere && configuration.nowhereUplink == .udp)
            || configuration.isXHTTPOverHTTP3
    }
    
    private var poolsQUICSession: Bool {
        configuration.outboundProtocol == .hysteria
            || (configuration.outboundProtocol == .nowhere && configuration.nowhereUplink == .udp)
    }
    
    /// Times the outbound handshake for the default proxy's live stats; matches the former
    /// `handshakeTimed` decorator (records only on success, skips pooled QUIC sessions).
    private func withHandshakeTiming(
        _ dial: () async throws -> ProxyConnection
    ) async throws -> ProxyConnection {
        guard isDefaultProxy, !poolsQUICSession else { return try await dial() }
        let metric: ConnectionMetrics.Metric = isQUICTransport ? .handshakeNoDial : .handshake
        var timer = MetricTimer(metric)
        timer.start()
        let connection = try await dial()
        timer.stop()
        return connection
    }

    /// Dials `destinationHost:destinationPort` for a TCP stream, resolving the proxied
    /// ``ProxyConnection`` or throwing on failure/cancellation.
    func connect(
        to destinationHost: String,
        port destinationPort: UInt16,
        initialData: Data? = nil
    ) async throws -> ProxyConnection {
        try await withHandshakeTiming {
            try await self.owningDelivered {
                try await self.connectThroughChainIfNeeded(
                    command: .tcp,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    initialData: initialData
                )
            }
        }
    }

    /// Opens a UDP association to `destinationHost:destinationPort`.
    func connectUDP(
        to destinationHost: String,
        port destinationPort: UInt16
    ) async throws -> ProxyConnection {
        try await withHandshakeTiming {
            try await self.owningDelivered {
                try await self.connectThroughChainIfNeeded(
                    command: .udp,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    initialData: nil
                )
            }
        }
    }

    /// Opens the protocol's stream multiplexer (VLESS Vision UDP-over-mux, etc.).
    func connectMultiplexer() async throws -> ProxyConnection {
        try await withHandshakeTiming {
            try await self.owningDelivered {
                try await self.connectThroughChainIfNeeded(
                    command: .mux,
                    destinationHost: "v1.mux.cool",
                    destinationPort: 666,
                    initialData: nil
                )
            }
        }
    }

    private func connectThroughChainIfNeeded(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard let chain = configuration.chain, !chain.isEmpty, tunnel == nil else {
            return try await connectWithCommand(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData
            )
        }

        if configuration.outboundProtocol == .nowhere,
           configuration.nowhereUplink != configuration.nowhereDownlink {
            throw ProxyError.protocolError("Asymmetric Nowhere carriers do not support proxy chains")
        }

        if isQUICTransport {
            return try await connectWithCommand(
                command: command,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData
            )
        }

        guard let lastDeliver = configuration.upstreamCommand(for: command) else {
            throw ProxyError.protocolError(
                "\(configuration.outboundProtocol.name) doesn't support \(command)"
            )
        }

        let hopCommands = try Self.computeChainHopCommands(chain: chain, lastDeliver: lastDeliver).get()

        let chainTunnel = try await buildChainTunnel(
            chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands
        )
        self.tunnel = chainTunnel
        return try await connectWithCommand(
            command: command,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: initialData
        )
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
                guard let request = nextHop.upstreamCommand(for: downstreamCmd) else {
                    return .failure(ProxyError.protocolError(
                        "Chain hop \(nextHop.outboundProtocol.name) doesn't support \(downstreamCmd) downstream — needed by the hop above it"
                    ))
                }
                commands[i] = request
            }
        }
        return .success(commands)
    }

    /// Builds the chain of hop tunnels sequentially, each dialed over the previous hop.
    /// Hop clients are registered via `track` (defaulting to `own`) so teardown reaches them.
    @discardableResult
    func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16)? = nil,
        track: ((ProxyClient) -> Void)? = nil
    ) async throws -> ProxyConnection {
        let resolvedDestination: (host: String, port: UInt16) = finalDestination
            ?? (host: configuration.serverAddress, port: configuration.serverPort)
        let resolvedTrack: (ProxyClient) -> Void = track ?? { [weak self] client in
            self?.own(client)
        }
        return try await Self.dialChain(
            chain: chain,
            index: index,
            currentTunnel: currentTunnel,
            hopCommands: hopCommands,
            finalDestination: resolvedDestination,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            track: resolvedTrack
        )
    }

    /// Chain build for pooled transports where the pool retains the hops and the
    /// build may outlive the first caller.
    static func buildDetachedChainTunnel(
        chain: [ProxyConfiguration],
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void
    ) async throws -> ProxyConnection {
        try await dialChain(
            chain: chain,
            index: 0,
            currentTunnel: nil,
            hopCommands: hopCommands,
            finalDestination: finalDestination,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            track: track
        )
    }

    /// Self-free sequential hop dial shared by the instance and detached chain builders.
    /// Replaces the former recursive `dispatchChainHop` with a `for hop in chain` loop:
    /// each hop dials over the previous hop's tunnel; a throw aborts the remaining hops.
    private static func dialChain(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void
    ) async throws -> ProxyConnection {
        var currentTunnel = currentTunnel
        for hopIndex in index..<chain.count {
            let isLastHop = (hopIndex + 1 == chain.count)
            let nextHost: String
            let nextPort: UInt16
            if !isLastHop {
                nextHost = chain[hopIndex + 1].serverAddress
                nextPort = chain[hopIndex + 1].serverPort
            } else {
                nextHost = finalDestination.host
                nextPort = finalDestination.port
            }

            let chainClient = ProxyClient(
                configuration: chain[hopIndex],
                tunnel: currentTunnel,
                useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
                parentChain: Array(chain[0..<hopIndex])
            )
            track(chainClient)

            if hopCommands[hopIndex] == .udp {
                currentTunnel = try await chainClient.connectUDP(to: nextHost, port: nextPort)
            } else {
                currentTunnel = try await chainClient.connect(to: nextHost, port: nextPort)
            }
        }
        guard let tunnel = currentTunnel else {
            throw ProxyError.connectionFailed("Empty proxy chain")
        }
        return tunnel
    }

    /// Fire-and-forget teardown for `deinit`/error paths: releases every owned resource
    /// LIFO without awaiting fd close. Awaitable hops (chain clients) recurse through the
    /// synchronous `releaseOwned()`.
    func cancel() {
        let owned = takeOwnedForCancel()
        // LIFO: unwind wrappers before the transports they ride.
        for resource in owned.reversed() {
            resource.releaseOwned()
        }
    }

    /// Cancels the client and suspends until every underlying socket is fully torn down
    /// (fd closed). Replaces the former `cancel(completion:)` + `TeardownCounter` with a
    /// `TaskGroup` awaiting each awaitable hop's `releaseOwned()`.
    func cancel() async {
        let owned = takeOwnedForCancel()
        await withTaskGroup(of: Void.self) { group in
            // LIFO: unwind wrappers before the transports they ride.
            for resource in owned.reversed() {
                if let awaitable = resource as? any AwaitableProxyClientOwned {
                    group.addTask { await awaitable.releaseOwned() }
                } else {
                    resource.releaseOwned()
                }
            }
        }
    }

    /// Marks the client cancelled and returns the owned resources for release. A chain
    /// link's inbound tunnel belongs to the client that produced it, so it is dropped by
    /// reference only.
    private func takeOwnedForCancel() -> [any ProxyClientOwned] {
        let owned: [any ProxyClientOwned] = ownedState.withLock { state in
            state.cancelled = true
            let owned = state.resources
            state.resources.removeAll()
            return owned
        }
        tunnel = nil
        return owned
    }

    // MARK: - Protocol Handshake

    /// Async protocol handshake over an established transport; dispatches to the VLESS or
    /// Shadowsocks handshake. Used by the native-async dial paths (Direct/TLS-record layers
    /// migrate their consumers onto this as their stages land).
    private func sendProtocolHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        supportsVision: Bool
    ) async throws -> ProxyConnection {
        if isShadowsocks {
            return try await sendShadowsocksProtocolHandshake(
                over: connection, command: command,
                destinationHost: destinationHost, destinationPort: destinationPort
            )
        } else {
            return try await sendVLESSProtocolHandshake(
                over: connection, command: command,
                destinationHost: destinationHost, destinationPort: destinationPort,
                initialData: initialData, supportsVision: supportsVision
            )
        }
    }

    // MARK: - Connection Routing

    private func connectWithCommand(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        // Vision silently drops UDP/443 (QUIC).
        if command == .udp && destinationPort == 443 && isVisionFlow {
            throw ProxyError.dropped
        }

        if command == .mux, !configuration.outboundProtocol.supportsMux {
            throw ProxyError.protocolError(
                "Mux is not supported with \(configuration.outboundProtocol.name)"
            )
        }

        if configuration.outboundProtocol == .hysteria {
            return try await connectWithHysteria(
                command: command, destinationHost: destinationHost, destinationPort: destinationPort
            )
        }

        if configuration.outboundProtocol == .nowhere {
            return try await connectWithNowhere(
                command: command, destinationHost: destinationHost, destinationPort: destinationPort
            )
        }

        if configuration.outboundProtocol == .trojan {
            return try await connectWithTrojan(
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData
            )
        }

        if configuration.outboundProtocol == .anytls {
            return try await connectWithAnyTLS(
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData
            )
        }

        if isShadowsocks {
            if command == .udp {
                return try await connectShadowsocksRealUDP(
                    destinationHost: destinationHost, destinationPort: destinationPort
                )
            }
            return try await connectDirect(
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData
            )
        }

        if configuration.outboundProtocol == .socks5 {
            return try await connectWithSOCKS5(
                command: command, destinationHost: destinationHost, destinationPort: destinationPort
            )
        }

        if configuration.outboundProtocol == .sudoku {
            return try await connectWithSudoku(
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData
            )
        }

        if configuration.outboundProtocol.isNaive {
            if command != .tcp {
                throw ProxyError.dropped
            }
            return try await connectWithNaive(destinationHost: destinationHost, destinationPort: destinationPort)
        }

        // Only VLESS reaches this point; Vision needs a TLS-record-like layer
        // (VLESS Encryption, or a raw TCP transport carrying TLS/Reality).
        switch configuration.xrayTransportLayer {
        case .ws:
            return try await connectWithWebSocket(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
        case .httpUpgrade:
            return try await connectWithHTTPUpgrade(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
        case .grpc:
            return try await connectWithGRPC(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
        case .xhttp:
            return try await connectWithXHTTP(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
        case .raw:
            switch configuration.xraySecurityLayer {
            case .tls(let tlsConfig):
                return try await connectWithTLS(tlsConfig: tlsConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
            case .reality(let realityConfig):
                return try await connectWithReality(realityConfig: realityConfig, command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
            case .none:
                return try await connectDirect(command: command, destinationHost: destinationHost, destinationPort: destinationPort, initialData: initialData)
            }
        }
    }

    // MARK: - Async dispatch bridges

    private func connectWithTLS(
        tlsConfig: TLSConfiguration,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let tlsClient = TLSClient(configuration: tlsConfig)
        self.own(tlsClient)
        let tlsConnection = try await connectTLSRecord(tlsClient)
        self.own(tlsConnection)
        let tlsProxyConnection = TLSProxyConnection(tlsConnection: tlsConnection)
        return try await sendProtocolHandshake(
            over: tlsProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData, supportsVision: true
        )
    }

    private func connectWithReality(
        realityConfig: RealityConfiguration,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let realityClient = RealityClient(configuration: realityConfig)
        self.own(realityClient)
        let realityConnection = try await connectRealityRecord(realityClient)
        self.own(realityConnection)
        let realityProxyConnection = RealityProxyConnection(realityConnection: realityConnection)
        return try await sendProtocolHandshake(
            over: realityProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData, supportsVision: true
        )
    }

    /// Runs the TLS handshake async-natively. Dials over the chain tunnel when present, else
    /// directly to the configured server.
    private func connectTLSRecord(_ tlsClient: TLSClient) async throws -> TLSRecordConnection {
        if let tunnel = self.tunnel {
            return try await tlsClient.connect(overTunnel: tunnel)
        } else {
            return try await tlsClient.connect(host: self.directDialHost, port: self.configuration.serverPort)
        }
    }

    /// Runs the Reality handshake async-natively. Dials over the chain tunnel when present, else
    /// directly to the configured server.
    private func connectRealityRecord(_ realityClient: RealityClient) async throws -> TLSRecordConnection {
        if let tunnel = self.tunnel {
            return try await realityClient.connect(overTunnel: tunnel)
        } else {
            return try await realityClient.connect(host: self.directDialHost, port: self.configuration.serverPort)
        }
    }

    // MARK: - WebSocket Connection

    private func connectWithWebSocket(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard case .ws(let wsConfig) = configuration.xrayTransportLayer else {
            throw ProxyError.connectionFailed("WebSocket transport specified but no WebSocket configuration")
        }

        let wsConnection: WebSocketConnection
        if case .tls(let baseTLSConfig) = configuration.xraySecurityLayer {
            let wsTlsConfig = TLSConfiguration(
                serverName: baseTLSConfig.serverName,
                alpn: ["http/1.1"],
                echEnabled: baseTLSConfig.echEnabled,
                echConfig: baseTLSConfig.echConfig,
                fingerprint: baseTLSConfig.fingerprint
            )
            let tlsClient = TLSClient(configuration: wsTlsConfig)
            self.own(tlsClient)
            let tlsConnection = try await connectTLSRecord(tlsClient)
            self.own(tlsConnection)
            wsConnection = WebSocketConnection(tlsConnection: tlsConnection, configuration: wsConfig)
        } else if let tunnel = self.tunnel {
            wsConnection = WebSocketConnection(tunnel: tunnel, configuration: wsConfig)
        } else {
            let transport = TCPTransport(host: directDialHost, port: configuration.serverPort)
            self.own(transport)
            try await transport.connect()
            wsConnection = WebSocketConnection(transport: transport, configuration: wsConfig)
        }

        own(wsConnection)
        try await wsConnection.performUpgrade()
        let webSocketProxyConnection = WebSocketProxyConnection(wsConnection: wsConnection)
        return try await sendProtocolHandshake(
            over: webSocketProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData, supportsVision: transportSupportsVision
        )
    }

    // MARK: - HTTP Upgrade Connection

    private func connectWithHTTPUpgrade(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard case .httpUpgrade(let huConfig) = configuration.xrayTransportLayer else {
            throw ProxyError.connectionFailed("HTTP upgrade transport specified but no configuration")
        }

        let huConnection: HTTPUpgradeConnection
        if case .tls(let tlsConfiguration) = configuration.xraySecurityLayer {
            let tlsClient = TLSClient(configuration: tlsConfiguration)
            self.own(tlsClient)
            let tlsConnection = try await connectTLSRecord(tlsClient)
            self.own(tlsConnection)
            huConnection = HTTPUpgradeConnection(tlsConnection: tlsConnection, configuration: huConfig)
        } else if let tunnel = self.tunnel {
            huConnection = HTTPUpgradeConnection(tunnel: tunnel, configuration: huConfig)
        } else {
            let transport = TCPTransport(host: directDialHost, port: configuration.serverPort)
            self.own(transport)
            try await transport.connect()
            huConnection = HTTPUpgradeConnection(transport: transport, configuration: huConfig)
        }

        own(huConnection)
        try await huConnection.performUpgrade()
        let httpUpgradeProxyConnection = HTTPUpgradeProxyConnection(huConnection: huConnection)
        return try await sendProtocolHandshake(
            over: httpUpgradeProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData, supportsVision: transportSupportsVision
        )
    }

    private func connectWithGRPC(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard case .grpc(let grpcConfig) = configuration.xrayTransportLayer else {
            throw ProxyError.connectionFailed("gRPC transport specified but no gRPC configuration")
        }

        // The :authority falls back to the TLS/Reality SNI when no override is configured.
        let tlsServerName: String?
        if case .tls(let tls) = configuration.xraySecurityLayer { tlsServerName = tls.serverName } else { tlsServerName = nil }
        let realityServerName: String?
        if case .reality(let reality) = configuration.xraySecurityLayer { realityServerName = reality.serverName } else { realityServerName = nil }
        let authority = grpcConfig.resolvedAuthority(
            tlsServerName: tlsServerName,
            realityServerName: realityServerName,
            serverAddress: configuration.serverAddress
        )

        let grpcConnection: GRPCConnection
        if case .reality(let realityConfig) = configuration.xraySecurityLayer {
            // Reality handles its own ALPN internally; layer gRPC on top.
            let realityClient = RealityClient(configuration: realityConfig)
            self.own(realityClient)
            let realityConnection = try await connectRealityRecord(realityClient)
            self.own(realityConnection)
            grpcConnection = GRPCConnection(tlsConnection: realityConnection, configuration: grpcConfig, authority: authority)
        } else if case .tls(let baseTLSConfig) = configuration.xraySecurityLayer {
            let grpcTLSConfig = sanitizedGRPCTLSConfiguration(from: baseTLSConfig)
            let tlsClient = TLSClient(configuration: grpcTLSConfig)
            self.own(tlsClient)
            let tlsConnection = try await connectTLSRecord(tlsClient)
            self.own(tlsConnection)
            grpcConnection = GRPCConnection(tlsConnection: tlsConnection, configuration: grpcConfig, authority: authority)
        } else if let tunnel = self.tunnel {
            grpcConnection = GRPCConnection(tunnel: tunnel, configuration: grpcConfig, authority: authority)
        } else {
            let transport = TCPTransport(host: directDialHost, port: configuration.serverPort)
            self.own(transport)
            try await transport.connect()
            grpcConnection = GRPCConnection(transport: transport, configuration: grpcConfig, authority: authority)
        }

        own(grpcConnection)
        try await grpcConnection.performSetup()
        let grpcProxyConnection = GRPCProxyConnection(grpcConnection: grpcConnection)
        return try await sendProtocolHandshake(
            over: grpcProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData, supportsVision: transportSupportsVision
        )
    }

    // MARK: - Direct Connection

    private func connectDirect(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let directProxyConnection: ProxyConnection
        let supportsVision = transportSupportsVision
        if let tunnel = self.tunnel {
            directProxyConnection = DirectProxyConnection(transport: TunneledTransport(tunnel: tunnel))
        } else {
            let transport = TCPTransport(host: directDialHost, port: configuration.serverPort)
            self.own(transport)
            try await transport.connect()
            directProxyConnection = DirectProxyConnection(transport: transport)
        }
        return try await sendProtocolHandshake(
            over: directProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData,
            supportsVision: supportsVision
        )
    }

    // MARK: - gRPC Connection

    /// ALPN is forced to `h2` because gRPC requires HTTP/2.
    private func sanitizedGRPCTLSConfiguration(from base: TLSConfiguration) -> TLSConfiguration {
        TLSConfiguration(
            serverName: base.serverName,
            alpn: ["h2"],
            echEnabled: base.echEnabled,
            echConfig: base.echConfig,
            fingerprint: base.fingerprint
        )
    }

    // MARK: - XHTTP Connection

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

    /// Selects the XHTTP HTTP version: Reality forces h2; plain TCP is http/1.1; otherwise per TLS ALPN.
    private func decideXHTTPHTTPVersion(for xraySecurityLayer: XraySecurityLayer? = nil) -> XHTTPHTTPVersion {
        let security = xraySecurityLayer ?? configuration.xraySecurityLayer
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
            echEnabled: base.echEnabled,
            echConfig: base.echConfig,
            fingerprint: base.fingerprint
        )
    }

    private func connectWithXHTTP(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard case .xhttp(let xhttpConfig) = configuration.xrayTransportLayer else {
            throw ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")
        }

        let httpVersion = decideXHTTPHTTPVersion()

        var resolvedMode: XHTTPMode
        if xhttpConfig.mode == .auto {
            if case .reality = configuration.xraySecurityLayer {
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
            let downloadHTTPVersion = decideXHTTPHTTPVersion(for: downloadSettings.xraySecurityLayer)
            return try await connectXHTTPDetached(
                xhttpConfig: xhttpConfig, downloadSettings: downloadSettings,
                mode: resolvedMode, sessionId: xhttpConfig.generateSessionID(),
                mainHTTPVersion: httpVersion, downloadHTTPVersion: downloadHTTPVersion,
                command: command, destinationHost: destinationHost, destinationPort: destinationPort,
                initialData: initialData
            )
        }

        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? xhttpConfig.generateSessionID() : ""
        return try await connectXHTTPCombined(
            xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId, httpVersion: httpVersion,
            command: command, destinationHost: destinationHost, destinationPort: destinationPort,
            initialData: initialData
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
        initialData: Data?
    ) async throws -> ProxyConnection {
        let route = consumeMainXHTTPRoute()
        let needsUploadFactory = httpVersion == .http11 && (mode == .packetUp || mode == .streamUp)
        let uploadFactory = needsUploadFactory
            ? makeXHTTPUploadFactory(security: configuration.xraySecurityLayer, httpVersion: httpVersion,
                                     mode: mode, xmux: xhttpConfig.effectiveXMUX)
            : nil
        let xhttpConnection = try await dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(), httpVersion: httpVersion, route: route,
            xhttp: xhttpConfig, mode: mode, sessionId: sessionId, role: .combined, uploadFactory: uploadFactory
        )
        self.own(xhttpConnection)
        return try await performXHTTPSetup(
            xhttpConnection: xhttpConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData
        )
    }

    private func performXHTTPSetup(
        xhttpConnection: XHTTPConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        try await xhttpConnection.performSetup()
        let xhttpProxyConnection = XHTTPProxyConnection(xhttpConnection: xhttpConnection)
        return try await sendProtocolHandshake(
            over: xhttpProxyConnection, command: command, destinationHost: destinationHost,
            destinationPort: destinationPort, initialData: initialData,
            supportsVision: self.transportSupportsVision
        )
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
        initialData: Data?
    ) async throws -> ProxyConnection {
        let uploadRoute = consumeMainXHTTPRoute()
        let uploadLeg = try await dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(), httpVersion: mainHTTPVersion, route: uploadRoute,
            xhttp: xhttpConfig, mode: mode, sessionId: sessionId, role: .uploadOnly, uploadFactory: nil
        )
        // The download leg later re-owns this as coordinator (`uploadChannel`);
        // the double-cancel is idempotent.
        self.own(uploadLeg)

        let downloadLeg: XHTTPConnection
        do {
            downloadLeg = try await dialXHTTPLeg(
                endpoint: self.downloadXHTTPEndpoint(downloadSettings), httpVersion: downloadHTTPVersion,
                route: .direct, xhttp: downloadSettings.xhttp, mode: mode, sessionId: sessionId,
                role: .downloadOnly, uploadFactory: nil
            )
        } catch {
            uploadLeg.cancel()
            throw error
        }

        // Download leg is the coordinator; it owns the upload leg.
        downloadLeg.uploadChannel = uploadLeg
        self.own(downloadLeg)
        return try await performXHTTPSetup(
            xhttpConnection: downloadLeg, command: command,
            destinationHost: destinationHost, destinationPort: destinationPort,
            initialData: initialData
        )
    }

    // MARK: XHTTP leg factory (shared by combined & detach)

    private struct XHTTPEndpoint {
        /// Host for a direct kernel dial (a pre-resolved IP when latency testing).
        let directHost: String
        /// Logical server identity, used as the HTTP/3 host when chained.
        let chainHost: String
        /// SNI / HTTP/3 server name.
        let serverName: String
        let port: UInt16
        let security: XraySecurityLayer
    }

    private enum XHTTPLegRoute {
        case direct
        case overTunnel(ProxyConnection)
        case buildChain([ProxyConfiguration])
    }

    private enum XHTTPDialedTransport {
        case byteStream(AsyncTransportClosures)
        case http3(HTTP3Multiplexer)
    }

    private func mainXHTTPEndpoint() -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: directDialHost,
            chainHost: configuration.serverAddress,
            serverName: configuration.xraySecurityLayer.serverName(fallback: configuration.serverAddress),
            port: configuration.serverPort,
            security: configuration.xraySecurityLayer
        )
    }

    private func downloadXHTTPEndpoint(_ downloadSettings: XHTTPDownloadSettings) -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: downloadSettings.serverAddress,
            chainHost: downloadSettings.serverAddress,
            serverName: downloadSettings.xraySecurityLayer.serverName(fallback: downloadSettings.serverAddress),
            port: downloadSettings.serverPort,
            security: downloadSettings.xraySecurityLayer
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
        uploadFactory: (() async throws -> AsyncTransportClosures)?
    ) async throws -> XHTTPConnection {
        // xmux: pool/multiplex direct-route XHTTP connections. XHTTP always pools — serial-reuse
        // defaults apply when xmux is omitted (see `effectiveXMUX`). Tunneled/chained routes
        // can't pool (single-use tunnel), so they fall through to a fresh dial below.
        if httpVersion == .http3, case .direct = route {
            return try await acquirePooledH3(
                endpoint: endpoint, xmux: xhttp.effectiveXMUX, xhttp: xhttp,
                mode: mode, sessionId: sessionId, role: role
            )
        }

        if httpVersion == .http2, case .direct = route {
            return try await acquirePooledH2(
                endpoint: endpoint, xmux: xhttp.effectiveXMUX, xhttp: xhttp,
                mode: mode, sessionId: sessionId, role: role
            )
        }

        let transport = try await dialXHTTPTransport(endpoint: endpoint, httpVersion: httpVersion, route: route)
        let connection: XHTTPConnection
        switch transport {
        case .byteStream(let closures):
            connection = XHTTPConnection(
                download: closures, configuration: xhttp, mode: mode, sessionId: sessionId,
                useHTTP2: httpVersion == .http2, uploadConnectionFactory: uploadFactory
            )
        case .http3(let session):
            connection = XHTTPConnection(
                h3Multiplexer: session, configuration: xhttp, mode: mode, sessionId: sessionId
            )
        }
        connection.role = role
        return connection
    }

    /// Acquires a shared, xmux-pooled HTTP/3 session for a direct-route XHTTP leg; the
    /// factory is destination-bound (captures no per-flow state) so the manager is reusable.
    private func acquirePooledH3(
        endpoint: XHTTPEndpoint,
        xmux: XHTTPXMUXMultiplexerConfiguration,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole
    ) async throws -> XHTTPConnection {
        let host = endpoint.directHost
        let port = endpoint.port
        let serverName = endpoint.serverName
        let key = "h3|\(host)|\(port)|\(serverName)"
        let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: xmux) {
            { () async -> XHTTPXMUXMultiplexerPoolable? in
                // QUIC connects lazily, so a fresh session never fails at creation.
                HTTP3Multiplexer(host: host, port: port, serverName: serverName)
            }
        }
        guard let lease = await manager.acquire(), let session = lease.connection as? HTTP3Multiplexer else {
            throw ProxyError.connectionFailed("xmux H3 session acquisition failed")
        }
        let connection = XHTTPConnection(
            h3Multiplexer: session, configuration: xhttp, mode: mode, sessionId: sessionId
        )
        connection.role = role
        connection.xmuxLease = lease
        return connection
    }

    /// Acquires a shared, xmux-pooled HTTP/2 connection for a direct-route XHTTP leg; the
    /// factory is destination-bound (captures no per-flow state) so the manager is reusable.
    private func acquirePooledH2(
        endpoint: XHTTPEndpoint,
        xmux: XHTTPXMUXMultiplexerConfiguration,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole
    ) async throws -> XHTTPConnection {
        let host = endpoint.directHost
        let port = endpoint.port
        let security = endpoint.security
        let serverName = endpoint.serverName
        let key = "h2|\(host)|\(port)|\(serverName)"
        let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: xmux) {
            { () async -> XHTTPXMUXMultiplexerPoolable? in
                try? await ProxyClient.dialSharedH2(host: host, port: port, security: security)
            }
        }
        guard let lease = await manager.acquire(), let shared = lease.connection as? XHTTPH2Multiplexer else {
            throw ProxyError.connectionFailed("xmux H2 connection acquisition failed")
        }
        let connection = XHTTPConnection(sharedH2: shared, configuration: xhttp, mode: mode, sessionId: sessionId)
        connection.role = role
        connection.xmuxLease = lease
        return connection
    }

    /// Dials a byte stream and brings up a shared multiplexing H2 connection on it (xmux).
    /// Static so the pooled manager's factory captures no per-flow state; the dial client is
    /// retained by the shared connection for its lifetime.
    private static func dialSharedH2(
        host: String,
        port: UInt16,
        security: XraySecurityLayer
    ) async throws -> XHTTPH2Multiplexer {
        func bringUp(_ transport: AsyncTransportClosures, retaining object: AnyObject?) async throws -> XHTTPH2Multiplexer {
            let shared = XHTTPH2Multiplexer(transport: transport)
            if let object { shared.retain(object) }
            try await shared.connect()
            return shared
        }
        switch security {
        case .none:
            let transport = TCPTransport(host: host, port: port)
            try await transport.connect()
            return try await bringUp(AsyncTransportClosures(transport), retaining: transport)
        case .tls(let tlsConfig):
            // XHTTP rides h2; advertise it (fall back to http/1.1) regardless of the configured ALPN.
            let h2TLS = TLSConfiguration(
                serverName: tlsConfig.serverName, alpn: ["h2", "http/1.1"],
                echEnabled: tlsConfig.echEnabled, echConfig: tlsConfig.echConfig, fingerprint: tlsConfig.fingerprint
            )
            let client = TLSClient(configuration: h2TLS)
            let connection = try await client.connect(host: host, port: port)
            return try await bringUp(AsyncTransportClosures(tls: connection), retaining: client)
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            let connection = try await client.connect(host: host, port: port)
            return try await bringUp(AsyncTransportClosures(tls: connection), retaining: client)
        }
    }

    /// HTTP/1.1 and HTTP/2 ride a byte stream; HTTP/3 rides a QUIC session whose
    /// datagram transport encodes the route.
    private func dialXHTTPTransport(
        endpoint: XHTTPEndpoint,
        httpVersion: XHTTPHTTPVersion,
        route: XHTTPLegRoute
    ) async throws -> XHTTPDialedTransport {
        if httpVersion == .http3 {
            return try await dialXHTTPHTTP3Session(endpoint: endpoint, route: route)
        }
        switch route {
        case .direct:
            return try await dialXHTTPByteStream(host: endpoint.directHost, port: endpoint.port, security: endpoint.security,
                                httpVersion: httpVersion, overTunnel: nil)
        case .overTunnel(let tunnel):
            return try await dialXHTTPByteStream(host: endpoint.chainHost, port: endpoint.port, security: endpoint.security,
                                httpVersion: httpVersion, overTunnel: tunnel)
        case .buildChain(let chain):
            // XHTTP requires a TCP stream end-to-end.
            let hopCommands = [ProxyCommand](repeating: .tcp, count: chain.count)
            let tunnel = try await self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands)
            return try await dialXHTTPByteStream(host: endpoint.chainHost, port: endpoint.port, security: endpoint.security,
                                     httpVersion: httpVersion, overTunnel: tunnel)
        }
    }

    private func dialXHTTPByteStream(
        host: String,
        port: UInt16,
        security: XraySecurityLayer,
        httpVersion: XHTTPHTTPVersion,
        overTunnel: ProxyConnection?
    ) async throws -> XHTTPDialedTransport {
        switch security {
        case .none:
            if let tunnel = overTunnel {
                return .byteStream(AsyncTransportClosures(proxyConnection: tunnel))
            } else {
                let transport = TCPTransport(host: host, port: port)
                own(transport)
                try await transport.connect()
                return .byteStream(AsyncTransportClosures(transport))
            }
        case .tls(let tlsConfig):
            let client = TLSClient(configuration: sanitizedXHTTPTLSConfiguration(from: tlsConfig, httpVersion: httpVersion))
            own(client)
            let connection: TLSRecordConnection
            if let tunnel = overTunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            return .byteStream(AsyncTransportClosures(tls: connection))
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            own(client)
            let connection: TLSRecordConnection
            if let tunnel = overTunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            return .byteStream(AsyncTransportClosures(tls: connection))
        }
    }

    /// QUIC performs TLS natively, so the route is encoded as the session's datagram
    /// transport instead of a TLS/Reality client.
    private func dialXHTTPHTTP3Session(
        endpoint: XHTTPEndpoint,
        route: XHTTPLegRoute
    ) async throws -> XHTTPDialedTransport {
        let makeSession: (String, QUICDatagramTransport?) -> XHTTPDialedTransport = { host, transport in
            .http3(HTTP3Multiplexer(host: host, port: endpoint.port, serverName: endpoint.serverName, transport: transport))
        }
        switch route {
        case .direct:
            return makeSession(endpoint.directHost, nil)
        case .overTunnel(let tunnel):
            return makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))
        case .buildChain(let chain):
            let hopCommands = try Self.computeChainHopCommands(chain: chain, lastDeliver: .udp).get()
            let tunnel = try await self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands)
            return makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))
        }
    }

    /// Upload-connection factory for combined HTTP/1.1 sessions; the download leg already
    /// consumed any inbound tunnel, so this routes direct or through a fresh chain.
    private func makeXHTTPUploadFactory(
        security: XraySecurityLayer,
        httpVersion: XHTTPHTTPVersion,
        mode: XHTTPMode,
        xmux: XHTTPXMUXMultiplexerConfiguration
    ) -> (() async throws -> AsyncTransportClosures) {
        // xmux: pool the packet-up upload socket across sessions for direct routes.
        // stream-up's upload is one indefinite POST (never reusable); chained routes can't pool.
        let hasChain = (configuration.chain?.isEmpty == false)
        if mode == .packetUp, !hasChain {
            let endpoint = mainXHTTPEndpoint()
            let host = endpoint.directHost
            let port = endpoint.port
            let sec = endpoint.security
            let serverName = endpoint.serverName
            // HTTP/1.1 can't multiplex: force exclusive use (concurrency 1) so a socket is never
            // handed to concurrent sessions. Rotation limits (connections/reuse/lifetime) still apply.
            var uploadXMUX = xmux
            uploadXMUX.maxConcurrency = XHTTPXMUXMultiplexerRange(from: 1, to: 1)
            let key = "h1up|\(host)|\(port)|\(serverName)"
            let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: uploadXMUX) {
                { () async -> XHTTPXMUXMultiplexerPoolable? in
                    await ProxyClient.dialH1UploadConnection(host: host, port: port, security: sec)
                }
            }
            return {
                guard let lease = await manager.acquire(), let connection = lease.connection as? XHTTPH1Multiplexer else {
                    throw ProxyError.connectionFailed("xmux H1 upload acquisition failed")
                }
                connection.lease = lease
                return connection.sessionClosures
            }
        }

        return { [weak self] in
            guard let self else {
                throw ProxyError.connectionFailed("Client deallocated")
            }
            let route: XHTTPLegRoute
            if let chain = self.configuration.chain, !chain.isEmpty {
                route = .buildChain(chain)
            } else {
                route = .direct
            }
            let transport = try await self.dialXHTTPTransport(endpoint: self.mainXHTTPEndpoint(), httpVersion: httpVersion, route: route)
            switch transport {
            case .byteStream(let closures):
                return closures
            case .http3:
                throw ProxyError.connectionFailed("HTTP/3 has no separate upload connection")
            }
        }
    }

    /// Dials a fresh HTTP/1.1 upload byte stream and wraps it as a poolable upload connection (xmux).
    /// Static so the pooled manager's factory captures no per-flow state.
    private static func dialH1UploadConnection(
        host: String,
        port: UInt16,
        security: XraySecurityLayer
    ) async -> XHTTPH1Multiplexer? {
        func wrap(_ transport: AsyncTransportClosures, retaining object: AnyObject?) -> XHTTPH1Multiplexer {
            let connection = XHTTPH1Multiplexer(transport: transport)
            if let object { connection.retain(object) }
            return connection
        }
        switch security {
        case .none:
            let transport = TCPTransport(host: host, port: port)
            do {
                try await transport.connect()
            } catch {
                return nil
            }
            return wrap(AsyncTransportClosures(transport), retaining: transport)
        case .tls(let tlsConfig):
            let h1TLS = TLSConfiguration(
                serverName: tlsConfig.serverName, alpn: ["http/1.1"],
                echEnabled: tlsConfig.echEnabled, echConfig: tlsConfig.echConfig, fingerprint: tlsConfig.fingerprint
            )
            let client = TLSClient(configuration: h1TLS)
            guard let connection = try? await client.connect(host: host, port: port) else { return nil }
            return wrap(AsyncTransportClosures(tls: connection), retaining: client)
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            guard let connection = try? await client.connect(host: host, port: port) else { return nil }
            return wrap(AsyncTransportClosures(tls: connection), retaining: client)
        }
    }

}
