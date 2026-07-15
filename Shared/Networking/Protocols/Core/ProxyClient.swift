//
//  ProxyClient.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Synchronization

// MARK: - ProxyClient

nonisolated class ProxyClient {
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

    /// Migration scaffold: bridges a one-shot completion dial to `async`. Wraps the
    /// per-protocol handshake internals that are not yet native async so their entry
    /// points can be `async throws`; each use is removed as its protocol stage lands.
    func bridged<Value>(
        _ operation: (@escaping (Result<Value, Error>) -> Void) -> Void
    ) async throws -> Value {
        let resumer = OneShotResumer<Value>()
        return try await withCheckedThrowingContinuation { continuation in
            resumer.arm(continuation)
            operation { resumer.resume($0) }
        }
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
        try await bridged { completion in
            self.connectWithTLS(
                tlsConfig: tlsConfig, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData, completion: completion
            )
        }
    }

    private func connectWithReality(
        realityConfig: RealityConfiguration,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        try await bridged { completion in
            self.connectWithReality(
                realityConfig: realityConfig, command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData, completion: completion
            )
        }
    }

    /// Bridges the still-callback TLS handshake to `async` (removed in Stage 14). Dials over the
    /// chain tunnel when present, else directly to the configured server.
    private func connectTLSRecord(_ tlsClient: TLSClient) async throws -> TLSRecordConnection {
        try await bridged { completion in
            if let tunnel = self.tunnel {
                tlsClient.connect(overTunnel: tunnel, completion: completion)
            } else {
                tlsClient.connect(host: self.directDialHost, port: self.configuration.serverPort, completion: completion)
            }
        }
    }

    /// Bridges the still-callback Reality handshake to `async` (removed in Stage 14). Dials over
    /// the chain tunnel when present, else directly to the configured server.
    private func connectRealityRecord(_ realityClient: RealityClient) async throws -> TLSRecordConnection {
        try await bridged { completion in
            if let tunnel = self.tunnel {
                realityClient.connect(overTunnel: tunnel, completion: completion)
            } else {
                realityClient.connect(host: self.directDialHost, port: self.configuration.serverPort, completion: completion)
            }
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

    private func connectWithXHTTP(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        try await bridged { completion in
            self.connectWithXHTTP(
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, initialData: initialData, completion: completion
            )
        }
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
            directProxyConnection = LegacyDirectProxyConnection(connection: TunneledTransport(tunnel: tunnel))
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
        self.own(tlsClient)

        let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let tlsConnection):
                self.own(tlsConnection)
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
        self.own(realityClient)

        let handleRealityResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let realityConnection):
                self.own(realityConnection)
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
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .xhttp(let xhttpConfig) = configuration.xrayTransportLayer else {
            completion(.failure(ProxyError.connectionFailed("XHTTP transport specified but no XHTTP configuration")))
            return
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
            ? makeXHTTPUploadFactory(security: configuration.xraySecurityLayer, httpVersion: httpVersion,
                                     mode: mode, xmux: xhttpConfig.effectiveXMUX)
            : nil
        dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(), httpVersion: httpVersion, route: route,
            xhttp: xhttpConfig, mode: mode, sessionId: sessionId, role: .combined, uploadFactory: uploadFactory
        ) { [weak self] result in
            guard let self else {
                if case .success(let xhttpConnection) = result { xhttpConnection.cancel() }
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let xhttpConnection):
                self.own(xhttpConnection)
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
        Task { [weak self] in
            do {
                try await xhttpConnection.performSetup()
            } catch {
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
                supportsVision: self.transportSupportsVision, completion: completion
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
                if case .success(let uploadLeg) = uploadResult { uploadLeg.cancel() }
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch uploadResult {
            case .failure(let error):
                completion(.failure(error))
            case .success(let uploadLeg):
                // The download leg later re-owns this as coordinator (`uploadChannel`);
                // the double-cancel is idempotent.
                self.own(uploadLeg)
                self.dialXHTTPLeg(
                    endpoint: self.downloadXHTTPEndpoint(downloadSettings), httpVersion: downloadHTTPVersion,
                    route: .direct, xhttp: downloadSettings.xhttp, mode: mode, sessionId: sessionId,
                    role: .downloadOnly, uploadFactory: nil
                ) { [weak self] downloadResult in
                    guard let self else {
                        // Deallocation never fires the registry, so dispose both legs by hand.
                        uploadLeg.cancel()
                        if case .success(let downloadLeg) = downloadResult { downloadLeg.cancel() }
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    switch downloadResult {
                    case .failure(let error):
                        uploadLeg.cancel()
                        completion(.failure(error))
                    case .success(let downloadLeg):
                        // Download leg is the coordinator; it owns the upload leg.
                        downloadLeg.uploadChannel = uploadLeg
                        self.own(downloadLeg)
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
        uploadFactory: (() async throws -> AsyncTransportClosures)?,
        completion: @escaping (Result<XHTTPConnection, Error>) -> Void
    ) {
        // xmux: pool/multiplex direct-route XHTTP connections. XHTTP always pools — serial-reuse
        // defaults apply when xmux is omitted (see `effectiveXMUX`). Tunneled/chained routes
        // can't pool (single-use tunnel), so they fall through to a fresh dial below.
        if httpVersion == .http3, case .direct = route {
            acquirePooledH3(
                endpoint: endpoint, xmux: xhttp.effectiveXMUX, xhttp: xhttp,
                mode: mode, sessionId: sessionId, role: role, completion: completion
            )
            return
        }

        if httpVersion == .http2, case .direct = route {
            acquirePooledH2(
                endpoint: endpoint, xmux: xhttp.effectiveXMUX, xhttp: xhttp,
                mode: mode, sessionId: sessionId, role: role, completion: completion
            )
            return
        }

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
                        h3Multiplexer: session, configuration: xhttp, mode: mode, sessionId: sessionId
                    )
                }
                connection.role = role
                completion(.success(connection))
            }
        }
    }

    /// Acquires a shared, xmux-pooled HTTP/3 session for a direct-route XHTTP leg; the
    /// factory is destination-bound (captures no per-flow state) so the manager is reusable.
    private func acquirePooledH3(
        endpoint: XHTTPEndpoint,
        xmux: XHTTPXMUXMultiplexerConfiguration,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole,
        completion: @escaping (Result<XHTTPConnection, Error>) -> Void
    ) {
        let host = endpoint.directHost
        let port = endpoint.port
        let serverName = endpoint.serverName
        let key = "h3|\(host)|\(port)|\(serverName)"
        let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: xmux) {
            { connectionCompletion in
                // QUIC connects lazily, so a fresh session never fails at creation.
                connectionCompletion(HTTP3Multiplexer(host: host, port: port, serverName: serverName))
            }
        }
        manager.acquire { lease in
            guard let lease, let session = lease.connection as? HTTP3Multiplexer else {
                completion(.failure(ProxyError.connectionFailed("xmux H3 session acquisition failed")))
                return
            }
            let connection = XHTTPConnection(
                h3Multiplexer: session, configuration: xhttp, mode: mode, sessionId: sessionId
            )
            connection.role = role
            connection.xmuxLease = lease
            completion(.success(connection))
        }
    }

    /// Acquires a shared, xmux-pooled HTTP/2 connection for a direct-route XHTTP leg; the
    /// factory is destination-bound (captures no per-flow state) so the manager is reusable.
    private func acquirePooledH2(
        endpoint: XHTTPEndpoint,
        xmux: XHTTPXMUXMultiplexerConfiguration,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole,
        completion: @escaping (Result<XHTTPConnection, Error>) -> Void
    ) {
        let host = endpoint.directHost
        let port = endpoint.port
        let security = endpoint.security
        let serverName = endpoint.serverName
        let key = "h2|\(host)|\(port)|\(serverName)"
        let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: xmux) {
            { connectionCompletion in
                ProxyClient.dialSharedH2(host: host, port: port, security: security) { result in
                    switch result {
                    case .success(let shared): connectionCompletion(shared)
                    case .failure: connectionCompletion(nil)
                    }
                }
            }
        }
        manager.acquire { lease in
            guard let lease, let shared = lease.connection as? XHTTPH2Multiplexer else {
                completion(.failure(ProxyError.connectionFailed("xmux H2 connection acquisition failed")))
                return
            }
            let connection = XHTTPConnection(sharedH2: shared, configuration: xhttp, mode: mode, sessionId: sessionId)
            connection.role = role
            connection.xmuxLease = lease
            completion(.success(connection))
        }
    }

    /// Dials a byte stream and brings up a shared multiplexing H2 connection on it (xmux).
    /// Static so the pooled manager's factory captures no per-flow state; the dial client is
    /// retained by the shared connection for its lifetime.
    private static func dialSharedH2(
        host: String,
        port: UInt16,
        security: XraySecurityLayer,
        completion: @escaping (Result<XHTTPH2Multiplexer, Error>) -> Void
    ) {
        func bringUp(_ transport: AsyncTransportClosures, retaining object: AnyObject?) {
            let shared = XHTTPH2Multiplexer(transport: transport)
            if let object { shared.retain(object) }
            Task {
                do {
                    try await shared.connect()
                    completion(.success(shared))
                } catch {
                    completion(.failure(error))
                }
            }
        }
        switch security {
        case .none:
            let transport = TCPTransport(host: host, port: port)
            Task {
                do {
                    try await transport.connect()
                } catch {
                    completion(.failure(error))
                    return
                }
                bringUp(AsyncTransportClosures(transport), retaining: transport)
            }
        case .tls(let tlsConfig):
            // XHTTP rides h2; advertise it (fall back to http/1.1) regardless of the configured ALPN.
            let h2TLS = TLSConfiguration(
                serverName: tlsConfig.serverName, alpn: ["h2", "http/1.1"],
                echEnabled: tlsConfig.echEnabled, echConfig: tlsConfig.echConfig, fingerprint: tlsConfig.fingerprint
            )
            let client = TLSClient(configuration: h2TLS)
            client.connect(host: host, port: port) { result in
                switch result {
                case .success(let connection): bringUp(AsyncTransportClosures(tls: connection), retaining: client)
                case .failure(let error): completion(.failure(error))
                }
            }
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            client.connect(host: host, port: port) { result in
                switch result {
                case .success(let connection): bringUp(AsyncTransportClosures(tls: connection), retaining: client)
                case .failure(let error): completion(.failure(error))
                }
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
            Task { [weak self] in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                do {
                    let tunnel = try await self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands)
                    self.dialXHTTPByteStream(host: endpoint.chainHost, port: endpoint.port, security: endpoint.security,
                                             httpVersion: httpVersion, overTunnel: tunnel, completion: completion)
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    private func dialXHTTPByteStream(
        host: String,
        port: UInt16,
        security: XraySecurityLayer,
        httpVersion: XHTTPHTTPVersion,
        overTunnel: ProxyConnection?,
        completion: @escaping (Result<XHTTPDialedTransport, Error>) -> Void
    ) {
        switch security {
        case .none:
            if let tunnel = overTunnel {
                completion(.success(.byteStream(AsyncTransportClosures(proxyConnection: tunnel))))
            } else {
                let transport = TCPTransport(host: host, port: port)
                own(transport)
                Task {
                    do {
                        try await transport.connect()
                    } catch {
                        completion(.failure(error))
                        return
                    }
                    completion(.success(.byteStream(AsyncTransportClosures(transport))))
                }
            }
        case .tls(let tlsConfig):
            let client = TLSClient(configuration: sanitizedXHTTPTLSConfiguration(from: tlsConfig, httpVersion: httpVersion))
            own(client)
            let handle: (Result<TLSRecordConnection, Error>) -> Void = { result in
                completion(result.map { .byteStream(AsyncTransportClosures(tls: $0)) })
            }
            if let tunnel = overTunnel {
                client.connect(overTunnel: tunnel, completion: handle)
            } else {
                client.connect(host: host, port: port, completion: handle)
            }
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            own(client)
            let handle: (Result<TLSRecordConnection, Error>) -> Void = { result in
                completion(result.map { .byteStream(AsyncTransportClosures(tls: $0)) })
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
            .http3(HTTP3Multiplexer(host: host, port: endpoint.port, serverName: endpoint.serverName, transport: transport))
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
            Task { [weak self] in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                do {
                    let tunnel = try await self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopCommands: hopCommands)
                    completion(.success(makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))))
                } catch {
                    completion(.failure(error))
                }
            }
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
                { connectionCompletion in
                    ProxyClient.dialH1UploadConnection(host: host, port: port, security: sec) { connection in
                        connectionCompletion(connection)
                    }
                }
            }
            return {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<AsyncTransportClosures, Error>) in
                    manager.acquire { lease in
                        guard let lease, let connection = lease.connection as? XHTTPH1Multiplexer else {
                            continuation.resume(throwing: ProxyError.connectionFailed("xmux H1 upload acquisition failed"))
                            return
                        }
                        connection.lease = lease
                        continuation.resume(returning: connection.sessionClosures)
                    }
                }
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
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<AsyncTransportClosures, Error>) in
                self.dialXHTTPTransport(endpoint: self.mainXHTTPEndpoint(), httpVersion: httpVersion, route: route) { result in
                    switch result {
                    case .success(.byteStream(let closures)):
                        continuation.resume(returning: closures)
                    case .success(.http3):
                        continuation.resume(throwing: ProxyError.connectionFailed("HTTP/3 has no separate upload connection"))
                    case .failure(let error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
    }

    /// Dials a fresh HTTP/1.1 upload byte stream and wraps it as a poolable upload connection (xmux).
    /// Static so the pooled manager's factory captures no per-flow state.
    private static func dialH1UploadConnection(
        host: String,
        port: UInt16,
        security: XraySecurityLayer,
        completion: @escaping (XHTTPH1Multiplexer?) -> Void
    ) {
        func wrap(_ transport: AsyncTransportClosures, retaining object: AnyObject?) {
            let connection = XHTTPH1Multiplexer(transport: transport)
            if let object { connection.retain(object) }
            completion(connection)
        }
        switch security {
        case .none:
            let transport = TCPTransport(host: host, port: port)
            Task {
                do {
                    try await transport.connect()
                } catch {
                    completion(nil)
                    return
                }
                wrap(AsyncTransportClosures(transport), retaining: transport)
            }
        case .tls(let tlsConfig):
            let h1TLS = TLSConfiguration(
                serverName: tlsConfig.serverName, alpn: ["http/1.1"],
                echEnabled: tlsConfig.echEnabled, echConfig: tlsConfig.echConfig, fingerprint: tlsConfig.fingerprint
            )
            let client = TLSClient(configuration: h1TLS)
            client.connect(host: host, port: port) { result in
                switch result {
                case .success(let connection): wrap(AsyncTransportClosures(tls: connection), retaining: client)
                case .failure: completion(nil)
                }
            }
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            client.connect(host: host, port: port) { result in
                switch result {
                case .success(let connection): wrap(AsyncTransportClosures(tls: connection), retaining: client)
                case .failure: completion(nil)
                }
            }
        }
    }

}
