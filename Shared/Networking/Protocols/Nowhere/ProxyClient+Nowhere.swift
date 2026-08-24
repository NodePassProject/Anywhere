//
//  ProxyClient+Nowhere.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated private enum NowhereLogicalFailureContext {
    case quicSession
    case tcpCarrier
    case chainBuild
}

nonisolated private struct NowhereLogicalOpenError: Error {
    let underlying: Error
    let context: NowhereLogicalFailureContext
}

/// Keeps the session-scoped UInt32 flow ID reserved for the lifetime of the logical flow.
nonisolated private final class NowhereLeasedConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let lease: NowhereFlowIDLease

    init(inner: ProxyConnection, lease: NowhereFlowIDLease) {
        self.inner = inner
        self.lease = lease
    }

    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { inner.deliversDatagrams }
    var isConnected: Bool { inner.isConnected }

    func sendRaw(_ data: Data) async throws {
        do { try await inner.sendRaw(data) }
        catch {
            inner.abort()
            lease.release()
            throw error
        }
    }

    func receiveRaw() async throws -> Data? {
        do {
            let data = try await inner.receiveRaw()
            if data == nil { lease.release() }
            return data
        } catch {
            inner.abort()
            lease.release()
            throw error
        }
    }

    func cancel() {
        inner.cancel()
        lease.release()
    }

    func abort() {
        inner.abort()
        lease.release()
    }

    deinit { lease.release() }
}

nonisolated extension ProxyClient {
    /// Connects through a Nowhere server. The iOS TUN stack already splits
    /// TCP and UDP flows, so this goes directly to Nowhere stream/DATAGRAM
    /// sessions instead of using the SOCKS5 ingress.
    func connectWithNowhere(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard case .nowhere(let key, let uplink, let downlink, let multiplex, let securityLayer) = configuration.outbound else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Invalid Nowhere configuration"))
        }
        guard let tls = securityLayer.tlsConfiguration else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Nowhere TLS configuration not set"))
        }
        let effectiveMultiplex = multiplex && (uplink == .tcp || downlink == .tcp)
        let identityKey = NowhereTransportIdentityKey(
            configurationID: configuration.id,
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            key: key,
            uplink: uplink,
            downlink: downlink,
            multiplex: effectiveMultiplex,
            tls: tls
        )
        let sessionID = try NowhereTransportIdentityRegistry.shared.identity(for: identityKey)
        let nwConfig = try NowhereConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            key: key,
            uplink: uplink,
            downlink: downlink,
            multiplex: effectiveMultiplex,
            sessionID: sessionID,
            tls: tls
        )

        let destination = try NowhereProtocol.Target(host: destinationHost, port: destinationPort)

        let asymmetric = uplink != downlink
        if asymmetric, !nwConfig.multiplex,
           tunnel != nil || configuration.chain?.isEmpty == false {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Asymmetric Nowhere carriers do not support proxy chains"))
        }

        let configuredChainCanRebuildQUIC = configuration.chain?.isEmpty == false
            && (uplink == .udp && downlink == .udp || nwConfig.multiplex)
        let retries = tunnel == nil || configuredChainCanRebuildQUIC ? 1 : 0
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))

        return try await connectLogicalNowhere(
            nwConfig: nwConfig,
            command: command,
            destination: destination,
            initialData: command == .tcp ? initialData : nil,
            identityKey: identityKey,
            deadline: deadline,
            retriesLeft: retries
        )
    }

    private func connectLogicalNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: NowhereProtocol.Target,
        initialData: Data?,
        identityKey: NowhereTransportIdentityKey,
        deadline: ContinuousClock.Instant,
        retriesLeft: Int
    ) async throws -> ProxyConnection {
        // The idle-close timer / SessionReplaced can race an open; retries share the
        // absolute 30 s `deadline` so the total budget spans all attempts.
        var retriesLeft = retriesLeft
        while true {
            let flowLease = try NowhereTransportIdentityRegistry.shared.leaseFlowID(
                for: identityKey,
                sessionID: nwConfig.sessionID
            )
            let flowID = flowLease.flowID

            let attempt = NowhereFlowOpenAttempt()
            do {
                let remaining = ContinuousClock.now.duration(to: deadline)
                guard remaining > .zero else {
                    throw AnywhereError.proxy(.nowhere, .openTimeout)
                }
                let connection = try await withDialDeadline(
                    remaining,
                    onExpiry: { attempt.cancel() },
                    error: { AnywhereError.proxy(.nowhere, .openTimeout) },
                    discardingLateResult: { $0.cancel() }
                ) { [weak self] in
                    guard let self else { throw AnywhereError.transport(.terminated) }
                    if nwConfig.uplink != nwConfig.downlink {
                        return try await self.connectAsymmetricNowhere(
                            nwConfig: nwConfig,
                            command: command,
                            destination: destination,
                            initialData: initialData,
                            flowID: flowID,
                            attempt: attempt
                        )
                    }
                    return try await self.connectDuplexNowhere(
                        nwConfig: nwConfig,
                        command: command,
                        destination: destination,
                        initialData: initialData,
                        flowID: flowID,
                        attempt: attempt
                    )
                }
                return NowhereLeasedConnection(inner: connection, lease: flowLease)
            } catch {
                attempt.cancel()
                flowLease.release()
                let explicitReplacement: Bool = {
                    guard case AnywhereError.proxy(.nowhere, .flowRejected(let code)) = Self.underlyingLogicalNowhereFailure(error),
                          code == NowhereProtocol.FlowRejectCode.sessionReplaced.rawValue else { return false }
                    return true
                }()
                let replaySafe = !attempt.hasStartedEarlyDataWrite || explicitReplacement
                if retriesLeft > 0, replaySafe, Self.isRetryableLogicalNowhereFailure(error) {
                    if explicitReplacement, nwConfig.multiplex {
                        NowhereMultiplexerRegistry.shared.invalidate(
                            configurationID: configuration.id
                        )
                    }
                    if Self.shouldInvalidateAsymmetricQUICSession(
                        error: error,
                        uplink: nwConfig.uplink,
                        downlink: nwConfig.downlink
                    ) {
                        NowhereClient.invalidateSharedSession(for: nwConfig)
                    }
                    retriesLeft -= 1
                    continue
                }
                throw Self.underlyingLogicalNowhereFailure(error)
            }
        }
    }

    private static func isRetryableLogicalNowhereFailure(_ error: Error) -> Bool {
        let tagged = error as? NowhereLogicalOpenError
        guard case AnywhereError.proxy(.nowhere, let failure) = (tagged?.underlying ?? error) else {
            return false
        }
        switch failure {
        case .flowRejected(let code) where code == NowhereProtocol.FlowRejectCode.sessionReplaced.rawValue:
            return true
        case .notReady, .streamClosed:
            return tagged?.context == .quicSession
        default:
            return false
        }
    }

    private static func logicalNowhereFailure(
        _ error: Error,
        context: NowhereLogicalFailureContext
    ) -> Error {
        NowhereLogicalOpenError(underlying: error, context: context)
    }

    private static func underlyingLogicalNowhereFailure(_ error: Error) -> Error {
        (error as? NowhereLogicalOpenError)?.underlying ?? error
    }

    static func shouldInvalidateAsymmetricQUICSession(
        error: Error,
        uplink: NowhereNetwork,
        downlink: NowhereNetwork
    ) -> Bool {
        guard uplink != downlink,
              (uplink == .udp || downlink == .udp),
              case AnywhereError.proxy(.nowhere, .flowRejected(let code)) = underlyingLogicalNowhereFailure(error),
              code == NowhereProtocol.FlowRejectCode.sessionReplaced.rawValue else {
            return false
        }
        return true
    }

    private func connectDuplexNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: NowhereProtocol.Target,
        initialData: Data?,
        flowID: UInt32,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        guard let (kind, mode) = Self.flowKindAndMode(command) else {
            throw AnywhereError.routing(.dropped)
        }
        let header = NowhereProtocol.FlowHeader(
            role: .duplex,
            flowID: flowID,
            kind: kind,
            uplink: nwConfig.uplink,
            downlink: nwConfig.downlink
        )

        if nwConfig.uplink == .tcp {
            if nwConfig.multiplex {
                let inheritedTunnel = tunnel
                if inheritedTunnel != nil { setChainTunnel(nil) }
                let chain = inheritedTunnel == nil ? configuredNowhereChain : nil
                do {
                    let connection = try await openNowhereMultiplexerHalf(
                        nwConfig: nwConfig,
                        destination: destination,
                        flowHeader: header,
                        initialData: initialData,
                        attempt: attempt,
                        providedTunnel: inheritedTunnel,
                        chain: chain
                    )
                    let logical: ProxyConnection = mode == .tcp
                        ? connection
                        : NowhereTCPUDPConnection(inner: connection)
                    return NowhereDirectionalConnection(
                        uplink: logical,
                        downlink: logical,
                        kind: kind
                    )
                } catch {
                    inheritedTunnel?.cancel()
                    throw Self.logicalNowhereFailure(error, context: .tcpCarrier)
                }
            }

            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: tunnel
            )
            guard !isCancelled else {
                setChainTunnel(nil)
                connection.cancel()
                throw AnywhereError.transport(.terminated)
            }
            guard attempt.bind(connection) else {
                connection.cancel()
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
            setChainTunnel(nil)
            do {
                try await connection.openFresh(
                    destination: destination,
                    flowHeader: header,
                    initialData: initialData,
                    attempt: attempt
                )
            } catch {
                connection.cancel()
                throw Self.logicalNowhereFailure(error, context: .tcpCarrier)
            }
            let logical: ProxyConnection = mode == .tcp
                ? connection
                : NowhereTCPUDPConnection(inner: connection)
            return NowhereDirectionalConnection(
                uplink: logical,
                downlink: logical,
                kind: kind
            )
        }

        if let chainTunnel = tunnel {
            let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
            setChainTunnel(nil)
            let client = NowhereClient.chained(configuration: nwConfig, transport: transport)
            return try await dispatchNowhere(
                client: client,
                header: header,
                attempt: attempt,
                destination: destination,
                initialData: initialData
            )
        }

        if let chain = configuration.chain, !chain.isEmpty {
            return try await connectPooledChainedNowhere(
                nwConfig: nwConfig,
                chain: chain,
                header: header,
                attempt: attempt,
                destination: destination,
                initialData: initialData
            )
        }

        let client = try NowhereClient.shared(for: nwConfig)
        return try await dispatchNowhere(
            client: client,
            header: header,
            attempt: attempt,
            destination: destination,
            initialData: initialData
        )
    }

    private func connectAsymmetricNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: NowhereProtocol.Target,
        initialData: Data?,
        flowID: UInt32,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        guard let (kind, mode) = Self.flowKindAndMode(command) else {
            throw AnywhereError.routing(.dropped)
        }
        let open = NowhereProtocol.FlowHeader(
            role: .open, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )
        let attach = NowhereProtocol.FlowHeader(
            role: .attach, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )

        let inheritedUplinkTunnel = tunnel
        if inheritedUplinkTunnel != nil { setChainTunnel(nil) }
        let rebuiltChain: [ProxyConfiguration]?
        if inheritedUplinkTunnel != nil {
            guard !parentChain.isEmpty else {
                inheritedUplinkTunnel?.cancel()
                throw AnywhereError.proxy(
                    .nowhere,
                    .protocolViolation(detail: "Mixed Nowhere Multiplexer needs a rebuildable parent chain for its second carrier")
                )
            }
            rebuiltChain = parentChain
        } else {
            rebuiltChain = configuredNowhereChain
        }
        if let rebuiltChain {
            let carriersToRebuild: [NowhereNetwork] = inheritedUplinkTunnel == nil
                ? [nwConfig.uplink, nwConfig.downlink]
                : [nwConfig.downlink]
            do {
                for carrier in carriersToRebuild {
                    let deliver: ProxyCommand = carrier == .tcp ? .tcp : .udp
                    _ = try Self.computeChainHopCommands(
                        chain: rebuiltChain,
                        lastDeliver: deliver
                    ).get()
                }
            } catch {
                inheritedUplinkTunnel?.cancel()
                throw error
            }
        }

        // Race the two carrier halves; the first hard failure aborts the sibling. A half
        // that already succeeded is bound to `attempt`, so the caller's teardown reaches it.
        return try await withThrowingTaskGroup(of: (isUplink: Bool, connection: ProxyConnection).self) { group in
            group.addTask {
                do {
                    let connection = try await self.openAsymmetricHalf(
                        nwConfig: nwConfig, destination: destination, mode: mode,
                        header: open, carrier: nwConfig.uplink, attempt: attempt,
                        initialData: initialData,
                        providedTunnel: inheritedUplinkTunnel,
                        chain: inheritedUplinkTunnel == nil ? rebuiltChain : nil
                    )
                    return (true, connection)
                } catch {
                    throw Self.logicalNowhereFailure(
                        error, context: nwConfig.uplink == .udp ? .quicSession : .tcpCarrier
                    )
                }
            }
            group.addTask {
                do {
                    let connection = try await self.openAsymmetricHalf(
                        nwConfig: nwConfig, destination: destination, mode: mode,
                        header: attach, carrier: nwConfig.downlink, attempt: attempt,
                        initialData: nil,
                        providedTunnel: nil,
                        chain: rebuiltChain
                    )
                    return (false, connection)
                } catch {
                    throw Self.logicalNowhereFailure(
                        error, context: nwConfig.downlink == .udp ? .quicSession : .tcpCarrier
                    )
                }
            }

            var uplink: ProxyConnection?
            var downlink: ProxyConnection?
            do {
                for try await result in group {
                    if result.isUplink { uplink = result.connection }
                    else { downlink = result.connection }
                }
            } catch {
                // First hard failure aborts the sibling: cancelling the attempt tears down
                // the already-bound (or in-flight) half so its open unblocks promptly, then
                // the group drains before we rethrow.
                attempt.cancel()
                inheritedUplinkTunnel?.cancel()
                group.cancelAll()
                throw error
            }
            guard let uplink, let downlink else {
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
            if let activatable = uplink as? NowhereUDPConnection {
                activatable.activatePairedFlow()
            }
            return NowhereDirectionalConnection(
                uplink: uplink,
                downlink: downlink,
                kind: kind
            )
        }
    }

    private static func flowKindAndMode(
        _ command: ProxyCommand
    ) -> (NowhereProtocol.FlowKind, NowhereTCPRelayMode)? {
        switch command {
        case .tcp, .mux: return (.tcp, .tcp)
        case .udp: return (.udp, .udp)
        }
    }

    private func openAsymmetricHalf(
        nwConfig: NowhereConfiguration,
        destination: NowhereProtocol.Target,
        mode: NowhereTCPRelayMode,
        header: NowhereProtocol.FlowHeader,
        carrier: NowhereNetwork,
        attempt: NowhereFlowOpenAttempt,
        initialData: Data?,
        providedTunnel: ProxyConnection?,
        chain: [ProxyConfiguration]?
    ) async throws -> ProxyConnection {
        if carrier == .tcp {
            if nwConfig.multiplex {
                let connection = try await openNowhereMultiplexerHalf(
                    nwConfig: nwConfig,
                    destination: destination,
                    flowHeader: header,
                    initialData: initialData,
                    attempt: attempt,
                    providedTunnel: providedTunnel,
                    chain: chain
                )
                switch mode {
                case .tcp:
                    return connection
                case .udp:
                    return NowhereTCPUDPConnection(inner: connection)
                }
            }

            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: nil
            )
            guard !isCancelled else {
                connection.cancel()
                throw AnywhereError.transport(.terminated)
            }
            guard attempt.bind(connection) else {
                connection.cancel()
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
            do {
                try await connection.openFresh(
                    destination: destination,
                    flowHeader: header,
                    initialData: initialData,
                    attempt: attempt
                )
            } catch {
                connection.cancel()
                throw error
            }
            switch mode {
            case .tcp:
                return connection
            case .udp:
                return NowhereTCPUDPConnection(inner: connection)
            }
        }

        let client: NowhereClient
        if let providedTunnel {
            client = NowhereClient.chained(
                configuration: nwConfig,
                transport: ProxyConnectionDatagramTransport(connection: providedTunnel)
            )
        } else if let chain, !chain.isEmpty {
            client = try await acquireChainedNowhereClient(
                nwConfig: nwConfig,
                chain: chain,
                lastDeliver: .udp
            )
        } else {
            client = try NowhereClient.shared(for: nwConfig)
        }
        if header.kind == .tcp {
            return try await client.openTCPHalf(
                destination: destination,
                header: header,
                initialData: initialData,
                attempt: attempt
            )
        }
        return try await client.openUDP(
            destination: destination,
            header: header,
            attempt: attempt
        )
    }

    private func dispatchNowhere(
        client: NowhereClient,
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt,
        destination: NowhereProtocol.Target,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let connection: ProxyConnection
        do {
            switch header.kind {
            case .tcp:
                connection = try await client.openTCPHalf(
                    destination: destination,
                    header: header,
                    initialData: initialData,
                    attempt: attempt
                )
            case .udp:
                connection = try await client.openUDP(
                    destination: destination,
                    header: header,
                    attempt: attempt
                )
            }
        } catch {
            throw Self.logicalNowhereFailure(error, context: .quicSession)
        }
        return NowhereDirectionalConnection(
            uplink: connection,
            downlink: connection,
            kind: header.kind
        )
    }

    private func openNowhereMultiplexerHalf(
        nwConfig: NowhereConfiguration,
        destination: NowhereProtocol.Target,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt,
        providedTunnel: ProxyConnection?,
        chain: [ProxyConfiguration]?
    ) async throws -> ProxyConnection {
        let stream: NowhereMultiplexerStream
        let ownedMultiplexer: NowhereMultiplexer?

        if let providedTunnel {
            let multiplexer = try await Self.makeNowhereMultiplexer(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: providedTunnel
            )
            do {
                stream = try await multiplexer.openStream(flowID: flowHeader.flowID)
                ownedMultiplexer = multiplexer
            } catch {
                multiplexer.abort()
                throw error
            }
        } else {
            let multiplexerChain: [ProxyConfiguration]
            let multiplexerBuilder: @Sendable () async throws -> NowhereMultiplexer
            let connectHost = directDialHost

            if let chain, !chain.isEmpty {
                let cascadeCommands = try Self.computeChainHopCommands(
                    chain: chain,
                    lastDeliver: .tcp
                ).get()
                multiplexerChain = chain
                let proxyHost = configuration.serverAddress
                let proxyPort = configuration.serverPort
                let useResolvedAddress = useResolvedAddressForDirectDial
                multiplexerBuilder = {
                    let holders = Mutex<[ProxyClient]>([])
                    do {
                        let tunnel = try await ProxyClient.buildDetachedChainTunnel(
                            chain: chain,
                            hopCommands: cascadeCommands,
                            finalDestination: (proxyHost, proxyPort),
                            useResolvedAddressForDirectDial: useResolvedAddress,
                            track: { client in holders.withLock { $0.append(client) } }
                        )
                        let snapshot = holders.withLock { $0 }
                        return try await Self.makeNowhereMultiplexer(
                            configuration: nwConfig,
                            connectHost: connectHost,
                            tunnel: tunnel,
                            chainHolders: snapshot
                        )
                    } catch {
                        let snapshot = holders.withLock { $0 }
                        for client in snapshot { await client.cancel() }
                        throw error
                    }
                }
            } else {
                multiplexerChain = []
                multiplexerBuilder = {
                    try await Self.makeNowhereMultiplexer(
                        configuration: nwConfig,
                        connectHost: connectHost,
                        tunnel: nil
                    )
                }
            }

            stream = try await NowhereMultiplexerRegistry.shared.acquire(
                configurationID: configuration.id,
                configuration: nwConfig,
                connectHost: connectHost,
                chain: multiplexerChain,
                flowID: flowHeader.flowID,
                builder: multiplexerBuilder
            )
            ownedMultiplexer = nil
        }

        let connection = NowhereMultiplexerConnection(
            stream: stream,
            ownedMultiplexer: ownedMultiplexer
        )
        guard !isCancelled, attempt.bind(connection) else {
            connection.abort()
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await connection.open(
                destination: destination,
                flowHeader: flowHeader,
                initialData: initialData,
                attempt: attempt
            )
            return connection
        } catch {
            connection.abort()
            throw error
        }
    }

    private static func makeNowhereMultiplexer(
        configuration: NowhereConfiguration,
        connectHost: String,
        tunnel: ProxyConnection?,
        chainHolders: [ProxyClient] = []
    ) async throws -> NowhereMultiplexer {
        let client = TLSClient(configuration: configuration.tcpTLSConfiguration)
        let record: TLSRecordConnection
        if let tunnel {
            record = try await client.connect(overTunnel: tunnel)
        } else {
            record = try await client.connect(
                host: connectHost,
                port: configuration.proxyPort
            )
        }

        do {
            guard configuration.acceptsNegotiatedALPN(record.negotiatedALPN) else {
                throw AnywhereError.tls(.handshakeFailed(
                    detail: "Portal did not negotiate the configured ALPN"
                ))
            }
            let exporter = try record.exportKeyingMaterial(
                label: "EXPORTER-Nowhere-Auth",
                context: Data(),
                length: 32
            )
            let auth = try NowhereProtocol.makeAuthFrame(
                authKey: configuration.authKey,
                transport: .tlsTCP,
                exporter: exporter,
                sessionID: configuration.sessionID
            )
            let transport = TLSByteTransport(record)
            var bootstrap = auth
            bootstrap.append(NowhereMultiplexerConstants.marker)
            do {
                try await transport.send(bootstrap)
            } catch {
                transport.cancel()
                throw error
            }
            return NowhereMultiplexer(
                transport: transport,
                tlsVersion: TLSVersion(rawValue: record.tlsVersion),
                chainHolders: chainHolders
            )
        } catch {
            record.cancel()
            throw error
        }
    }

    private func connectPooledChainedNowhere(
        nwConfig: NowhereConfiguration,
        chain: [ProxyConfiguration],
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt,
        destination: NowhereProtocol.Target,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let client: NowhereClient
        do {
            client = try await acquireChainedNowhereClient(
                nwConfig: nwConfig,
                chain: chain,
                lastDeliver: .udp
            )
        } catch {
            throw Self.logicalNowhereFailure(error, context: .chainBuild)
        }
        return try await dispatchNowhere(
            client: client,
            header: header,
            attempt: attempt,
            destination: destination,
            initialData: initialData
        )
    }

    private var configuredNowhereChain: [ProxyConfiguration]? {
        if let chain = configuration.chain, !chain.isEmpty { return chain }
        return nil
    }

    private func acquireChainedNowhereClient(
        nwConfig: NowhereConfiguration,
        chain: [ProxyConfiguration],
        lastDeliver: ProxyCommand
    ) async throws -> NowhereClient {
        let cascadeCommands = try Self.computeChainHopCommands(
            chain: chain,
            lastDeliver: lastDeliver
        ).get()
        let nwServerAddress = configuration.serverAddress
        let nwServerPort = configuration.serverPort
        let useResolvedAddress = useResolvedAddressForDirectDial

        return try await NowhereClient.acquireChained(
            configuration: nwConfig,
            chain: chain,
            builder: {
                let holders = Mutex<[ProxyClient]>([])
                do {
                    let chainTunnel = try await ProxyClient.buildDetachedChainTunnel(
                        chain: chain,
                        hopCommands: cascadeCommands,
                        finalDestination: (nwServerAddress, nwServerPort),
                        useResolvedAddressForDirectDial: useResolvedAddress,
                        track: { client in holders.withLock { $0.append(client) } }
                    )
                    let snapshot = holders.withLock { $0 }
                    return (
                        ProxyConnectionDatagramTransport(connection: chainTunnel),
                        snapshot
                    )
                } catch {
                    let snapshot = holders.withLock { $0 }
                    for client in snapshot { await client.cancel() }
                    throw error
                }
            }
        )
    }
}
