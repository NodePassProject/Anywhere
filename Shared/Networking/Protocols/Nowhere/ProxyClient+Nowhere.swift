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
    func connectWithNowhere(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard case .nowhere(let nowhere) = configuration.outbound else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Invalid Nowhere configuration"))
        }
        let key = nowhere.key
        let uplink = nowhere.uplink
        let downlink = nowhere.downlink
        let ports = nowhere.resolvedPorts(serverPort: configuration.serverPort)
        let transportIdentity = NowhereTransportIdentity(
            configurationID: configuration.id,
            proxyHost: configuration.serverAddress,
            proxyTCPPort: ports.tcp,
            proxyUDPPort: ports.udp,
            key: key,
            uplink: uplink,
            downlink: downlink,
            multiplex: nowhere.multiplex,
            morph: nowhere.morph,
            morphPrelude: nowhere.morphPrelude,
            serverName: nowhere.serverName
        )
        let sessionID = try NowhereTransportIdentityRegistry.shared.sessionID(for: transportIdentity)
        let runtimeConfiguration = try NowhereRuntimeConfiguration(
            proxyHost: configuration.serverAddress,
            proxyTCPPort: ports.tcp,
            proxyUDPPort: ports.udp,
            key: key,
            uplink: uplink,
            downlink: downlink,
            multiplex: nowhere.multiplex,
            morph: nowhere.morph,
            morphPrelude: nowhere.morphPrelude,
            sessionID: sessionID,
            serverName: nowhere.serverName
        )

        let destination = try NowhereProtocol.Target(host: request.host, port: request.port)

        let asymmetric = uplink != downlink
        if asymmetric, !runtimeConfiguration.multiplex,
           tunnel != nil || configuration.chain?.isEmpty == false {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Asymmetric Nowhere carriers do not support proxy chains"))
        }

        let configuredChainCanRebuildQUIC = configuration.chain?.isEmpty == false
            && (uplink == .udp && downlink == .udp || runtimeConfiguration.multiplex)
        let retries = tunnel == nil || configuredChainCanRebuildQUIC ? 1 : 0
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))

        return try await connectLogicalNowhere(
            runtimeConfiguration: runtimeConfiguration,
            network: request.network,
            destination: destination,
            initialData: request.network == .tcp ? request.initialData : nil,
            transportIdentity: transportIdentity,
            deadline: deadline,
            retriesLeft: retries
        )
    }

    private func connectLogicalNowhere(
        runtimeConfiguration: NowhereRuntimeConfiguration,
        network: ProxyNetwork,
        destination: NowhereProtocol.Target,
        initialData: Data?,
        transportIdentity: NowhereTransportIdentity,
        deadline: ContinuousClock.Instant,
        retriesLeft: Int
    ) async throws -> ProxyConnection {
        var retriesLeft = retriesLeft
        while true {
            let flowLease = try NowhereTransportIdentityRegistry.shared.leaseFlowID(
                for: transportIdentity,
                sessionID: runtimeConfiguration.sessionID
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
                    if runtimeConfiguration.uplink != runtimeConfiguration.downlink {
                        return try await self.connectAsymmetricNowhere(
                            runtimeConfiguration: runtimeConfiguration,
                            network: network,
                            destination: destination,
                            initialData: initialData,
                            flowID: flowID,
                            attempt: attempt
                        )
                    }
                    return try await self.connectDuplexNowhere(
                        runtimeConfiguration: runtimeConfiguration,
                        network: network,
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
                    if explicitReplacement, runtimeConfiguration.multiplex {
                        NowhereMultiplexerRegistry.shared.invalidate(
                            configurationID: configuration.id
                        )
                    }
                    if Self.shouldInvalidateAsymmetricQUICSession(
                        error: error,
                        uplink: runtimeConfiguration.uplink,
                        downlink: runtimeConfiguration.downlink
                    ) {
                        NowhereClient.invalidateSharedSession(for: runtimeConfiguration)
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
        runtimeConfiguration: NowhereRuntimeConfiguration,
        network: ProxyNetwork,
        destination: NowhereProtocol.Target,
        initialData: Data?,
        flowID: UInt32,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        let (kind, mode) = Self.flowKindAndMode(network)
        let header = NowhereProtocol.FlowHeader(
            role: .duplex,
            flowID: flowID,
            kind: kind,
            uplink: runtimeConfiguration.uplink,
            downlink: runtimeConfiguration.downlink
        )

        if runtimeConfiguration.uplink == .tcp {
            if runtimeConfiguration.multiplex {
                let inheritedTunnel = tunnel
                if inheritedTunnel != nil { setChainTunnel(nil) }
                let chain = inheritedTunnel == nil ? configuredNowhereChain : nil
                do {
                    let connection = try await openNowhereMultiplexerHalf(
                        runtimeConfiguration: runtimeConfiguration,
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
                configuration: runtimeConfiguration,
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
            let client = NowhereClient.chained(configuration: runtimeConfiguration, transport: transport)
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
                runtimeConfiguration: runtimeConfiguration,
                chain: chain,
                header: header,
                attempt: attempt,
                destination: destination,
                initialData: initialData
            )
        }

        let client = try NowhereClient.shared(for: runtimeConfiguration)
        return try await dispatchNowhere(
            client: client,
            header: header,
            attempt: attempt,
            destination: destination,
            initialData: initialData
        )
    }

    private func connectAsymmetricNowhere(
        runtimeConfiguration: NowhereRuntimeConfiguration,
        network: ProxyNetwork,
        destination: NowhereProtocol.Target,
        initialData: Data?,
        flowID: UInt32,
        attempt: NowhereFlowOpenAttempt
    ) async throws -> ProxyConnection {
        let (kind, mode) = Self.flowKindAndMode(network)
        let open = NowhereProtocol.FlowHeader(
            role: .open, flowID: flowID, kind: kind,
            uplink: runtimeConfiguration.uplink, downlink: runtimeConfiguration.downlink
        )
        let attach = NowhereProtocol.FlowHeader(
            role: .attach, flowID: flowID, kind: kind,
            uplink: runtimeConfiguration.uplink, downlink: runtimeConfiguration.downlink
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
                ? [runtimeConfiguration.uplink, runtimeConfiguration.downlink]
                : [runtimeConfiguration.downlink]
            do {
                for carrier in carriersToRebuild {
                    let deliver: ProxyNetwork = carrier == .tcp ? .tcp : .udp
                    _ = try Self.computeChainHopNetworks(
                        chain: rebuiltChain,
                        lastDeliver: deliver
                    ).get()
                }
            } catch {
                inheritedUplinkTunnel?.cancel()
                throw error
            }
        }

        return try await withThrowingTaskGroup(of: (isUplink: Bool, connection: ProxyConnection).self) { group in
            group.addTask {
                do {
                    let connection = try await self.openAsymmetricHalf(
                        runtimeConfiguration: runtimeConfiguration, destination: destination, mode: mode,
                        header: open, carrier: runtimeConfiguration.uplink, attempt: attempt,
                        initialData: initialData,
                        providedTunnel: inheritedUplinkTunnel,
                        chain: inheritedUplinkTunnel == nil ? rebuiltChain : nil
                    )
                    return (true, connection)
                } catch {
                    throw Self.logicalNowhereFailure(
                        error, context: runtimeConfiguration.uplink == .udp ? .quicSession : .tcpCarrier
                    )
                }
            }
            group.addTask {
                do {
                    let connection = try await self.openAsymmetricHalf(
                        runtimeConfiguration: runtimeConfiguration, destination: destination, mode: mode,
                        header: attach, carrier: runtimeConfiguration.downlink, attempt: attempt,
                        initialData: nil,
                        providedTunnel: nil,
                        chain: rebuiltChain
                    )
                    return (false, connection)
                } catch {
                    throw Self.logicalNowhereFailure(
                        error, context: runtimeConfiguration.downlink == .udp ? .quicSession : .tcpCarrier
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
        _ network: ProxyNetwork
    ) -> (NowhereProtocol.FlowKind, NowhereTCPRelayMode) {
        switch network {
        case .tcp: (.tcp, .tcp)
        case .udp: (.udp, .udp)
        }
    }

    private func openAsymmetricHalf(
        runtimeConfiguration: NowhereRuntimeConfiguration,
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
            if runtimeConfiguration.multiplex {
                let connection = try await openNowhereMultiplexerHalf(
                    runtimeConfiguration: runtimeConfiguration,
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
                configuration: runtimeConfiguration,
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
                configuration: runtimeConfiguration,
                transport: ProxyConnectionDatagramTransport(connection: providedTunnel)
            )
        } else if let chain, !chain.isEmpty {
            client = try await acquireChainedNowhereClient(
                runtimeConfiguration: runtimeConfiguration,
                chain: chain,
                lastDeliver: .udp
            )
        } else {
            client = try NowhereClient.shared(for: runtimeConfiguration)
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
        runtimeConfiguration: NowhereRuntimeConfiguration,
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
                configuration: runtimeConfiguration,
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
                let cascadeNetworks = try Self.computeChainHopNetworks(
                    chain: chain,
                    lastDeliver: .tcp
                ).get()
                multiplexerChain = chain
                let proxyHost = configuration.serverAddress
                let proxyPort = try runtimeConfiguration.proxyPort(for: .tcp)
                let useResolvedAddress = useResolvedAddressForDirectDial
                multiplexerBuilder = {
                    let holders = Mutex<[ProxyClient]>([])
                    do {
                        let tunnel = try await ProxyClient.buildDetachedChainTunnel(
                            chain: chain,
                            hopNetworks: cascadeNetworks,
                            finalDestination: (proxyHost, proxyPort),
                            useResolvedAddressForDirectDial: useResolvedAddress,
                            track: { client in holders.withLock { $0.append(client) } }
                        )
                        let snapshot = holders.withLock { $0 }
                        return try await Self.makeNowhereMultiplexer(
                            configuration: runtimeConfiguration,
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
                        configuration: runtimeConfiguration,
                        connectHost: connectHost,
                        tunnel: nil
                    )
                }
            }

            stream = try await NowhereMultiplexerRegistry.shared.acquire(
                configurationID: configuration.id,
                configuration: runtimeConfiguration,
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
        configuration: NowhereRuntimeConfiguration,
        connectHost: String,
        tunnel: ProxyConnection?,
        chainHolders: [ProxyClient] = []
    ) async throws -> NowhereMultiplexer {
        let client = TLSClient(configuration: configuration.tlsConfiguration)
        let record: TLSRecordConnection
        if configuration.morph {
            let base: any ByteTransport
            if let tunnel {
                base = TunneledTransport(tunnel: tunnel)
            } else {
                let tcp = TCPTransport(
                    host: connectHost,
                    port: try configuration.proxyPort(for: .tcp),
                    resolution: .proxies
                )
                try await tcp.connect()
                base = tcp
            }
            guard let keys = configuration.morphKeys else {
                base.cancel()
                throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Missing Morph keys"))
            }
            record = try await NowhereMorph.connectTLS(
                client: client,
                base: base,
                keys: keys,
                prelude: configuration.morphPrelude
            )
        } else if let tunnel {
            record = try await client.connect(overTunnel: tunnel)
        } else {
            record = try await client.connect(
                host: connectHost,
                port: try configuration.proxyPort(for: .tcp)
            )
        }

        do {
            guard record.negotiatedALPN == NowhereProtocol.applicationProtocol else {
                throw AnywhereError.tls(.handshakeFailed(
                    detail: "Portal did not negotiate the Nowhere application protocol"
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
            bootstrap.append(try NowhereMultiplexerFrameHeader.window(
                flowID: 0,
                creditUnits: Int(NowhereMultiplexerConstants.connectionWindowExtensionUnits)
            ).encode())
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
        runtimeConfiguration: NowhereRuntimeConfiguration,
        chain: [ProxyConfiguration],
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt,
        destination: NowhereProtocol.Target,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let client: NowhereClient
        do {
            client = try await acquireChainedNowhereClient(
                runtimeConfiguration: runtimeConfiguration,
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
        runtimeConfiguration: NowhereRuntimeConfiguration,
        chain: [ProxyConfiguration],
        lastDeliver: ProxyNetwork
    ) async throws -> NowhereClient {
        let cascadeNetworks = try Self.computeChainHopNetworks(
            chain: chain,
            lastDeliver: lastDeliver
        ).get()
        let serverAddress = configuration.serverAddress
        let serverPort = try runtimeConfiguration.proxyPort(for: .udp)
        let useResolvedAddress = useResolvedAddressForDirectDial

        return try await NowhereClient.acquireChained(
            configuration: runtimeConfiguration,
            chain: chain,
            builder: {
                let holders = Mutex<[ProxyClient]>([])
                do {
                    let chainTunnel = try await ProxyClient.buildDetachedChainTunnel(
                        chain: chain,
                        hopNetworks: cascadeNetworks,
                        finalDestination: (serverAddress, serverPort),
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
