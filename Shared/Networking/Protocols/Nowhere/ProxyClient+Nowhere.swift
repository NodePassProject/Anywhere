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
        catch { lease.release(); throw error }
    }

    func receiveRaw() async throws -> Data? {
        do {
            let data = try await inner.receiveRaw()
            if data == nil { lease.release() }
            return data
        } catch {
            lease.release()
            throw error
        }
    }

    func cancel() {
        lease.release()
        inner.cancel()
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
        guard case .nowhere(let key, let uplink, let downlink, let pool, let securityLayer) = configuration.outbound else {
            throw ProxyError.protocolError("Invalid Nowhere configuration")
        }
        guard let tls = securityLayer.tlsConfiguration else {
            throw ProxyError.protocolError("Nowhere TLS configuration not set")
        }
        let identityKey = NowhereTransportIdentityKey(
            configurationID: configuration.id,
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            key: key,
            uplink: uplink,
            downlink: downlink,
            tls: tls
        )
        let sessionID = try NowhereTransportIdentityRegistry.shared.identity(for: identityKey)
        let nwConfig = try NowhereConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            key: key,
            uplink: uplink,
            downlink: downlink,
            pool: pool,
            sessionID: sessionID,
            tls: tls
        )

        let destination = try NowhereProtocol.Target(host: destinationHost, port: destinationPort)

        let asymmetric = uplink != downlink
        if asymmetric, tunnel != nil || configuration.chain?.isEmpty == false {
            throw ProxyError.protocolError("Asymmetric Nowhere carriers do not support proxy chains")
        }

        if uplink != .tcp || downlink != .tcp || pool == 0 || tunnel != nil {
            NowhereTCPConnectionPoolRegistry.shared.disable(configurationID: configuration.id)
        }

        let configuredChainCanRebuildQUIC = configuration.chain?.isEmpty == false
            && uplink == .udp && downlink == .udp
        let retries = tunnel == nil || configuredChainCanRebuildQUIC ? 1 : 0
        let deadline = DispatchTime.now() + .seconds(30)

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
        deadline: DispatchTime,
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
                // Single-winner race: the open (success/failure) vs. the deadline, resolved by
                // `attempt.claimResult()` — the winner returns/throws, the loser returns nil and is
                // torn down. Structured `withThrowingTaskGroup`, so the loser is cancelled on exit.
                let connection = try await withThrowingTaskGroup(of: ProxyConnection?.self) { group in
                    group.addTask { [weak self] in
                        guard let self else {
                            if attempt.claimResult() {
                                throw ProxyError.connectionFailed("Client deallocated during connect")
                            }
                            return nil
                        }
                        do {
                            let opened: ProxyConnection
                            if nwConfig.uplink != nwConfig.downlink {
                                opened = try await self.connectAsymmetricNowhere(
                                    nwConfig: nwConfig,
                                    command: command,
                                    destination: destination,
                                    initialData: initialData,
                                    flowID: flowID,
                                    attempt: attempt
                                )
                            } else {
                                opened = try await self.connectDuplexNowhere(
                                    nwConfig: nwConfig,
                                    command: command,
                                    destination: destination,
                                    initialData: initialData,
                                    flowID: flowID,
                                    attempt: attempt
                                )
                            }
                            if attempt.claimResult() { return opened }
                            opened.cancel()   // the deadline already won
                            return nil
                        } catch {
                            if attempt.claimResult() { throw error }
                            return nil
                        }
                    }
                    group.addTask {
                        // Mirrors the former `armDeadline`: sleep to the shared absolute deadline,
                        // then claim + tear down bound halves before failing.
                        let nowNanos = DispatchTime.now().uptimeNanoseconds
                        let deadlineNanos = deadline.uptimeNanoseconds
                        let delayNanos = deadlineNanos > nowNanos ? deadlineNanos - nowNanos : 0
                        try? await Task.sleep(nanoseconds: delayNanos)
                        guard !Task.isCancelled, attempt.claimResult() else { return nil }
                        attempt.cancel()
                        throw NowhereError.flowOpenTimeout
                    }
                    defer { group.cancelAll() }
                    while let result = try await group.next() {
                        if let opened = result { return opened }
                        // nil = this task lost the claim; await the winner.
                    }
                    throw NowhereError.flowOpenTimeout
                }
                return NowhereLeasedConnection(inner: connection, lease: flowLease)
            } catch {
                attempt.cancel()
                flowLease.release()
                let explicitReplacement: Bool = {
                    guard let nowhere = Self.underlyingLogicalNowhereError(error) as? NowhereError,
                          case .flowRejected(.sessionReplaced) = nowhere else { return false }
                    return true
                }()
                let replaySafe = !attempt.hasStartedEarlyDataWrite || explicitReplacement
                if retriesLeft > 0, replaySafe, Self.isRetryableLogicalNowhereError(error) {
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
                throw Self.underlyingLogicalNowhereError(error)
            }
        }
    }

    private static func isRetryableLogicalNowhereError(_ error: Error) -> Bool {
        let tagged = error as? NowhereLogicalOpenError
        guard let nowhereError = (tagged?.underlying ?? error) as? NowhereError else {
            return false
        }
        switch nowhereError {
        case .flowRejected(.sessionReplaced):
            return true
        case .notReady, .streamClosed:
            return tagged?.context == .quicSession
        case .connectionFailed, .authFailed, .invalidTargetLength,
             .destinationTooLargeForDatagram, .udpPacketTooLarge,
             .flowRejected, .flowOpenTimeout:
            return false
        }
    }

    private static func logicalNowhereError(
        _ error: Error,
        context: NowhereLogicalFailureContext
    ) -> Error {
        NowhereLogicalOpenError(underlying: error, context: context)
    }

    private static func underlyingLogicalNowhereError(_ error: Error) -> Error {
        (error as? NowhereLogicalOpenError)?.underlying ?? error
    }

    static func shouldInvalidateAsymmetricQUICSession(
        error: Error,
        uplink: NowhereNetwork,
        downlink: NowhereNetwork
    ) -> Bool {
        guard uplink != downlink,
              (uplink == .udp || downlink == .udp),
              let nowhereError = underlyingLogicalNowhereError(error) as? NowhereError,
              case .flowRejected(.sessionReplaced) = nowhereError else {
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
            throw ProxyError.dropped
        }
        let header = NowhereProtocol.FlowHeader(
            role: .duplex,
            flowID: flowID,
            kind: kind,
            uplink: nwConfig.uplink,
            downlink: nwConfig.downlink
        )

        if nwConfig.uplink == .tcp {
            if nwConfig.pool > 0, tunnel == nil {
                let connection: ProxyConnection
                do {
                    connection = try await NowhereTCPConnectionPoolRegistry.shared.acquire(
                        configurationID: configuration.id,
                        configuration: nwConfig,
                        connectHost: directDialHost,
                        destination: destination,
                        mode: mode,
                        flowHeader: header,
                        initialData: initialData,
                        attempt: attempt
                    )
                } catch {
                    throw Self.logicalNowhereError(error, context: .tcpCarrier)
                }
                return NowhereDirectionalConnection(
                    uplink: connection,
                    downlink: connection,
                    kind: kind
                )
            }

            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: tunnel
            )
            guard !isCancelled else {
                setChainTunnel(nil)
                connection.cancel()
                throw ProxyError.connectionFailed("Client released during connect")
            }
            guard attempt.bind(connection) else {
                connection.cancel()
                throw NowhereError.streamClosed
            }
            setChainTunnel(nil)
            do {
                try await connection.openFresh(
                    destination: destination,
                    mode: mode,
                    flowHeader: header,
                    initialData: initialData,
                    attempt: attempt
                )
            } catch {
                connection.cancel()
                throw Self.logicalNowhereError(error, context: .tcpCarrier)
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

        let client = NowhereClient.shared(for: nwConfig)
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
            throw ProxyError.dropped
        }
        let open = NowhereProtocol.FlowHeader(
            role: .open, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )
        let attach = NowhereProtocol.FlowHeader(
            role: .attach, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )

        // Race the two carrier halves; the first hard failure aborts the sibling. A half
        // that already succeeded is bound to `attempt`, so the caller's teardown reaches it.
        return try await withThrowingTaskGroup(of: (isUplink: Bool, connection: ProxyConnection).self) { group in
            group.addTask {
                do {
                    let connection = try await self.openAsymmetricHalf(
                        nwConfig: nwConfig, destination: destination, mode: mode,
                        header: open, carrier: nwConfig.uplink, attempt: attempt,
                        initialData: initialData
                    )
                    return (true, connection)
                } catch {
                    throw Self.logicalNowhereError(
                        error, context: nwConfig.uplink == .udp ? .quicSession : .tcpCarrier
                    )
                }
            }
            group.addTask {
                do {
                    let connection = try await self.openAsymmetricHalf(
                        nwConfig: nwConfig, destination: destination, mode: mode,
                        header: attach, carrier: nwConfig.downlink, attempt: attempt,
                        initialData: nil
                    )
                    return (false, connection)
                } catch {
                    throw Self.logicalNowhereError(
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
                group.cancelAll()
                throw error
            }
            guard let uplink, let downlink else {
                throw NowhereError.streamClosed
            }
            if let activatable = uplink as? NowhereUDPConnection {
                await activatable.activatePairedFlow()
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
        initialData: Data?
    ) async throws -> ProxyConnection {
        if carrier == .tcp {
            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: nil
            )
            guard !isCancelled else {
                connection.cancel()
                throw ProxyError.connectionFailed("Client released during connect")
            }
            guard attempt.bind(connection) else {
                connection.cancel()
                throw NowhereError.streamClosed
            }
            do {
                try await connection.openFresh(
                    destination: destination,
                    mode: mode,
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

        let client = NowhereClient.shared(for: nwConfig)
        if header.kind == .tcp {
            return try await client.openTCPHalf(
                destination: destination,
                header: header,
                initialData: initialData,
                attempt: attempt,
                isDefaultProxy: isDefaultProxy
            )
        }
        return try await client.openUDP(
            destination: destination,
            header: header,
            attempt: attempt,
            isDefaultProxy: isDefaultProxy
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
                    attempt: attempt,
                    isDefaultProxy: isDefaultProxy
                )
            case .udp:
                connection = try await client.openUDP(
                    destination: destination,
                    header: header,
                    attempt: attempt,
                    isDefaultProxy: isDefaultProxy
                )
            }
        } catch {
            throw Self.logicalNowhereError(error, context: .quicSession)
        }
        return NowhereDirectionalConnection(
            uplink: connection,
            downlink: connection,
            kind: header.kind
        )
    }

    private func connectPooledChainedNowhere(
        nwConfig: NowhereConfiguration,
        chain: [ProxyConfiguration],
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt,
        destination: NowhereProtocol.Target,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let chainSignature = chain.map { $0.id.uuidString }.joined(separator: ":")

        let cascadeCommands: [ProxyCommand]
        switch Self.computeChainHopCommands(
            chain: chain,
            outerProtocol: .nowhere,
            outerCommand: header.kind == .udp ? .udp : .tcp
        ) {
        case .success(let cmds):
            cascadeCommands = cmds
        case .failure(let error):
            throw error
        }

        let nwServerAddress = configuration.serverAddress
        let nwServerPort = configuration.serverPort
        let useResolvedAddress = useResolvedAddressForDirectDial

        let client: NowhereClient
        do {
            client = try await NowhereClient.acquireChained(
                configuration: nwConfig,
                chainSignature: chainSignature,
                // Builder must be self-free: one build is shared across concurrent
                // waiters and outlives any single caller's ProxyClient.
                builder: {
                    let holders = Mutex<[ProxyClient]>([])
                    do {
                        let chainTunnel = try await ProxyClient.buildDetachedChainTunnel(
                            chain: chain,
                            hopCommands: cascadeCommands,
                            finalDestination: (nwServerAddress, nwServerPort),
                            useResolvedAddressForDirectDial: useResolvedAddress,
                            track: { client in
                                holders.withLock { $0.append(client) }
                            }
                        )
                        let snapshot = holders.withLock { $0 }
                        let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
                        return (transport, snapshot)
                    } catch {
                        let snapshot = holders.withLock { $0 }
                        for c in snapshot { await c.cancel() }
                        throw error
                    }
                }
            )
        } catch {
            throw Self.logicalNowhereError(error, context: .chainBuild)
        }
        return try await dispatchNowhere(
            client: client,
            header: header,
            attempt: attempt,
            destination: destination,
            initialData: initialData
        )
    }
}
