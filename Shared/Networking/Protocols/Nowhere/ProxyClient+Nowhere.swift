//
//  ProxyClient+Nowhere.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

private enum NowhereLogicalFailureContext {
    case quicSession
    case tcpCarrier
    case chainBuild
}

private struct NowhereLogicalOpenError: Error {
    let underlying: Error
    let context: NowhereLogicalFailureContext
}

extension ProxyClient {
    /// Connects through a Nowhere server. The iOS TUN stack already splits
    /// TCP and UDP flows, so this goes directly to Nowhere stream/DATAGRAM
    /// sessions instead of using the SOCKS5 ingress.
    func connectWithNowhere(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        guard case .nowhere(let key, let spec, let uplink, let downlink, let pool, let securityLayer) = configuration.outbound else {
            throw ProxyError.protocolError("Invalid Nowhere configuration")
        }
        guard let tls = securityLayer.tlsConfiguration else {
            throw ProxyError.protocolError("Nowhere TLS configuration not set")
        }
        let normalizedSpec = NowhereProtocol.normalizedSpec(spec)

        let identityKey = NowhereTransportIdentityKey(
            configurationID: configuration.id,
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            key: key,
            spec: normalizedSpec,
            uplink: uplink,
            downlink: downlink,
            tls: tls
        )
        let sessionID = try NowhereTransportIdentityRegistry.shared.identity(for: identityKey)
        let nwConfig = try NowhereConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            key: key,
            spec: normalizedSpec,
            uplink: uplink,
            downlink: downlink,
            pool: pool,
            sessionID: sessionID,
            tls: tls
        )

        // RFC 3986 §3.2.2: IPv6 literals must be bracketed.
        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

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
            identityKey: identityKey,
            deadline: deadline,
            retriesLeft: retries
        )
    }

    private func connectLogicalNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: String,
        identityKey: NowhereTransportIdentityKey,
        deadline: DispatchTime,
        retriesLeft: Int
    ) async throws -> ProxyConnection {
        // The idle-close timer / SessionReplaced can race an open; retries share the
        // absolute 30 s `deadline` so the total budget spans all attempts.
        var retriesLeft = retriesLeft
        while true {
            let flowID = try NowhereTransportIdentityRegistry.shared.nextFlowID(
                for: identityKey,
                sessionID: nwConfig.sessionID
            )

            let attempt = NowhereFlowOpenAttempt()
            do {
                let connection = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ProxyConnection, Error>) in
                    // Single-winner gate: the deadline, or the open (success/failure), whichever
                    // claims first. The deadline handler tears down bound halves before failing.
                    attempt.armDeadline(at: deadline) {
                        continuation.resume(throwing: NowhereError.flowOpenTimeout)
                    }
                    Task { [weak self] in
                        guard let self else {
                            if attempt.claimResult() {
                                continuation.resume(throwing: ProxyError.connectionFailed("Client deallocated during connect"))
                            }
                            return
                        }
                        do {
                            let opened: ProxyConnection
                            if nwConfig.uplink != nwConfig.downlink {
                                opened = try await self.connectAsymmetricNowhere(
                                    nwConfig: nwConfig,
                                    command: command,
                                    destination: destination,
                                    flowID: flowID,
                                    attempt: attempt
                                )
                            } else {
                                opened = try await self.connectDuplexNowhere(
                                    nwConfig: nwConfig,
                                    command: command,
                                    destination: destination,
                                    flowID: flowID,
                                    attempt: attempt
                                )
                            }
                            if attempt.claimResult() {
                                continuation.resume(returning: opened)
                            } else {
                                opened.cancel()   // the deadline already won
                            }
                        } catch {
                            if attempt.claimResult() {
                                continuation.resume(throwing: error)
                            }
                        }
                    }
                }
                return connection
            } catch {
                attempt.cancel()
                if retriesLeft > 0, Self.isRetryableLogicalNowhereError(error) {
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
        destination: String,
        flowID: UInt64,
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
                tunnel = nil
                connection.cancel()
                throw ProxyError.connectionFailed("Client released during connect")
            }
            guard attempt.bind(connection) else {
                connection.cancel()
                throw NowhereError.streamClosed
            }
            tunnel = nil
            do {
                try await connection.openFresh(destination: destination, mode: mode, flowHeader: header)
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
            self.tunnel = nil
            let client = NowhereClient.chained(configuration: nwConfig, transport: transport)
            return try await dispatchNowhere(
                client: client,
                header: header,
                attempt: attempt,
                destination: destination
            )
        }

        if let chain = configuration.chain, !chain.isEmpty {
            return try await connectPooledChainedNowhere(
                nwConfig: nwConfig,
                chain: chain,
                header: header,
                attempt: attempt,
                destination: destination
            )
        }

        let client = NowhereClient.shared(for: nwConfig)
        return try await dispatchNowhere(
            client: client,
            header: header,
            attempt: attempt,
            destination: destination
        )
    }

    private func connectAsymmetricNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: String,
        flowID: UInt64,
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
                        header: open, carrier: nwConfig.uplink, attempt: attempt
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
                        header: attach, carrier: nwConfig.downlink, attempt: attempt
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
        destination: String,
        mode: NowhereTCPRelayMode,
        header: NowhereProtocol.FlowHeader,
        carrier: NowhereNetwork,
        attempt: NowhereFlowOpenAttempt
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
                try await connection.openFresh(destination: destination, mode: mode, flowHeader: header)
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
        destination: String
    ) async throws -> ProxyConnection {
        let connection: ProxyConnection
        do {
            switch header.kind {
            case .tcp:
                connection = try await client.openTCPHalf(
                    destination: destination,
                    header: header,
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
        destination: String
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
            destination: destination
        )
    }
}
