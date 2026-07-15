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
    func connectWithNowhere(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ProxyConnection, Error>) in
            self.connectWithNowhere(
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort
            ) { continuation.resume(with: $0) }
        }
    }

    /// Connects through a Nowhere server. The iOS TUN stack already splits
    /// TCP and UDP flows, so this goes directly to Nowhere stream/DATAGRAM
    /// sessions instead of using the SOCKS5 ingress.
    func connectWithNowhere(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .nowhere(let key, let spec, let uplink, let downlink, let pool, let securityLayer) = configuration.outbound else {
            completion(.failure(ProxyError.protocolError("Invalid Nowhere configuration")))
            return
        }
        guard let tls = securityLayer.tlsConfiguration else {
            completion(.failure(ProxyError.protocolError("Nowhere TLS configuration not set")))
            return
        }
        let normalizedSpec = NowhereProtocol.normalizedSpec(spec)

        let nwConfig: NowhereConfiguration
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
        do {
            let sessionID = try NowhereTransportIdentityRegistry.shared.identity(for: identityKey)
            nwConfig = try NowhereConfiguration(
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
        } catch {
            completion(.failure(error))
            return
        }

        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

        let asymmetric = uplink != downlink
        if asymmetric, tunnel != nil || configuration.chain?.isEmpty == false {
            completion(.failure(ProxyError.protocolError("Asymmetric Nowhere carriers do not support proxy chains")))
            return
        }

        if uplink != .tcp || downlink != .tcp || pool == 0 || tunnel != nil {
            NowhereTCPConnectionPoolRegistry.shared.disable(configurationID: configuration.id)
        }

        let configuredChainCanRebuildQUIC = configuration.chain?.isEmpty == false
            && uplink == .udp && downlink == .udp
        let retries = tunnel == nil || configuredChainCanRebuildQUIC ? 1 : 0
        let deadline = DispatchTime.now() + .seconds(30)

        connectLogicalNowhere(
            nwConfig: nwConfig,
            command: command,
            destination: destination,
            identityKey: identityKey,
            deadline: deadline,
            retriesLeft: retries,
            completion: completion
        )
    }

    private func connectLogicalNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: String,
        identityKey: NowhereTransportIdentityKey,
        deadline: DispatchTime,
        retriesLeft: Int,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let flowID: UInt64
        do {
            flowID = try NowhereTransportIdentityRegistry.shared.nextFlowID(
                for: identityKey,
                sessionID: nwConfig.sessionID
            )
        } catch {
            completion(.failure(error))
            return
        }

        let attempt = NowhereFlowOpenAttempt()
        attempt.armDeadline(at: deadline) {
            completion(.failure(NowhereError.flowOpenTimeout))
        }

        let finish: (Result<ProxyConnection, Error>) -> Void = { [weak self] result in
            guard attempt.claimResult() else {
                if case .success(let connection) = result { connection.cancel() }
                return
            }
            switch result {
            case .success:
                completion(result)
            case .failure(let error):
                attempt.cancel()
                if retriesLeft > 0,
                   Self.isRetryableLogicalNowhereError(error),
                   let self {
                    if Self.shouldInvalidateAsymmetricQUICSession(
                        error: error,
                        uplink: nwConfig.uplink,
                        downlink: nwConfig.downlink
                    ) {
                        NowhereClient.invalidateSharedSession(for: nwConfig)
                    }
                    self.connectLogicalNowhere(
                        nwConfig: nwConfig,
                        command: command,
                        destination: destination,
                        identityKey: identityKey,
                        deadline: deadline,
                        retriesLeft: retriesLeft - 1,
                        completion: completion
                    )
                } else {
                    completion(.failure(Self.underlyingLogicalNowhereError(error)))
                }
            }
        }

        if nwConfig.uplink != nwConfig.downlink {
            connectAsymmetricNowhere(
                nwConfig: nwConfig,
                command: command,
                destination: destination,
                flowID: flowID,
                attempt: attempt,
                completion: finish
            )
        } else {
            connectDuplexNowhere(
                nwConfig: nwConfig,
                command: command,
                destination: destination,
                flowID: flowID,
                attempt: attempt,
                completion: finish
            )
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
        attempt: NowhereFlowOpenAttempt,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let (kind, mode) = Self.flowKindAndMode(command) else {
            completion(.failure(ProxyError.dropped))
            return
        }
        let header = NowhereProtocol.FlowHeader(
            role: .duplex,
            flowID: flowID,
            kind: kind,
            uplink: nwConfig.uplink,
            downlink: nwConfig.downlink
        )

        if nwConfig.uplink == .tcp {
            let deliver: (Result<ProxyConnection, Error>) -> Void = { result in
                switch result {
                case .failure(let error):
                    completion(.failure(Self.logicalNowhereError(
                        error,
                        context: .tcpCarrier
                    )))
                case .success(let connection):
                    completion(.success(NowhereDirectionalConnection(
                        uplink: connection,
                        downlink: connection,
                        kind: kind
                    )))
                }
            }
            if nwConfig.pool > 0, tunnel == nil {
                NowhereTCPConnectionPoolRegistry.shared.acquire(
                    configurationID: configuration.id,
                    configuration: nwConfig,
                    connectHost: directDialHost,
                    destination: destination,
                    mode: mode,
                    flowHeader: header,
                    attempt: attempt,
                    completion: deliver
                )
                return
            }

            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: tunnel
            )
            guard own(connection) else {
                tunnel = nil
                completion(.failure(ProxyError.connectionFailed("Client released during connect")))
                return
            }
            guard attempt.bind(connection) else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            tunnel = nil
            connection.openFresh(destination: destination, mode: mode, flowHeader: header) { error in
                if let error {
                    connection.cancel()
                    deliver(.failure(error))
                } else {
                    let logical: ProxyConnection = mode == .tcp
                        ? connection
                        : NowhereTCPUDPConnection(inner: connection)
                    deliver(.success(logical))
                }
            }
            return
        }

        if let chainTunnel = tunnel {
            let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
            self.tunnel = nil
            let client = NowhereClient.chained(configuration: nwConfig, transport: transport)
            dispatchNowhere(
                client: client,
                header: header,
                attempt: attempt,
                destination: destination,
                completion: completion
            )
            return
        }

        if let chain = configuration.chain, !chain.isEmpty {
            connectPooledChainedNowhere(
                nwConfig: nwConfig,
                chain: chain,
                header: header,
                attempt: attempt,
                destination: destination,
                completion: completion
            )
            return
        }

        let client = NowhereClient.shared(for: nwConfig)
        dispatchNowhere(
            client: client,
            header: header,
            attempt: attempt,
            destination: destination,
            completion: completion
        )
    }

    private func connectAsymmetricNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: String,
        flowID: UInt64,
        attempt: NowhereFlowOpenAttempt,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let (kind, mode) = Self.flowKindAndMode(command) else {
            completion(.failure(ProxyError.dropped))
            return
        }
        let open = NowhereProtocol.FlowHeader(
            role: .open, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )
        let attach = NowhereProtocol.FlowHeader(
            role: .attach, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )
        struct JoinState {
            var uplink: ProxyConnection?
            var downlink: ProxyConnection?
            var finished = false
        }
        let join = Mutex(JoinState())

        func receive(_ result: Result<ProxyConnection, Error>, isUplink: Bool) {
            // First hard failure wins immediately and cancels the sibling setup.
            let (outcome, discard): (
                Result<ProxyConnection, Error>?, ProxyConnection?
            ) = join.withLock { state in
                guard !state.finished else {
                    if case .success(let connection) = result { return (nil, connection) }
                    return (nil, nil)
                }
                switch result {
                case .failure(let error):
                    state.finished = true
                    let carrier = isUplink ? nwConfig.uplink : nwConfig.downlink
                    let context: NowhereLogicalFailureContext = carrier == .udp
                        ? .quicSession : .tcpCarrier
                    return (.failure(Self.logicalNowhereError(
                        error,
                        context: context
                    )), nil)
                case .success(let connection):
                    if isUplink { state.uplink = connection } else { state.downlink = connection }
                }
                guard let up = state.uplink, let down = state.downlink else {
                    return (nil, nil)
                }
                state.finished = true
                return (.success(NowhereDirectionalConnection(
                    uplink: up,
                    downlink: down,
                    kind: kind
                )), nil)
            }
            discard?.cancel()
            if case .failure = outcome { attempt.cancel() }
            if let outcome { completion(outcome) }
        }

        openAsymmetricHalf(
            nwConfig: nwConfig, destination: destination, mode: mode,
            header: open, carrier: nwConfig.uplink, attempt: attempt
        ) { receive($0, isUplink: true) }
        openAsymmetricHalf(
            nwConfig: nwConfig, destination: destination, mode: mode,
            header: attach, carrier: nwConfig.downlink, attempt: attempt
        ) { receive($0, isUplink: false) }
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
        attempt: NowhereFlowOpenAttempt,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if carrier == .tcp {
            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: nil
            )
            guard own(connection) else {
                completion(.failure(ProxyError.connectionFailed("Client released during connect")))
                return
            }
            guard attempt.bind(connection) else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            connection.openFresh(destination: destination, mode: mode, flowHeader: header) { error in
                if let error {
                    connection.cancel()
                    completion(.failure(error))
                    return
                }
                switch mode {
                case .tcp:
                    completion(.success(connection))
                case .udp:
                    completion(.success(NowhereTCPUDPConnection(
                        inner: connection
                    )))
                }
            }
            return
        }

        let client = NowhereClient.shared(for: nwConfig)
        if header.kind == .tcp {
            client.openTCPHalf(
                destination: destination,
                header: header,
                attempt: attempt,
                isDefaultProxy: isDefaultProxy,
                completion: completion
            )
            return
        }
        client.openUDP(
            destination: destination,
            header: header,
            attempt: attempt,
            isDefaultProxy: isDefaultProxy,
            completion: completion
        )
    }

    private func dispatchNowhere(
        client: NowhereClient,
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt,
        destination: String,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let opened: (Result<ProxyConnection, Error>) -> Void = { result in
            switch result {
            case .failure(let error):
                completion(.failure(Self.logicalNowhereError(
                    error,
                    context: .quicSession
                )))
            case .success(let connection):
                completion(.success(NowhereDirectionalConnection(
                    uplink: connection,
                    downlink: connection,
                    kind: header.kind
                )))
            }
        }
        switch header.kind {
        case .tcp:
            client.openTCPHalf(
                destination: destination,
                header: header,
                attempt: attempt,
                isDefaultProxy: isDefaultProxy,
                completion: opened
            )
        case .udp:
            client.openUDP(
                destination: destination,
                header: header,
                attempt: attempt,
                isDefaultProxy: isDefaultProxy,
                completion: opened
            )
        }
    }

    private func connectPooledChainedNowhere(
        nwConfig: NowhereConfiguration,
        chain: [ProxyConfiguration],
        header: NowhereProtocol.FlowHeader,
        attempt: NowhereFlowOpenAttempt,
        destination: String,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
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
            completion(.failure(error))
            return
        }

        let nwServerAddress = configuration.serverAddress
        let nwServerPort = configuration.serverPort
        let useResolvedAddress = useResolvedAddressForDirectDial

        NowhereClient.acquireChained(
            configuration: nwConfig,
            chainSignature: chainSignature,
            builder: { builderCompletion in
                let holders = Mutex<[ProxyClient]>([])
                Task {
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
                        builderCompletion(.success((transport, snapshot)))
                    } catch {
                        let snapshot = holders.withLock { $0 }
                        for c in snapshot { await c.cancel() }
                        builderCompletion(.failure(error))
                    }
                }
            },
            completion: { [weak self] clientResult in
                switch clientResult {
                case .success(let client):
                    if let self {
                        self.dispatchNowhere(
                            client: client,
                            header: header,
                            attempt: attempt,
                            destination: destination,
                            completion: completion
                        )
                    } else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated after pool acquire")))
                    }
                case .failure(let error):
                    completion(.failure(Self.logicalNowhereError(
                        error,
                        context: .chainBuild
                    )))
                }
            }
        )
    }
}
