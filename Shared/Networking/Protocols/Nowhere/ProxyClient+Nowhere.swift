//
//  ProxyClient+Nowhere.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

extension ProxyClient {
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

        if asymmetric {
            do {
                let flowID = try NowhereTransportIdentityRegistry.shared.nextFlowID(for: identityKey)
                connectAsymmetricNowhere(
                    nwConfig: nwConfig,
                    command: command,
                    destination: destination,
                    flowID: flowID,
                    completion: completion
                )
            } catch {
                completion(.failure(error))
            }
            return
        }

        if uplink == .tcp {
            let mode: NowhereTCPRelayMode
            switch command {
            case .tcp:
                mode = .tcp
            case .udp:
                mode = .udp
            default:
                completion(.failure(ProxyError.dropped))
                return
            }
            if pool > 0, tunnel == nil {
                NowhereTCPConnectionPoolRegistry.shared.acquire(
                    configurationID: configuration.id,
                    configuration: nwConfig,
                    connectHost: directDialHost,
                    destination: destination,
                    mode: mode,
                    completion: completion
                )
                return
            }

            let connection = NowhereTCPConnection(
                configuration: nwConfig,
                connectHost: directDialHost,
                tunnel: tunnel
            )
            own(connection)
            tunnel = nil
            connection.openFresh(destination: destination, mode: mode) { error in
                if let error {
                    connection.cancel()
                    completion(.failure(error))
                } else {
                    switch mode {
                    case .tcp:
                        completion(.success(connection))
                    case .udp:
                        completion(.success(NowhereTCPUDPConnection(inner: connection)))
                    }
                }
            }
            return
        }

        if let chainTunnel = tunnel {
            let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
            self.tunnel = nil
            let client = NowhereClient.chained(configuration: nwConfig, transport: transport)
            dispatchNowhere(client: client, command: command, destination: destination, completion: completion)
            return
        }

        if let chain = configuration.chain, !chain.isEmpty {
            connectPooledChainedNowhere(
                nwConfig: nwConfig,
                chain: chain,
                command: command,
                destination: destination,
                completion: completion
            )
            return
        }

        let client = NowhereClient.shared(for: nwConfig)
        dispatchNowhere(client: client, command: command, destination: destination, completion: completion)
    }

    private func connectAsymmetricNowhere(
        nwConfig: NowhereConfiguration,
        command: ProxyCommand,
        destination: String,
        flowID: UInt64,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let kind: NowhereProtocol.FlowKind
        let mode: NowhereTCPRelayMode
        switch command {
        case .tcp, .mux:
            kind = .tcp
            mode = .tcp
        case .udp:
            kind = .udp
            mode = .udp
        }
        let open = NowhereProtocol.FlowHeader(
            role: .open, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )
        let attach = NowhereProtocol.FlowHeader(
            role: .attach, flowID: flowID, kind: kind,
            uplink: nwConfig.uplink, downlink: nwConfig.downlink
        )
        let lock = UnfairLock()
        var upResult: Result<ProxyConnection, Error>?
        var downResult: Result<ProxyConnection, Error>?
        var finished = false

        func receive(_ result: Result<ProxyConnection, Error>, isUplink: Bool) {
            let outcome: Result<ProxyConnection, Error>? = lock.withLock { () -> Result<ProxyConnection, Error>? in
                guard !finished else {
                    if case .success(let connection) = result { connection.cancel() }
                    return nil
                }
                if isUplink { upResult = result } else { downResult = result }
                guard let upResult, let downResult else { return nil }
                finished = true
                switch (upResult, downResult) {
                case (.success(let up), .success(let down)):
                    return .success(NowhereDirectionalConnection(uplink: up, downlink: down))
                case (.failure(let error), .success(let down)):
                    down.cancel(); return .failure(error)
                case (.success(let up), .failure(let error)):
                    up.cancel(); return .failure(error)
                case (.failure(let error), .failure(_)):
                    return .failure(error)
                }
            }
            if let outcome { completion(outcome) }
        }

        openAsymmetricHalf(
            nwConfig: nwConfig, destination: destination, mode: mode,
            header: open, carrier: nwConfig.uplink
        ) { receive($0, isUplink: true) }
        openAsymmetricHalf(
            nwConfig: nwConfig, destination: destination, mode: mode,
            header: attach, carrier: nwConfig.downlink
        ) { receive($0, isUplink: false) }
    }

    private func openAsymmetricHalf(
        nwConfig: NowhereConfiguration,
        destination: String,
        mode: NowhereTCPRelayMode,
        header: NowhereProtocol.FlowHeader,
        carrier: NowhereNetwork,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if carrier == .tcp {
            NowhereTCPConnectionPoolRegistry.shared.acquire(
                configurationID: configuration.id,
                configuration: nwConfig,
                connectHost: directDialHost,
                destination: destination,
                mode: mode,
                flowHeader: header,
                completion: completion
            )
            return
        }

        let client = NowhereClient.shared(for: nwConfig)
        if header.kind == .tcp {
            client.openTCPHalf(
                destination: destination,
                header: header,
                isDefaultProxy: isDefaultProxy,
                completion: completion
            )
            return
        }
        if header.role == .open {
            client.openUDP(
                destination: destination,
                flowID: header.flowID,
                downlink: header.downlink,
                isDefaultProxy: isDefaultProxy,
                completion: completion
            )
            return
        }

        client.openUDP(
            destination: destination,
            flowID: header.flowID,
            downlink: header.downlink,
            isDefaultProxy: isDefaultProxy
        ) { udpResult in
            switch udpResult {
            case .failure(let error): completion(.failure(error))
            case .success(let udp):
                client.openTCPHalf(
                    destination: destination,
                    header: header,
                    isDefaultProxy: self.isDefaultProxy
                ) { controlResult in
                    switch controlResult {
                    case .failure(let error): udp.cancel(); completion(.failure(error))
                    case .success(let control):
                        completion(.success(NowhereDirectionalConnection(uplink: control, downlink: udp)))
                    }
                }
            }
        }
    }

    private func dispatchNowhere(
        client: NowhereClient,
        command: ProxyCommand,
        destination: String,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        switch command {
        case .tcp, .mux:
            client.openTCP(destination: destination, isDefaultProxy: isDefaultProxy, completion: completion)
        case .udp:
            client.openUDP(destination: destination, isDefaultProxy: isDefaultProxy, completion: completion)
        }
    }

    private func connectPooledChainedNowhere(
        nwConfig: NowhereConfiguration,
        chain: [ProxyConfiguration],
        command: ProxyCommand,
        destination: String,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let chainSignature = chain.map { $0.id.uuidString }.joined(separator: ":")

        let cascadeCommands: [ProxyCommand]
        switch Self.computeChainHopCommands(
            chain: chain,
            outerProtocol: .nowhere,
            outerCommand: command
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
                var holders: [ProxyClient] = []
                let holdersLock = UnfairLock()
                ProxyClient.buildDetachedChainTunnel(
                    chain: chain,
                    hopCommands: cascadeCommands,
                    finalDestination: (nwServerAddress, nwServerPort),
                    useResolvedAddressForDirectDial: useResolvedAddress,
                    track: { client in
                        holdersLock.withLock { holders.append(client) }
                    }
                ) { result in
                    switch result {
                    case .success(let chainTunnel):
                        let snapshot = holdersLock.withLock { holders }
                        let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
                        builderCompletion(.success((transport, snapshot)))
                    case .failure(let error):
                        let snapshot = holdersLock.withLock { holders }
                        for c in snapshot { c.cancel() }
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
                            command: command,
                            destination: destination,
                            completion: completion
                        )
                    } else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated after pool acquire")))
                    }
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        )
    }
}
