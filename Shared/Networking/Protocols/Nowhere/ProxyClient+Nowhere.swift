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
        guard case .nowhere(let key, let spec, let tls) = configuration.outbound else {
            completion(.failure(ProxyError.protocolError("Nowhere key not set")))
            return
        }

        let nwConfig: NowhereConfiguration
        do {
            nwConfig = try NowhereConfiguration(
                proxyHost: configuration.serverAddress,
                proxyPort: configuration.serverPort,
                key: key,
                spec: spec,
                tls: tls
            )
        } catch {
            completion(.failure(error))
            return
        }

        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

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
