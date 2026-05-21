//
//  ProxyClient+Hysteria.swift
//  Anywhere
//
//  Created by NodePassProject on 4/15/26.
//

import Foundation

extension ProxyClient {
    /// Connects through a Hysteria v2 server. Routes by chain context:
    /// direct (no chain) shares one QUIC session; chained outer pools per
    /// `(server, chain)`; chain link reuses the inbound tunnel per-flow.
    func connectWithHysteria(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let password = configuration.hysteriaPassword else {
            completion(.failure(ProxyError.protocolError("Hysteria password not set")))
            return
        }

        let hyConfig = HysteriaConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            password: password,
            sni: configuration.hysteriaSNI ?? configuration.serverAddress,
            congestionControl: configuration.hysteriaCongestionControl ?? .brutal,
            uploadMbps: configuration.hysteriaUploadMbps ?? HysteriaUploadMbpsDefault,
            downloadMbps: configuration.hysteriaDownloadMbps ?? 0
        )

        // RFC 3986 §3.2.2: IPv6 literals must be bracketed.
        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

        if let chainTunnel = tunnel {
            // Chain link: wrap the inbound UDP-relay tunnel as a per-flow client.
            let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
            self.tunnel = nil
            let client = HysteriaClient.chained(configuration: hyConfig, transport: transport)
            dispatchHysteria(client: client, command: command, destination: destination, completion: completion)
            return
        }

        if let chain = configuration.chain, !chain.isEmpty {
            connectPooledChainedHysteria(
                hyConfig: hyConfig,
                chain: chain,
                command: command,
                destination: destination,
                completion: completion
            )
            return
        }

        let client = HysteriaClient.shared(for: hyConfig)
        dispatchHysteria(client: client, command: command, destination: destination, completion: completion)
    }

    private func dispatchHysteria(
        client: HysteriaClient,
        command: ProxyCommand,
        destination: String,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        switch command {
        case .tcp, .mux:
            client.openTCP(destination: destination, completion: completion)
        case .udp:
            client.openUDP(destination: destination, completion: completion)
        }
    }

    /// Pooled chained dial via ``HysteriaClient/acquireChained``. On cache
    /// miss, builds the chain and hands its hops to the pool entry so they
    /// outlive any single flow.
    private func connectPooledChainedHysteria(
        hyConfig: HysteriaConfiguration,
        chain: [ProxyConfiguration],
        command: ProxyCommand,
        destination: String,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let chainSignature = chain.map { $0.id.uuidString }.joined(separator: ":")

        // Validate the chain synchronously so config errors don't get
        // deferred behind a pool registration.
        let cascadeCommands: [ProxyCommand]
        switch Self.computeChainHopCommands(
            chain: chain,
            outerProtocol: .hysteria,
            outerCommand: command
        ) {
        case .success(let cmds):
            cascadeCommands = cmds
        case .failure(let error):
            completion(.failure(error))
            return
        }

        let hyServerAddress = configuration.serverAddress
        let hyServerPort = configuration.serverPort
        let useResolvedAddress = useResolvedAddressForDirectDial

        HysteriaClient.acquireChained(
            configuration: hyConfig,
            chainSignature: chainSignature,
            // Builder is self-free: one build is shared across concurrent
            // `acquireChained` waiters, so it must outlive any single
            // caller's `ProxyClient`.
            builder: { builderCompletion in
                var holders: [ProxyClient] = []
                let holdersLock = UnfairLock()
                ProxyClient.buildDetachedChainTunnel(
                    chain: chain,
                    hopCommands: cascadeCommands,
                    finalDestination: (hyServerAddress, hyServerPort),
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
                        self.dispatchHysteria(
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
