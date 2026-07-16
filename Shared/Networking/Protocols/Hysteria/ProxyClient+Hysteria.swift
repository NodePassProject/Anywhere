//
//  ProxyClient+Hysteria.swift
//  Anywhere
//
//  Created by NodePassProject on 4/15/26.
//

import Foundation
import Synchronization

extension ProxyClient {
    /// Connects through a Hysteria v2 server. Routes by chain context:
    /// direct (no chain) shares one QUIC session; chained outer pools per
    /// `(server, chain)`; chain link reuses the inbound tunnel per-flow.
    func connectWithHysteria(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        guard case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let obfuscation, let sni) = configuration.outbound else {
            throw ProxyError.protocolError("Hysteria password not set")
        }

        let hysteriaConfiguration = HysteriaConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            password: password,
            congestionControl: congestionControl,
            uploadMbps: uploadMbps,
            downloadMbps: downloadMbps,
            obfuscation: obfuscation,
            sni: sni
        )

        // RFC 3986 §3.2.2: IPv6 literals must be bracketed.
        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

        if let chainTunnel = tunnel {
            // Chain link: wrap the inbound UDP-relay tunnel as a per-flow client.
            let transport = ProxyConnectionDatagramTransport(connection: chainTunnel)
            self.tunnel = nil
            let client = HysteriaClient.chained(configuration: hysteriaConfiguration, transport: transport)
            return try await dispatchHysteria(client: client, command: command, destination: destination)
        }

        if let chain = configuration.chain, !chain.isEmpty {
            return try await connectPooledChainedHysteria(
                hysteriaConfiguration: hysteriaConfiguration,
                chain: chain,
                command: command,
                destination: destination
            )
        }

        let client = HysteriaClient.shared(for: hysteriaConfiguration)
        return try await dispatchHysteria(client: client, command: command, destination: destination)
    }

    private func dispatchHysteria(
        client: HysteriaClient,
        command: ProxyCommand,
        destination: String
    ) async throws -> ProxyConnection {
        switch command {
        case .tcp, .mux:
            return try await client.openTCP(destination: destination, isDefaultProxy: isDefaultProxy)
        case .udp:
            return try await client.openUDP(destination: destination, isDefaultProxy: isDefaultProxy)
        }
    }

    /// Acquires a pooled chained Hysteria client, building the chain on cache
    /// miss so that its hops outlive any single flow.
    private func connectPooledChainedHysteria(
        hysteriaConfiguration: HysteriaConfiguration,
        chain: [ProxyConfiguration],
        command: ProxyCommand,
        destination: String
    ) async throws -> ProxyConnection {
        let chainSignature = chain.map { $0.id.uuidString }.joined(separator: ":")

        // Validate the chain synchronously so config errors aren't deferred behind pool registration.
        let cascadeCommands: [ProxyCommand]
        switch Self.computeChainHopCommands(
            chain: chain,
            outerProtocol: .hysteria,
            outerCommand: command
        ) {
        case .success(let cmds):
            cascadeCommands = cmds
        case .failure(let error):
            throw error
        }

        let hyServerAddress = configuration.serverAddress
        let hyServerPort = configuration.serverPort
        let useResolvedAddress = useResolvedAddressForDirectDial

        let client = try await HysteriaClient.acquireChained(
            configuration: hysteriaConfiguration,
            chainSignature: chainSignature,
            // Builder must be self-free: one build is shared across concurrent
            // waiters and outlives any single caller's ProxyClient.
            builder: {
                let holders = Mutex<[ProxyClient]>([])
                do {
                    let chainTunnel = try await ProxyClient.buildDetachedChainTunnel(
                        chain: chain,
                        hopCommands: cascadeCommands,
                        finalDestination: (hyServerAddress, hyServerPort),
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
        return try await dispatchHysteria(client: client, command: command, destination: destination)
    }
}
