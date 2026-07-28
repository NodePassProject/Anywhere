//
//  ProxyClient+SOCKS5.swift
//  Anywhere
//
//  Created by NodePassProject on 4/15/26.
//

import Foundation

extension ProxyClient {
    func connectWithSOCKS5(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        guard case .socks5(let username, let password) = configuration.outbound else {
            throw AnywhereError.proxy(.socks5, .protocolViolation(detail: "SOCKS5 outbound expected"))
        }

        let transport: any ByteTransport
        if let tunnel = self.tunnel {
            transport = TunneledTransport(tunnel: tunnel)
        } else {
            let tcp = TCPTransport(host: directDialHost, port: configuration.serverPort, resolvesViaProxyDNS: true)
            try await tcp.connect()
            transport = tcp
        }

        let buffer = SOCKS5AsyncBuffer(transport: transport)
        
        do {
            if command == .udp {
                let relay = try await SOCKS5Handshake.performUDPAssociate(
                    buffer: buffer,
                    transport: transport,
                    username: username,
                    password: password,
                    serverAddress: configuration.serverAddress
                )
                let relayConnection = try await openSOCKS5UDPRelay(
                    relayHost: relay.host,
                    relayPort: relay.port
                )
                return SOCKS5UDPProxyConnection(
                    tcpTransport: transport,
                    relay: relayConnection,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort
                )
            } else {
                try await SOCKS5Handshake.perform(
                    buffer: buffer,
                    transport: transport,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    username: username,
                    password: password
                )
                let dataTransport: any ByteTransport
                if let excess = buffer.remaining {
                    dataTransport = SOCKS5ReplayTransport(inner: transport, initialData: excess)
                } else {
                    dataTransport = transport
                }
                return DirectProxyConnection(transport: dataTransport)
            }
        } catch {
            transport.cancel()
            throw error
        }
    }

    func openSOCKS5UDPRelay(
        relayHost: String,
        relayPort: UInt16
    ) async throws -> ProxyConnection {
        let effectiveChain: [ProxyConfiguration]
        if let outerChain = configuration.chain, !outerChain.isEmpty {
            effectiveChain = outerChain
        } else if !parentChain.isEmpty {
            effectiveChain = parentChain
        } else {
            effectiveChain = []
        }

        if !effectiveChain.isEmpty {
            let hopCommands = try Self.computeChainHopCommands(
                chain: effectiveChain, lastDeliver: .udp
            ).get()
            return try await buildChainTunnel(
                chain: effectiveChain, index: 0, currentTunnel: nil,
                hopCommands: hopCommands,
                finalDestination: (relayHost, relayPort)
            )
        } else {
            let transport = UDPTransport(host: relayHost, port: relayPort, resolvesViaProxyDNS: true)
            try await transport.connect()
            return DirectUDPProxyConnection(transport: transport)
        }
    }
}
