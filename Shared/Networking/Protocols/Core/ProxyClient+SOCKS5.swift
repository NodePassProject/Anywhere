//
//  ProxyClient+SOCKS5.swift
//  Anywhere
//
//  Created by NodePassProject on 4/15/26.
//

import Foundation

extension ProxyClient {
    /// Connects through a SOCKS5 proxy server.
    ///
    /// Supports three modes:
    /// - **TCP CONNECT**: SOCKS5 handshake → raw bidirectional tunnel.
    /// - **UDP ASSOCIATE**: SOCKS5 handshake → UDP relay via ``SOCKS5UDPProxyConnection``.
    /// - **TLS**: When `security == "tls"`, wraps the TCP connection with TLS before the handshake.
    func connectWithSOCKS5(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        connectSOCKS5Direct(
            command: command,
            destinationHost: destinationHost, destinationPort: destinationPort,
            completion: completion
        )
    }

    /// SOCKS5 over plain TCP: TCP → SOCKS5 handshake.
    private func connectSOCKS5Direct(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let onTransportReady: (any RawTransport) -> Void = { [weak self] transport in
            self?.performSOCKS5Handshake(
                transport: transport,
                command: command, destinationHost: destinationHost,
                destinationPort: destinationPort, completion: completion
            )
        }

        if let tunnel = self.tunnel {
            onTransportReady(TunneledTransport(tunnel: tunnel))
        } else {
            let transport = RawTCPSocket()
            self.connection = transport
            transport.connect(host: directDialHost, port: configuration.serverPort) { error in
                if let error {
                    completion(.failure(error))
                    return
                }
                onTransportReady(transport)
            }
        }
    }

    /// Performs the SOCKS5 handshake, dispatching on `.udp` for UDP ASSOCIATE
    /// or CONNECT otherwise.
    private func performSOCKS5Handshake(
        transport: any RawTransport,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let buffer = SOCKS5Buffer(transport: transport)

        if command == .udp {
            SOCKS5Handshake.performUDPAssociate(
                buffer: buffer,
                transport: transport,
                username: configuration.socks5Username,
                password: configuration.socks5Password,
                serverAddress: configuration.serverAddress
            ) { [weak self] result in
                guard let self else {
                    completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                    return
                }
                switch result {
                case .success(let relay):
                    // For chained outbounds, the relay socket must ride the
                    // same chain as the control channel.
                    self.openSOCKS5UDPRelay(
                        relayHost: relay.host,
                        relayPort: relay.port
                    ) { relayResult in
                        switch relayResult {
                        case .success(let relayConn):
                            let udpConnection = SOCKS5UDPProxyConnection(
                                tcpTransport: transport,
                                tlsClient: nil,
                                tlsConnection: nil,
                                relay: relayConn,
                                destinationHost: destinationHost,
                                destinationPort: destinationPort
                            )
                            completion(.success(udpConnection))
                        case .failure(let error):
                            completion(.failure(error))
                        }
                    }
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        } else {
            SOCKS5Handshake.perform(
                buffer: buffer,
                transport: transport,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                username: configuration.socks5Username,
                password: configuration.socks5Password
            ) { error in
                if let error {
                    completion(.failure(error))
                    return
                }
                let wrappedTransport: any RawTransport
                if let excess = buffer.remaining {
                    wrappedTransport = SOCKS5Transport(inner: transport, initialData: excess)
                } else {
                    wrappedTransport = transport
                }
                let proxyConnection = DirectProxyConnection(connection: wrappedTransport)
                completion(.success(proxyConnection))
            }
        }
    }

    /// Opens a UDP-shaped `ProxyConnection` aimed at the SOCKS5 relay address.
    /// Rebuilds the chain (outer chain or inherited `parentChain`) so the
    /// relay rides the proxied path; falls back to a kernel UDP socket
    /// otherwise.
    func openSOCKS5UDPRelay(
        relayHost: String,
        relayPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let effectiveChain: [ProxyConfiguration]
        if let outerChain = configuration.chain, !outerChain.isEmpty {
            effectiveChain = outerChain
        } else if !parentChain.isEmpty {
            effectiveChain = parentChain
        } else {
            effectiveChain = []
        }
        if !effectiveChain.isEmpty {
            let chain = effectiveChain
            switch Self.computeChainHopCommands(chain: chain, lastDeliver: .udp) {
            case .success(let hopCommands):
                buildChainTunnel(
                    chain: chain, index: 0, currentTunnel: nil,
                    hopCommands: hopCommands,
                    finalDestination: (relayHost, relayPort),
                    completion: completion
                )
            case .failure(let error):
                completion(.failure(error))
            }
        } else {
            let socket = RawUDPSocket()
            socket.connect(host: relayHost, port: relayPort,
                           completionQueue: .global()) { error in
                if let error {
                    completion(.failure(error))
                    return
                }
                completion(.success(DirectUDPProxyConnection(socket: socket)))
            }
        }
    }
}
