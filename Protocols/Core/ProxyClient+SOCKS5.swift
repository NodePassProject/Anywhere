//
//  ProxyClient+SOCKS5.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/15/26.
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

    /// SOCKS5 over TLS: TCP → TLS handshake → SOCKS5 handshake.
    /// Performs the SOCKS5 handshake and returns the appropriate connection.
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
            ) { result in
                switch result {
                case .success(let relay):
                    let udpConnection = SOCKS5UDPProxyConnection(
                        tcpTransport: transport,
                        tlsClient: nil,
                        tlsConnection: nil,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort
                    )
                    udpConnection.connectRelay(relayHost: relay.host, relayPort: relay.port) { error in
                        if let error {
                            completion(.failure(error))
                        } else {
                            completion(.success(udpConnection))
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
}
