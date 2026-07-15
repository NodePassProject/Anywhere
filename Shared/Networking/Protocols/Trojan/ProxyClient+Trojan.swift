//
//  ProxyClient+Trojan.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation

extension ProxyClient {
    /// Trojan requires TLS; on password (SHA224) mismatch the server silently serves its decoy site.
    func connectWithTrojan(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard case .trojan(let password, let securityLayer) = configuration.outbound, !password.isEmpty,
              let tlsConfig = securityLayer.tlsConfiguration else {
            throw ProxyError.protocolError("Trojan password not set")
        }

        let tlsClient = TLSClient(configuration: tlsConfig)
        own(tlsClient)

        let tlsConnection: TLSRecordConnection
        if let tunnel = self.tunnel {
            tlsConnection = try await tlsClient.connect(overTunnel: tunnel)
        } else {
            tlsConnection = try await tlsClient.connect(host: directDialHost, port: configuration.serverPort)
        }
        own(tlsConnection)

        let tlsProxyConnection = TLSProxyConnection(tlsConnection: tlsConnection)
        return try wrapTrojan(
            over: tlsProxyConnection,
            password: password,
            command: command,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: initialData
        )
    }

    /// Wraps a TLS connection with Trojan framing; `initialData` is sent through
    /// the wrapper so the Trojan header and first payload coalesce into one TLS record.
    private func wrapTrojan(
        over tlsConnection: ProxyConnection,
        password: String,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) throws -> ProxyConnection {
        switch command {
        case .tcp:
            let trojan = TrojanConnection(
                inner: tlsConnection,
                password: password,
                destinationHost: destinationHost,
                destinationPort: destinationPort
            )
            if let initialData, !initialData.isEmpty {
                trojan.send(data: initialData)
            }
            return trojan
        case .udp:
            return TrojanUDPConnection(
                inner: tlsConnection,
                password: password,
                destinationHost: destinationHost,
                destinationPort: destinationPort
            )
        case .mux:
            throw ProxyError.protocolError("Mux is not supported with Trojan")
        }
    }
}
