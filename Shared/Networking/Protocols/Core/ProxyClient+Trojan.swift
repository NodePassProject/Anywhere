//
//  ProxyClient+Trojan.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation

extension ProxyClient {
    /// Connects through a Trojan server: TCP → TLS → Trojan header → payload.
    /// Trojan requires TLS; on password (SHA224) mismatch the server silently serves its decoy site.
    func connectWithTrojan(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard case .trojan(let password, let tlsConfig) = configuration.outbound, !password.isEmpty else {
            completion(.failure(ProxyError.protocolError("Trojan password not set")))
            return
        }

        let tlsClient = TLSClient(configuration: tlsConfig)

        let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            switch result {
            case .success(let tlsConnection):
                self.tlsClient = tlsClient
                self.tlsConnection = tlsConnection
                let tlsProxyConnection = TLSProxyConnection(tlsConnection: tlsConnection)
                self.wrapTrojan(
                    over: tlsProxyConnection,
                    password: password,
                    command: command,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort,
                    initialData: initialData,
                    completion: completion
                )
            case .failure(let error):
                completion(.failure(error))
            }
        }

        if let tunnel = self.tunnel {
            tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
        } else {
            tlsClient.connect(host: directDialHost, port: configuration.serverPort, completion: handleTLSResult)
        }
    }

    /// Wraps a TLS connection with Trojan framing; `initialData` is sent through
    /// the wrapper so the Trojan header and first payload coalesce into one TLS record.
    private func wrapTrojan(
        over tlsConnection: ProxyConnection,
        password: String,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
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
            completion(.success(trojan))
        case .udp:
            let trojan = TrojanUDPConnection(
                inner: tlsConnection,
                password: password,
                destinationHost: destinationHost,
                destinationPort: destinationPort
            )
            completion(.success(trojan))
        case .mux:
            completion(.failure(ProxyError.protocolError("Mux is not supported with Trojan")))
        }
    }
}
