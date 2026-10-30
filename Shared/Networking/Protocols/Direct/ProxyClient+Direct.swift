//
//  ProxyClient+Direct.swift
//  Anywhere
//
//  Created by NodePassProject on 10/30/26.
//

import Foundation

extension ProxyClient {
    func connectWithDirect(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard tunnel == nil else {
            throw AnywhereError.proxy(
                .direct,
                .protocolViolation(
                    detail: "Direct has no server for the previous chain hop to reach"
                )
            )
        }

        if let chain = configuration.chain, !chain.isEmpty {
            let hopNetworks = try Self.computeChainHopNetworks(chain: chain, lastDeliver: request.network).get()
            return try await buildChainTunnel(
                chain: chain,
                index: 0,
                currentTunnel: nil,
                hopNetworks: hopNetworks,
                finalDestination: (request.host, request.port)
            )
        }

        switch request.network {
        case .tcp:
            let transport = TCPTransport(host: request.host, port: request.port, resolution: .localRequests)
            do {
                try await transport.connect()
                if let initialData = request.initialData, !initialData.isEmpty {
                    try await transport.send(initialData)
                }
            } catch {
                transport.cancel()
                throw error
            }
            return DirectProxyConnection(transport: transport)

        case .udp:
            let transport = UDPTransport(host: request.host, port: request.port, resolution: .localRequests)
            do {
                try await transport.connect()
            } catch {
                transport.cancel()
                throw error
            }
            return DirectUDPProxyConnection(transport: transport)
        }
    }
}
