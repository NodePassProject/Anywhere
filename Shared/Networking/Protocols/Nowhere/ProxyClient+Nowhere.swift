//
//  ProxyClient+Nowhere.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated extension ProxyClient {
    func connectWithNowhere(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard case .nowhere(let configuration) = self.configuration.outbound else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Invalid Nowhere configuration"))
        }
        let runtime = try NowhereRuntimeConfiguration(
            proxyHost: self.configuration.serverAddress,
            proxyPort: self.configuration.serverPort,
            configuration: configuration
        )
        let destination = try NowhereProtocol.Target(host: request.host, port: request.port)
        let attempt = NowhereFlowOpenAttempt()
        do {
            return try await withDialDeadline(
                .seconds(30),
                onExpiry: { attempt.cancel() },
                error: { AnywhereError.proxy(.nowhere, .openTimeout) },
                discardingLateResult: { $0.cancel() }
            ) { [self] in
                try Task.checkCancellation()
                guard !isCancelled else { throw AnywhereError.transport(.terminated) }
                let connection: ProxyConnection
                switch runtime.network {
                case .tcp:
                    let carrier = NowhereTCPConnection(
                        configuration: runtime,
                        connectHost: directDialHost,
                        tunnel: takeChainTunnel()
                    )
                    guard attempt.bind(carrier) else {
                        throw AnywhereError.proxy(.nowhere, .streamClosed)
                    }
                    try await carrier.openFresh(
                        destination: destination,
                        kind: request.network == .tcp ? .tcp : .udp,
                        initialData: request.network == .tcp ? request.initialData : nil
                    )
                    connection = request.network == .tcp ? carrier : NowhereTCPUDPConnection(inner: carrier)
                case .udp:
                    let client = try await acquireNowhereClient(configuration: runtime)
                    if request.network == .tcp {
                        connection = try await client.openTCP(
                            destination: destination,
                            initialData: request.initialData,
                            attempt: attempt
                        )
                    } else {
                        connection = try await client.openUDP(destination: destination, attempt: attempt)
                    }
                }
                guard !isCancelled, !Task.isCancelled else {
                    connection.cancel()
                    throw AnywhereError.transport(.terminated)
                }
                return connection
            }
        } catch {
            attempt.cancel()
            throw error
        }
    }

    private func acquireNowhereClient(configuration runtime: NowhereRuntimeConfiguration) async throws -> NowhereClient {
        if let tunnel = takeChainTunnel() {
            return NowhereClient.chained(
                configuration: runtime,
                transport: ProxyConnectionDatagramTransport(connection: tunnel)
            )
        }
        guard let chain = configuration.chain, !chain.isEmpty else {
            return try NowhereClient.shared(for: runtime)
        }
        let hopNetworks = try Self.computeChainHopNetworks(chain: chain, lastDeliver: .udp).get()
        let useResolvedAddress = useResolvedAddressForDirectDial
        return try await NowhereClient.acquireChained(configuration: runtime, chain: chain) {
            let holders = Mutex<[ProxyClient]>([])
            do {
                let tunnel = try await ProxyClient.buildDetachedChainTunnel(
                    chain: chain,
                    hopNetworks: hopNetworks,
                    finalDestination: (runtime.proxyHost, runtime.proxyPort),
                    useResolvedAddressForDirectDial: useResolvedAddress,
                    track: { client in holders.withLock { $0.append(client) } }
                )
                return (ProxyConnectionDatagramTransport(connection: tunnel), holders.withLock { $0 })
            } catch {
                for client in holders.withLock({ $0 }) { await client.cancel() }
                throw error
            }
        }
    }
}
