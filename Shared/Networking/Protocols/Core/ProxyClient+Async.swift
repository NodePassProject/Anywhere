//
//  ProxyClient+Async.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// MARK: - ProxyClient callback-compat surface

// The `async` dial/handshake/cancel surface (see `ProxyClient.swift`) is now the
// primary, native implementation: `connect`/`connectUDP`/`connectMultiplexer` run the
// async chain builder and dispatch directly, and `cancel()` awaits fd teardown through
// a `TaskGroup`. These thin wrappers bridge *up* to that surface for the callback
// consumers that remain until their own stages land — the MITM `OutboundConnector`,
// `LatencyTester`, the VLESS-Vision UDP multiplexer, the Sudoku chain builder, and the
// protocol E2E harness — plus the pooled-QUIC chain builders (Hysteria/Nowhere) and the
// SOCKS5/XHTTP chain dials that are still callback internally. All are removed in
// later stage.
//
// A dial that lands after the client is torn down is caught by the async surface's own
// `owningDelivered` guard and released, so nothing leaks; task teardown is driven by the
// caller through `cancel(completion:)` / `cancel()`, matching the former callback API.

extension ProxyClient {

    func connect(
        to destinationHost: String,
        port destinationPort: UInt16,
        initialData: Data? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        Task {
            do {
                completion(.success(try await connect(
                    to: destinationHost, port: destinationPort, initialData: initialData
                )))
            } catch {
                completion(.failure(error))
            }
        }
    }

    func connectUDP(
        to destinationHost: String,
        port destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        Task {
            do {
                completion(.success(try await connectUDP(to: destinationHost, port: destinationPort)))
            } catch {
                completion(.failure(error))
            }
        }
    }

    func connectMultiplexer(completion: @escaping (Result<ProxyConnection, Error>) -> Void) {
        Task {
            do {
                completion(.success(try await connectMultiplexer()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Fires `completion` once every underlying socket has fully torn down (fd closed).
    func cancel(completion: @escaping @Sendable () -> Void) {
        Task {
            await cancel()
            completion()
        }
    }

    // MARK: Chain-builder compat

    func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16)? = nil,
        track: ((ProxyClient) -> Void)? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        Task {
            do {
                completion(.success(try await buildChainTunnel(
                    chain: chain, index: index, currentTunnel: currentTunnel,
                    hopCommands: hopCommands, finalDestination: finalDestination, track: track
                )))
            } catch {
                completion(.failure(error))
            }
        }
    }

    static func buildDetachedChainTunnel(
        chain: [ProxyConfiguration],
        hopCommands: [ProxyCommand],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        Task {
            do {
                completion(.success(try await buildDetachedChainTunnel(
                    chain: chain, hopCommands: hopCommands, finalDestination: finalDestination,
                    useResolvedAddressForDirectDial: useResolvedAddressForDirectDial, track: track
                )))
            } catch {
                completion(.failure(error))
            }
        }
    }
}
