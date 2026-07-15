//
//  ProxyClient+Async.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// MARK: - ProxyClient async surface

// Async-native entry points over the completion-handler dial/handshake API. These
// bridge through `awaitCallback` so consumers (the NE flows, latency probes, chain
// builders) can `await` a hop instead of nesting callbacks. Task cancellation unblocks
// the in-flight await via the `PendingResumer`; the underlying client is torn down
// separately by the caller through `cancelAndWait()` (matching the callback API, where
// the connect and the fd-close teardown are distinct — see `LatencyTester`). A
// connection that lands after cancellation is caught by the client's own
// `owningDelivered` guard and released, so nothing leaks.

extension ProxyClient {

    /// Dials `destinationHost:destinationPort` for a TCP stream, resolving the proxied
    /// ``ProxyConnection`` or throwing on failure/cancellation.
    func connect(
        to destinationHost: String,
        port destinationPort: UInt16,
        initialData: Data? = nil
    ) async throws -> ProxyConnection {
        let resumer = PendingResumer()
        return try await withTaskCancellationHandler {
            try await awaitCallback(resumer: resumer) { completion in
                self.connect(
                    to: destinationHost,
                    port: destinationPort,
                    initialData: initialData,
                    completion: completion
                )
            }
        } onCancel: {
            resumer.cancel()
        }
    }

    /// Opens a UDP association to `destinationHost:destinationPort`.
    func connectUDP(
        to destinationHost: String,
        port destinationPort: UInt16
    ) async throws -> ProxyConnection {
        let resumer = PendingResumer()
        return try await withTaskCancellationHandler {
            try await awaitCallback(resumer: resumer) { completion in
                self.connectUDP(to: destinationHost, port: destinationPort, completion: completion)
            }
        } onCancel: {
            resumer.cancel()
        }
    }

    /// Opens the protocol's stream multiplexer (VLESS Vision UDP-over-mux, etc.).
    func connectMultiplexer() async throws -> ProxyConnection {
        let resumer = PendingResumer()
        return try await withTaskCancellationHandler {
            try await awaitCallback(resumer: resumer) { completion in
                self.connectMultiplexer(completion: completion)
            }
        } onCancel: {
            resumer.cancel()
        }
    }

    /// Cancels the client and suspends until every underlying socket is fully torn down
    /// (fd closed). The async analogue of `cancel(completion:)`.
    func cancelAndWait() async {
        await withCheckedContinuation { continuation in
            self.cancel { continuation.resume() }
        }
    }
}
