//
//  AsyncUDPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

// MARK: - AsyncUDPTransport

/// A connected-UDP transport with an async-native surface, backed by an iOS 26
/// `NetworkConnection`.
///
/// The datagram sibling of ``AsyncTCPTransport``: a lightweight driver task holds
/// the `withNetworkConnection` scope open and publishes the connection, and
/// ``send(_:)``/``receive()`` await it directly — one `send`/`receive` per
/// datagram, boundaries preserved. Unlike TCP there is no handshake, so readiness
/// is the connection reaching `.ready` (an establish send would put a spurious
/// empty datagram on the wire). Teardown is ``cancel()`` or a viability drop.
nonisolated final class AsyncUDPTransport: AsyncDatagramTransport, @unchecked Sendable {

    // MARK: Constants

    /// Wall-clock backstop for the whole dial.
    private static let dialDeadline: Duration = .seconds(20)

    // MARK: State

    /// All mutable state, `Mutex`-guarded so ``cancel()`` is safe from any thread.
    private struct State {
        var connection: NetworkConnection<UDP>?
        var flowSlot: FlowSlot?
        var driverTask: Task<Void, Never>?
        var ready = false
        var cancelled = false
    }

    private let state = Mutex(State())
    /// Resolved when the connection reaches ready (success) or fails/times out.
    private let connectPromise = AsyncPromise<Void>()
    /// Resolved to unwind the driver: `cancel()`, a viability drop, or a failure.
    private let teardownPromise = AsyncPromise<Void>()

    private let host: String
    private let port: UInt16
    /// "host:port" for diagnostics.
    let endpointDescription: String

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.endpointDescription = "\(host):\(port)"
    }

    deinit {
        // Backstop for a transport dropped without an explicit cancel.
        cancel()
    }

    var isReady: Bool {
        state.withLock { $0.ready && !$0.cancelled }
    }

    // MARK: - Connect

    /// Dials the endpoint, resolving when the connection is ready or throwing on
    /// failure/timeout/cancellation.
    func connect() async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw TransportError.connectionFailed("Invalid port \(port)")
        }
        let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(.udp, context: "[AsyncUDP] \(endpointDescription)")

        let started: Bool = state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.driverTask = Task { [self] in
                await runDriver(endpoint: endpoint, slot: slot)
            }
            return true
        }
        guard started else {
            slot.release()
            throw TransportError.connectionFailed("Cancelled")
        }

        try await withTaskCancellationHandler {
            try await raceDialDeadline(Self.dialDeadline, onExpire: { [self] in cancel() }) { [self] in
                try await connectPromise.value()
            }
        } onCancel: {
            cancel()
        }
    }

    /// Owns the connection scope for the whole session. Publishes the connection,
    /// resolves the dial on `.ready`, then parks on `teardownPromise` until
    /// cancel / viability loss / failure unwinds it.
    private func runDriver(endpoint: NWEndpoint, slot: FlowSlot) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { UDP() }) { [self] conn in
                let live = state.withLock { state -> Bool in
                    guard !state.cancelled else { return false }
                    state.connection = conn
                    return true
                }
                guard live else { throw CancellationError() }

                conn.onStateUpdate { [self] _, update in
                    switch update {
                    case .ready:
                        state.withLock { $0.ready = true }
                        connectPromise.resolve(.success(()))
                    case .failed(let error), .waiting(let error):
                        // UDP drops viability before a receive would error; any
                        // failure/waiting fails the transport.
                        connectPromise.resolve(.failure(error.transportError(op: .connect)))
                        teardownPromise.resolve(.success(()))
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                .onViabilityUpdate { [self] _, viable in
                    if !viable { teardownPromise.resolve(.success(())) }
                }

                // Covers the connection already being ready before the handler ran.
                if case .ready = conn.state {
                    state.withLock { $0.ready = true }
                    connectPromise.resolve(.success(()))
                }

                // Hold the connection open until something asks for teardown.
                _ = try? await teardownPromise.value()
            }
        } catch {
            // No-op if the dial already resolved; covers a pre-ready scope failure.
            connectPromise.resolve(.failure(TransportError.from(error, op: .connect)))
        }
        slot.release()
        state.withLock { $0.connection = nil }
    }

    // MARK: - AsyncDatagramTransport

    func send(_ datagram: Data) async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(datagram)
        } catch {
            teardownPromise.resolve(.success(()))
            throw TransportError.from(error, op: .send)
        }
    }

    func receive() async throws -> Data {
        while true {
            let connection = try activeConnection()
            let message: (content: Data, metadata: UDP.Metadata)
            do {
                message = try await connection.receive()
            } catch {
                teardownPromise.resolve(.success(()))
                throw TransportError.from(error, op: .receive)
            }
            // Skip empty datagrams (keepalive artifacts).
            if !message.content.isEmpty { return message.content }
        }
    }

    func cancel() {
        let task: Task<Void, Never>? = state.withLock { state in
            guard !state.cancelled else { return nil }
            state.cancelled = true
            let task = state.driverTask
            state.driverTask = nil
            return task
        }
        connectPromise.resolve(.failure(TransportError.connectionFailed("Cancelled")))
        teardownPromise.resolve(.success(()))
        task?.cancel()
    }

    // MARK: - Helpers

    /// The live connection, or a throw if cancelled / not yet published.
    private func activeConnection() throws -> NetworkConnection<UDP> {
        try state.withLock { state in
            if state.cancelled { throw TransportError.connectionFailed("Cancelled") }
            guard let connection = state.connection else { throw TransportError.notConnected }
            return connection
        }
    }
}
