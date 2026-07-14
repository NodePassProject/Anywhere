//
//  AsyncTCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

// MARK: - AsyncTCPTransport

/// A TCP byte-stream transport with an async-native surface, backed by an iOS 26
/// `NetworkConnection`.
///
/// A `OneToOneProtocol` connection has no manual `start()`/`cancel()`: its lifetime
/// is the `withNetworkConnection` scope. A single lightweight driver task holds
/// that scope open and publishes the connection; ``send(_:)``/``receive()`` then
/// await the connection *directly* — the `await` is the ordering and backpressure,
/// so there is no `AsyncStream` send feeder, pending-completion FIFO, or receive
/// token stream. Teardown is ``cancel()`` (or a viability drop); state protection
/// stays with a `Mutex`.
nonisolated final class AsyncTCPTransport: AsyncByteTransport, @unchecked Sendable {

    // MARK: Constants

    /// Per-attempt connect timeout (seconds), handed to the protocol stack.
    private static let connectTimeout: UInt32 = 16
    /// Wall-clock backstop for the whole dial.
    private static let dialDeadline: Duration = .seconds(20)
    private static let maxReceiveLength = 65535

    // MARK: State

    /// All mutable state, `Mutex`-guarded so ``cancel()`` is safe from any thread.
    private struct State {
        var connection: NetworkConnection<TCP>?
        var flowSlot: FlowSlot?
        var driverTask: Task<Void, Never>?
        var ready = false
        var cancelled = false
        /// Latched once a data-bearing final segment is delivered, so the next
        /// `receive()` reports `.end` without another framework read.
        var eofLatched = false
    }

    private let state = Mutex(State())
    /// Resolved when the dial reaches ready (success) or fails/times out.
    private let connectPromise = AsyncPromise<Void>()
    /// Resolved to unwind the driver: `cancel()`, a viability drop, or a fatal
    /// send/receive error.
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

    /// Dials the endpoint, resolving when ready (and any `initialData` is flushed)
    /// or throwing on failure/timeout/cancellation. `NetworkConnection` resolves
    /// `host` (or uses it directly for an IP literal) and races addresses.
    func connect(initialData: Data? = nil) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw TransportError.connectionFailed("Invalid port \(port)")
        }
        let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(.tcp, context: "[AsyncTCP] \(endpointDescription)")

        let started: Bool = state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.driverTask = Task { [self] in
                await runDriver(endpoint: endpoint, initialData: initialData, slot: slot)
            }
            return true
        }
        guard started else {
            slot.release()
            throw TransportError.connectionFailed("Cancelled")
        }

        try await withTaskCancellationHandler {
            try await connectPromise.value()
        } onCancel: {
            cancel()
        }
    }

    /// Owns the connection scope for the whole session. Publishes the connection,
    /// resolves the dial via an establish send, then parks on `teardownPromise`
    /// until cancel / viability loss / a fatal I/O error unwinds it.
    private func runDriver(endpoint: NWEndpoint, initialData: Data?, slot: FlowSlot) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { Self.makeProtocolStack() }) { [self] conn in
                let live = state.withLock { state -> Bool in
                    guard !state.cancelled else { return false }
                    state.connection = conn
                    return true
                }
                guard live else { throw CancellationError() }

                // TCP can't migrate a 4-tuple: a viability drop means the leg is dead.
                conn.onViabilityUpdate { [self] _, viable in
                    if !viable { teardownPromise.resolve(.success(())) }
                }

                do {
                    try await raceDialDeadline(Self.dialDeadline, onExpire: { [self] in
                        teardownPromise.resolve(.success(()))
                    }) {
                        // The establish send returns once the connection is ready
                        // and the initial data is flushed — an authoritative
                        // readiness signal.
                        try await conn.send(initialData ?? Data(), endOfStream: false)
                    }
                } catch {
                    connectPromise.resolve(.failure(TransportError.from(error, op: .connect)))
                    throw error  // exit scope → tear the connection down
                }

                state.withLock { $0.ready = true }
                connectPromise.resolve(.success(()))

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

    // MARK: - AsyncByteTransport

    func send(_ data: Data) async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(data, endOfStream: false)
        } catch {
            teardownPromise.resolve(.success(()))
            throw TransportError.from(error, op: .send)
        }
    }

    func finishSend() async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(Data(), endOfStream: true)
        } catch {
            teardownPromise.resolve(.success(()))
            throw TransportError.from(error, op: .send)
        }
    }

    func receive() async throws -> TransportChunk {
        while true {
            if state.withLock({ $0.eofLatched }) { return .end }
            let connection = try activeConnection()

            let message: (content: Data, metadata: TCP.Metadata)
            do {
                message = try await connection.receive(atLeast: 1, atMost: Self.maxReceiveLength)
            } catch {
                teardownPromise.resolve(.success(()))
                throw TransportError.from(error, op: .receive)
            }

            let endOfStream = message.metadata.endOfStream
            if !message.content.isEmpty {
                // Deliver the data now; if this was the final segment, the next
                // receive() returns .end.
                if endOfStream { state.withLock { $0.eofLatched = true } }
                return .bytes(message.content)
            }
            if endOfStream {
                state.withLock { $0.eofLatched = true }
                return .end
            }
            // Empty, not end-of-stream (shouldn't happen with atLeast: 1): retry.
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
        // Unblock a pending connect() and the driver's hold-open; cancel the driver
        // so an in-flight establish send unwinds.
        connectPromise.resolve(.failure(TransportError.connectionFailed("Cancelled")))
        teardownPromise.resolve(.success(()))
        task?.cancel()
    }

    // MARK: - Helpers

    /// The live connection, or a throw if cancelled / not yet published.
    private func activeConnection() throws -> NetworkConnection<TCP> {
        try state.withLock { state in
            if state.cancelled { throw TransportError.connectionFailed("Cancelled") }
            guard let connection = state.connection else { throw TransportError.notConnected }
            return connection
        }
    }

    /// The TCP protocol stack (`NWParameters`-equivalent tuning).
    private static func makeProtocolStack() -> TCP {
        TCP()
            .noDelay(true)
            .keepalive(idleTimeInSeconds: 30, count: 3, intervalInSeconds: 10)
            .connectionTimeout(connectTimeout)
    }
}
