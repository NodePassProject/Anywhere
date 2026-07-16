//
//  UDPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

nonisolated final class UDPTransport: DatagramTransport, Sendable {

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

    /// State and one-shot signals shared with the driver task. Both signals are
    /// element-less streams used as latches: the first `finish` wins, later finishes
    /// are no-ops, and each has exactly one consumer.
    private final class Guts: Sendable {
        let state = Mutex(State())
        /// Consumed once by `connect()`: finished on ready, finished throwing on
        /// failure/timeout/cancel.
        let dialOutcome: AsyncThrowingStream<Never, Error>
        let dialSignal: AsyncThrowingStream<Never, Error>.Continuation
        /// Consumed once by the driver's hold-open: finished by `cancel()`, a
        /// viability drop, or a failure.
        let teardown: AsyncStream<Never>
        let teardownSignal: AsyncStream<Never>.Continuation

        init() {
            (dialOutcome, dialSignal) = AsyncThrowingStream.makeStream(of: Never.self)
            (teardown, teardownSignal) = AsyncStream.makeStream(of: Never.self)
        }
    }

    private let guts = Guts()

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
        guts.state.withLock { $0.ready && !$0.cancelled }
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
        let slot = FlowSlot(.udp, context: "[UDP] \(endpointDescription)")

        let guts = self.guts
        let started: Bool = guts.state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.driverTask = Task {
                await Self.runDriver(guts: guts, endpoint: endpoint, slot: slot)
            }
            return true
        }
        guard started else {
            slot.release()
            throw TransportError.connectionFailed("Cancelled")
        }

        try await withTaskCancellationHandler {
            try await raceDialDeadline(Self.dialDeadline, onExpire: { [self] in cancel() }) {
                for try await _ in guts.dialOutcome {}
            }
        } onCancel: {
            cancel()
        }
        // A cancelled iteration ends without throwing; only a live, ready
        // transport may report a successful dial.
        guard isReady else { throw TransportError.connectionFailed("Cancelled") }
    }

    /// Owns the connection scope for the whole session. Publishes the connection,
    /// resolves the dial on `.ready`, then parks on `teardownPromise` until
    /// cancel / viability loss / failure unwinds it.
    private static func runDriver(guts: Guts, endpoint: NWEndpoint, slot: FlowSlot) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { UDP() }) { conn in
                let live = guts.state.withLock { state -> Bool in
                    guard !state.cancelled else { return false }
                    state.connection = conn
                    return true
                }
                guard live else { throw CancellationError() }

                conn.onStateUpdate { _, update in
                    switch update {
                    case .ready:
                        guts.state.withLock { $0.ready = true }
                        guts.dialSignal.finish()
                    case .failed(let error), .waiting(let error):
                        // UDP drops viability before a receive would error; any
                        // failure/waiting fails the transport.
                        guts.dialSignal.finish(throwing: error.transportError(op: .connect))
                        guts.teardownSignal.finish()
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                .onViabilityUpdate { _, viable in
                    if !viable { guts.teardownSignal.finish() }
                }

                // Covers the connection already being ready before the handler ran.
                if case .ready = conn.state {
                    guts.state.withLock { $0.ready = true }
                    guts.dialSignal.finish()
                }

                // Hold the connection open until something asks for teardown; ends
                // early if the driver task itself is cancelled.
                for await _ in guts.teardown {}
            }
        } catch {
            // No-op if the dial already resolved; covers a pre-ready scope failure.
            guts.dialSignal.finish(throwing: TransportError.from(error, op: .connect))
        }
        slot.release()
        guts.state.withLock { $0.connection = nil }
    }

    // MARK: - DatagramTransport

    func send(_ datagram: Data) async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(datagram)
        } catch {
            guts.teardownSignal.finish()
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
                guts.teardownSignal.finish()
                throw TransportError.from(error, op: .receive)
            }
            // Skip empty datagrams (keepalive artifacts).
            if !message.content.isEmpty { return message.content }
        }
    }

    func cancel() {
        let task: Task<Void, Never>? = guts.state.withLock { state in
            guard !state.cancelled else { return nil }
            state.cancelled = true
            let task = state.driverTask
            state.driverTask = nil
            return task
        }
        guts.dialSignal.finish(throwing: TransportError.connectionFailed("Cancelled"))
        guts.teardownSignal.finish()
        task?.cancel()
    }

    // MARK: - Helpers

    /// The live connection, or a throw if cancelled / not yet published.
    private func activeConnection() throws -> NetworkConnection<UDP> {
        try guts.state.withLock { state in
            if state.cancelled { throw TransportError.connectionFailed("Cancelled") }
            guard let connection = state.connection else { throw TransportError.notConnected }
            return connection
        }
    }
}
