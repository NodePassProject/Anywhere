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
        var lastDialState: String?
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
    
    func connect() async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "invalid port \(port)"))
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
            throw AnywhereError.transport(.terminated)
        }
        
        try await withDialDeadline(Self.dialDeadline, onExpiry: {
            self.cancel()
        }, error: {
            self.dialTimeoutError()
        }) {
            try await withTaskCancellationHandler {
                for try await _ in guts.dialOutcome {}
            } onCancel: {
                self.cancel()
            }
        }
        guard isReady else { throw AnywhereError.transport(.terminated) }
    }
    
    private func dialTimeoutError() -> AnywhereError {
        let lastState = guts.state.withLock { $0.lastDialState }
        return .transport(.timedOut(.connect, endpoint: endpointDescription,
                                    detail: lastState ?? "no state updates"))
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
                    guts.state.withLock { $0.lastDialState = String(describing: update) }
                    switch update {
                    case .ready:
                        guts.state.withLock { $0.ready = true }
                        guts.dialSignal.finish()
                    case .failed(let error), .waiting(let error):
                        // UDP drops viability before a receive would error; any
                        // failure/waiting fails the transport.
                        guts.dialSignal.finish(throwing: error.anywhereError(op: .connect))
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
            guts.dialSignal.finish(throwing: AnywhereError.networkFailure(error, op: .connect))
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
            throw AnywhereError.networkFailure(error, op: .send)
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
                throw AnywhereError.networkFailure(error, op: .receive)
            }
            // Skip empty datagrams (keepalive artifacts).
            if !message.content.isEmpty { return message.content }
        }
    }

    func cancel() {
        tearDown(dialError: AnywhereError.transport(.terminated))
    }

    private func tearDown(dialError: Error) {
        let task: Task<Void, Never>? = guts.state.withLock { state in
            guard !state.cancelled else { return nil }
            state.cancelled = true
            let task = state.driverTask
            state.driverTask = nil
            return task
        }
        guts.dialSignal.finish(throwing: dialError)
        guts.teardownSignal.finish()
        task?.cancel()
    }

    // MARK: - Helpers

    /// The live connection, or a throw if cancelled / not yet published.
    private func activeConnection() throws -> NetworkConnection<UDP> {
        try guts.state.withLock { state in
            if state.cancelled { throw AnywhereError.transport(.terminated) }
            guard let connection = state.connection else { throw AnywhereError.transport(.notConnected) }
            return connection
        }
    }
}
