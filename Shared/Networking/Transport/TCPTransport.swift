//
//  TCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

nonisolated final class TCPTransport: AsyncByteTransport, Sendable {

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

    /// State and promises shared with the driver task.
    private final class Guts: Sendable {
        let state = Mutex(State())
        /// Resolved when the dial reaches ready (success) or fails/times out.
        let connectPromise = AsyncPromise<Void>()
        /// Resolved to unwind the driver: `cancel()`, a viability drop, or a fatal
        /// send/receive error.
        let teardownPromise = AsyncPromise<Void>()
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

    /// Dials the endpoint, resolving when ready (and any `initialData` is flushed)
    /// or throwing on failure/timeout/cancellation. `NetworkConnection` resolves
    /// `host` (or uses it directly for an IP literal) and races addresses.
    func connect(initialData: Data? = nil) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw TransportError.connectionFailed("Invalid port \(port)")
        }
        let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(.tcp, context: "[TCP] \(endpointDescription)")

        let guts = self.guts
        let started: Bool = guts.state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.driverTask = Task {
                await Self.runDriver(guts: guts, endpoint: endpoint, initialData: initialData, slot: slot)
            }
            return true
        }
        guard started else {
            slot.release()
            throw TransportError.connectionFailed("Cancelled")
        }

        try await withTaskCancellationHandler {
            try await guts.connectPromise.value()
        } onCancel: {
            cancel()
        }
    }

    /// Owns the connection scope for the whole session. Publishes the connection,
    /// resolves the dial, then parks on `teardownPromise` until cancel / viability loss /
    /// a fatal I/O error unwinds it.
    private static func runDriver(guts: Guts, endpoint: NWEndpoint, initialData: Data?, slot: FlowSlot) async {
        let hasInitialData = initialData?.isEmpty == false
        do {
            try await withNetworkConnection(to: endpoint, using: { Self.makeProtocolStack() }) { connection in
                let live = guts.state.withLock { state -> Bool in
                    guard !state.cancelled else { return false }
                    state.connection = connection
                    return true
                }
                guard live else { throw CancellationError() }

                connection.onStateUpdate { _, update in
                    switch update {
                    case .ready:
                        guts.state.withLock { $0.ready = true }
                    case .failed(let error), .waiting(let error):
                        guts.connectPromise.resolve(.failure(error.transportError(op: .connect)))
                        guts.teardownPromise.resolve(.success(()))
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                .onViabilityUpdate { _, viable in
                    if !viable { guts.teardownPromise.resolve(.success(())) }
                }

                if let initialData, hasInitialData {
                    do {
                        try await raceDialDeadline(Self.dialDeadline, onExpire: {
                            guts.teardownPromise.resolve(.success(()))
                        }) {
                            try await connection.send(initialData, endOfStream: false)
                        }
                    } catch {
                        guts.connectPromise.resolve(.failure(TransportError.from(error, op: .connect)))
                        throw error  // exit scope → tear the connection down
                    }
                }

                guts.state.withLock { $0.ready = true }
                guts.connectPromise.resolve(.success(()))

                // Hold the connection open until something asks for teardown.
                _ = try? await guts.teardownPromise.value()
            }
        } catch {
            // No-op if the dial already resolved; covers a pre-ready scope failure.
            guts.connectPromise.resolve(.failure(TransportError.from(error, op: .connect)))
        }
        slot.release()
        guts.state.withLock { $0.connection = nil }
    }

    // MARK: - AsyncByteTransport

    func send(_ data: Data) async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(data, endOfStream: false)
        } catch {
            guts.teardownPromise.resolve(.success(()))
            throw TransportError.from(error, op: .send)
        }
    }

    func finishSend() async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(Data(), endOfStream: true)
        } catch {
            guts.teardownPromise.resolve(.success(()))
            throw TransportError.from(error, op: .send)
        }
    }

    func receive() async throws -> TransportChunk {
        while true {
            if guts.state.withLock({ $0.eofLatched }) { return .end }
            let connection = try activeConnection()

            let message: (content: Data, metadata: TCP.Metadata)
            do {
                message = try await connection.receive(atLeast: 1, atMost: Self.maxReceiveLength)
            } catch {
                guts.teardownPromise.resolve(.success(()))
                throw TransportError.from(error, op: .receive)
            }

            let endOfStream = message.metadata.endOfStream
            if !message.content.isEmpty {
                // Deliver the data now; if this was the final segment, the next
                // receive() returns .end.
                if endOfStream { guts.state.withLock { $0.eofLatched = true } }
                return .bytes(message.content)
            }
            if endOfStream {
                guts.state.withLock { $0.eofLatched = true }
                return .end
            }
            // Empty, not end-of-stream (shouldn't happen with atLeast: 1): retry.
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
        // Unblock a pending connect() and the driver's hold-open; cancel the driver
        // so an in-flight establish send unwinds.
        guts.connectPromise.resolve(.failure(TransportError.connectionFailed("Cancelled")))
        guts.teardownPromise.resolve(.success(()))
        task?.cancel()
    }

    // MARK: - Helpers

    /// The live connection, or a throw if cancelled / not yet published.
    private func activeConnection() throws -> NetworkConnection<TCP> {
        try guts.state.withLock { state in
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
