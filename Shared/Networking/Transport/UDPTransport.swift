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
    
    private static let dialDeadline: Duration = .seconds(20)

    // MARK: State
    
    private struct State {
        var connection: NetworkConnection<UDP>?
        var flowSlot: FlowSlot?
        var driverTask: Task<Void, Never>?
        var ready = false
        var cancelled = false
        var established = false
        var failure: AnywhereError?
        var lastDialState: String?
    }
    
    private final class Guts: Sendable {
        let state = Mutex(State())
        let dialOutcome: AsyncThrowingStream<Never, Error>
        let dialSignal: AsyncThrowingStream<Never, Error>.Continuation
        let dialArmed: AsyncStream<Never>
        let dialArmedSignal: AsyncStream<Never>.Continuation
        let teardown: AsyncStream<Never>
        let teardownSignal: AsyncStream<Never>.Continuation

        init() {
            (dialOutcome, dialSignal) = AsyncThrowingStream.makeStream(of: Never.self)
            (dialArmed, dialArmedSignal) = AsyncStream.makeStream(of: Never.self)
            (teardown, teardownSignal) = AsyncStream.makeStream(of: Never.self)
        }
    }

    private let guts = Guts()

    private let host: String
    private let port: UInt16
    let endpointDescription: String

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.endpointDescription = "\(host):\(port)"
    }

    deinit {
        cancel()
    }

    var isReady: Bool {
        guts.state.withLock { $0.ready && !$0.cancelled && $0.failure == nil }
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
        let endpointDescription = self.endpointDescription
        let started: Bool = guts.state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.driverTask = Task {
                await Self.runDriver(guts: guts, endpoint: endpoint,
                                     endpointDescription: endpointDescription, slot: slot)
            }
            return true
        }
        guard started else {
            slot.release()
            throw AnywhereError.transport(.terminated)
        }

        try await withTaskCancellationHandler {
            for try await _ in guts.dialOutcome {}
        } onCancel: {
            self.cancel()
        }
        guard isReady else { throw AnywhereError.transport(.terminated) }
    }
    
    private static func runDriver(
        guts: Guts,
        endpoint: NWEndpoint,
        endpointDescription: String,
        slot: FlowSlot
    ) async {
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
                        guts.state.withLock { $0.established = true }
                    case .failed(let error), .waiting(let error):
                        guts.state.withLock { state in
                            if !state.established, state.failure == nil {
                                state.failure = error.anywhereError(op: .connect)
                            }
                        }
                        guts.teardownSignal.finish()
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                .onViabilityUpdate { _, viable in
                    if !viable { guts.teardownSignal.finish() }
                }

                guts.state.withLock { $0.ready = true }
                guts.dialSignal.finish()
                
                await withTaskGroup(of: Void.self) { group in
                    group.addTask {
                        await Self.runDialWatchdog(guts: guts, endpointDescription: endpointDescription)
                    }
                    for await _ in guts.teardown {}
                    group.cancelAll()
                }
            }
        } catch {
            guts.dialSignal.finish(throwing: AnywhereError.networkFailure(error, op: .connect))
        }
        slot.release()
        guts.state.withLock { $0.connection = nil }
    }
    
    private static func runDialWatchdog(guts: Guts, endpointDescription: String) async {
        for await _ in guts.dialArmed {}
        do { try await Task.sleep(for: dialDeadline) } catch { return }
        let expired: Bool = guts.state.withLock { state in
            guard !state.established, !state.cancelled, state.failure == nil else { return false }
            state.failure = .transport(.timedOut(.connect, endpoint: endpointDescription,
                                                 detail: state.lastDialState ?? "no state updates"))
            return true
        }
        if expired { guts.teardownSignal.finish() }
    }

    // MARK: - DatagramTransport

    func send(_ datagram: Data) async throws {
        let connection = try activeConnection()
        guts.dialArmedSignal.finish()
        do {
            try await connection.send(datagram)
        } catch {
            guts.teardownSignal.finish()
            throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .send)
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
                throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .receive)
            }
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
    
    private func activeConnection() throws -> NetworkConnection<UDP> {
        try guts.state.withLock { state in
            if let failure = state.failure { throw failure }
            if state.cancelled { throw AnywhereError.transport(.terminated) }
            guard let connection = state.connection else { throw AnywhereError.transport(.notConnected) }
            return connection
        }
    }
    
    private func latchedFailure() -> AnywhereError? {
        guts.state.withLock { $0.failure }
    }
}
