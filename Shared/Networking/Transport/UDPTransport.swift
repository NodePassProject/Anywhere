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

    // MARK: State

    enum Phase: PhaseTransitionable {
        case idle
        case connecting
        case ready
        case cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .ready):
                return true
            case (_, .cancelled):
                return old != .cancelled
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var engine: UDPTransportEngine?
        var flowSlot: FlowSlot?
        var failure: AnywhereError?
    }

    private let state = Mutex(State())

    private let host: String
    private let port: UInt16
    private let resolution: DialResolution
    let endpointDescription: String

    init(host: String, port: UInt16, resolution: DialResolution = .system) {
        self.host = host
        self.port = port
        self.resolution = resolution
        self.endpointDescription = "\(host):\(port)"
    }

    deinit {
        cancel()
    }

    var isReady: Bool {
        state.withLock { $0.phase == .ready }
    }

    // MARK: - Connect

    func connect() async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "invalid port \(port)"))
        }
        let endpointHost = try await NWEndpoint.Host.dialHost(for: host, resolution: resolution)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(context: "[UDP] \(endpointDescription)")

        let engine = UDPTransportEngine(endpoint: endpoint)

        let live: Bool = state.withLock { state in
            guard state.transition(to: .connecting) else { return false }
            state.flowSlot = slot
            state.engine = engine
            return true
        }
        guard live else {
            slot.release()
            throw AnywhereError.transport(.terminated)
        }
        let published: Bool = state.withLock { $0.transition(to: .ready) }
        guard published else { throw AnywhereError.transport(.terminated) }
    }

    // MARK: - DatagramTransport

    func send(_ datagram: Data) async throws {
        let engine = try activeEngine()
        do {
            try await engine.send(datagram)
        } catch {
            throw latchedFailure() ?? AnywhereError.networkFailure(error, operation: .send)
        }
    }

    func receive() async throws -> Data {
        while true {
            let engine = try activeEngine()
            let content: Data
            do {
                content = try await engine.receive()
            } catch {
                throw latchedFailure() ?? AnywhereError.networkFailure(error, operation: .receive)
            }
            if !content.isEmpty { return content }
        }
    }

    func cancel() {
        let (engine, slot): (UDPTransportEngine?, FlowSlot?) = state.withLock { state in
            if state.failure == nil { state.failure = .transport(.terminated) }
            state.transition(to: .cancelled)
            let pair = (state.engine, state.flowSlot)
            state.engine = nil
            state.flowSlot = nil
            return pair
        }
        engine?.cancel()
        slot?.release()
    }

    // MARK: - Helpers

    private func activeEngine() throws -> UDPTransportEngine {
        try state.withLock { state in
            if let failure = state.failure { throw failure }
            if state.phase == .cancelled { throw AnywhereError.transport(.terminated) }
            guard let engine = state.engine else { throw AnywhereError.transport(.notConnected) }
            return engine
        }
    }

    private func latchedFailure() -> AnywhereError? {
        state.withLock { $0.failure }
    }
}

// MARK: - Engine

nonisolated final class UDPTransportEngine: Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.UDPTransport", qos: .userInitiated)
    private let stall = NWStallLatch()

    init(endpoint: NWEndpoint) {
        connection = NWConnection(to: endpoint, using: .udp)
        stall.watch(connection)
        connection.start(queue: queue)
    }

    deinit {
        connection.cancel()
    }

    func cancel() {
        connection.cancel()
    }

    func send(_ datagram: Data) async throws {
        let connection = connection
        let stall = stall
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                connection.send(content: datagram, completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: stall.failure(for: error, operation: .send))
                    } else {
                        continuation.resume()
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func receive() async throws -> Data {
        let connection = connection
        let stall = stall
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                connection.receiveMessage { content, _, _, error in
                    if let error {
                        continuation.resume(throwing: stall.failure(for: error, operation: .receive))
                    } else {
                        continuation.resume(returning: content ?? Data())
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }
}
