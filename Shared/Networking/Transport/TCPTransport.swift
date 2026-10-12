//
//  TCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

nonisolated final class TCPTransport: ByteTransport, Sendable {

    // MARK: Constants

    private static let connectTimeout: UInt32 = 16
    private static let maxReceiveLength = 128 * 1024

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

        var engine: TCPTransportEngine?
        var flowSlot: FlowSlot?
        var failure: AnywhereError?
        var eofLatched = false
    }

    private let state = Mutex(State())

    private let host: String
    private let port: UInt16
    private let resolution: DialResolution
    let endpointDescription: String

    private let dialAttempt: ConnectionMetrics.Attempt?

    init(host: String, port: UInt16, resolution: DialResolution = .system) {
        self.host = host
        self.port = port
        self.resolution = resolution
        self.endpointDescription = "\(host):\(port)"
        self.dialAttempt = ConnectionMetrics.currentAttempt
    }

    deinit {
        cancel()
    }

    var isReady: Bool {
        state.withLock { $0.phase == .ready }
    }

    // MARK: - Connect

    func connect(initialData: Data? = nil) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "invalid port \(port)"))
        }
        let endpointHost = try await NWEndpoint.Host.dialHost(for: host, resolution: resolution)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(context: "[TCP] \(endpointDescription)")

        let engine = TCPTransportEngine(endpoint: endpoint, connectTimeout: Self.connectTimeout)

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

        if let initialData, !initialData.isEmpty {
            do {
                try await engine.send(initialData)
            } catch {
                let cause = latchedFailure() ?? AnywhereError.networkFailure(error, operation: .connect)
                cancel()
                throw cause
            }
        }
        let published: Bool = state.withLock { $0.transition(to: .ready) }
        guard published else { throw AnywhereError.transport(.terminated) }
    }

    // MARK: - ByteTransport

    func send(_ data: Data) async throws {
        let engine = try activeEngine()
        do {
            try await engine.send(data)
        } catch {
            throw latchedFailure() ?? AnywhereError.networkFailure(error, operation: .send)
        }
    }

    func receive() async throws -> TransportChunk {
        while true {
            if state.withLock({ $0.eofLatched }) { return .end }
            let engine = try activeEngine()

            let message: (content: Data, endOfStream: Bool)
            do {
                message = try await engine.receive(atMost: Self.maxReceiveLength)
            } catch {
                throw latchedFailure() ?? AnywhereError.networkFailure(error, operation: .receive)
            }

            if !message.content.isEmpty {
                dialAttempt?.noteServerResponse()
                if message.endOfStream { state.withLock { $0.eofLatched = true } }
                return .bytes(message.content)
            }
            if message.endOfStream {
                state.withLock { $0.eofLatched = true }
                return .end
            }
        }
    }

    func cancel() {
        let (engine, slot): (TCPTransportEngine?, FlowSlot?) = state.withLock { state in
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

    private func activeEngine() throws -> TCPTransportEngine {
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

nonisolated final class TCPTransportEngine: Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.TCPTransport", qos: .userInitiated)
    private let stall = NWStallLatch()

    init(endpoint: NWEndpoint, connectTimeout: UInt32) {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        tcpOptions.keepaliveCount = 3
        tcpOptions.keepaliveInterval = 10
        tcpOptions.connectionTimeout = Int(connectTimeout)
        connection = NWConnection(to: endpoint, using: NWParameters(tls: nil, tcp: tcpOptions))
        stall.watch(connection)
        connection.start(queue: queue)
    }

    deinit {
        connection.cancel()
    }

    func cancel() {
        connection.cancel()
    }

    func send(_ data: Data) async throws {
        let connection = connection
        let stall = stall
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                connection.send(content: data, completion: .contentProcessed { error in
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

    func receive(atMost maxLength: Int) async throws -> (content: Data, endOfStream: Bool) {
        let connection = connection
        let stall = stall
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(content: Data, endOfStream: Bool), any Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { content, context, isComplete, error in
                    if let error {
                        continuation.resume(throwing: stall.failure(for: error, operation: .receive))
                        return
                    }
                    let endOfStream = isComplete && (context == nil || context?.isFinal == true)
                    continuation.resume(returning: (content ?? Data(), endOfStream))
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }
}
