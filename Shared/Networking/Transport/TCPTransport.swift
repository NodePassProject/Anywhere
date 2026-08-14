//
//  TCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

nonisolated protocol TCPTransportEngine: AnyObject, Sendable {
    func send(_ data: Data) async throws
    func receive(atMost maxLength: Int) async throws -> (content: Data, endOfStream: Bool)
}

nonisolated final class TCPTransport: ByteTransport, Sendable {

    // MARK: Constants

    private static let connectTimeout: UInt32 = 16
    private static let maxReceiveLength = 65535

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

        var engine: (any TCPTransportEngine)?
        var flowSlot: FlowSlot?
        var failure: AnywhereError?
        var eofLatched = false
    }

    private let state = Mutex(State())

    private let host: String
    private let port: UInt16
    private let resolvesViaProxyDNS: Bool
    let endpointDescription: String

    private let dialAttempt: ConnectionMetrics.Attempt?

    init(host: String, port: UInt16, resolvesViaProxyDNS: Bool = false) {
        self.host = host
        self.port = port
        self.resolvesViaProxyDNS = resolvesViaProxyDNS
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
        let endpointHost = await NWEndpoint.Host.dialHost(for: host, viaProxyDNS: resolvesViaProxyDNS)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(context: "[TCP] \(endpointDescription)")

        let engine: any TCPTransportEngine
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            engine = ModernTCPEngine(endpoint: endpoint, connectTimeout: Self.connectTimeout)
        } else {
            engine = LegacyTCPEngine(endpoint: endpoint, connectTimeout: Self.connectTimeout)
        }

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
        // Engines tear down on release; in-flight operations end via task cancellation.
        let (_, slot): ((any TCPTransportEngine)?, FlowSlot?) = state.withLock { state in
            if state.failure == nil { state.failure = .transport(.terminated) }
            state.transition(to: .cancelled)
            let pair = (state.engine, state.flowSlot)
            state.engine = nil
            state.flowSlot = nil
            return pair
        }
        slot?.release()
    }

    // MARK: - Helpers

    private func activeEngine() throws -> any TCPTransportEngine {
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

// MARK: - Modern engine

@available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
nonisolated final class ModernTCPEngine: TCPTransportEngine, Sendable {

    private let connection: NetworkConnection<TCP>

    init(endpoint: NWEndpoint, connectTimeout: UInt32) {
        connection = NetworkConnection(to: endpoint) {
            TCP()
                .noDelay(true)
                .keepalive(idleTimeInSeconds: 30, count: 3, intervalInSeconds: 10)
                .connectionTimeout(connectTimeout)
        }
    }

    func send(_ data: Data) async throws {
        try await connection.send(data, endOfStream: false)
    }

    func receive(atMost maxLength: Int) async throws -> (content: Data, endOfStream: Bool) {
        let message = try await connection.receive(atLeast: 1, atMost: maxLength)
        return (message.content, message.metadata.endOfStream)
    }
}
