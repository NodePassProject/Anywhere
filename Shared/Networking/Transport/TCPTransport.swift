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
    private static let maxReceiveLength = 65535

    // MARK: State

    private struct State {
        var connection: NetworkConnection<TCP>?
        var flowSlot: FlowSlot?
        var ready = false
        var cancelled = false
        var failure: AnywhereError?
        var eofLatched = false
    }

    private let state = Mutex(State())

    private let host: String
    private let port: UInt16
    let endpointDescription: String
    
    private let dialAttempt: ConnectionMetrics.Attempt?

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.endpointDescription = "\(host):\(port)"
        self.dialAttempt = ConnectionMetrics.currentAttempt
    }

    deinit {
        cancel()
    }

    var isReady: Bool {
        state.withLock { $0.ready && !$0.cancelled && $0.failure == nil }
    }

    // MARK: - Connect
    
    func connect(initialData: Data? = nil) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "invalid port \(port)"))
        }
        let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(context: "[TCP] \(endpointDescription)")
        
        let connection = NetworkConnection(to: endpoint) { Self.makeProtocolStack() }

        let live: Bool = state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.connection = connection
            return true
        }
        guard live else {
            slot.release()
            throw AnywhereError.transport(.terminated)
        }

        if let initialData, !initialData.isEmpty {
            do {
                try await connection.send(initialData, endOfStream: false)
            } catch {
                cancel()
                throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .connect)
            }
        }
        state.withLock { $0.ready = true }
    }

    // MARK: - ByteTransport

    func send(_ data: Data) async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(data, endOfStream: false)
        } catch {
            throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .send)
        }
    }

    func finishSend() async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(Data(), endOfStream: true)
        } catch {
            throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .send)
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
                throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .receive)
            }

            let endOfStream = message.metadata.endOfStream
            if !message.content.isEmpty {
                dialAttempt?.noteServerResponse()
                if endOfStream { state.withLock { $0.eofLatched = true } }
                return .bytes(message.content)
            }
            if endOfStream {
                state.withLock { $0.eofLatched = true }
                return .end
            }
        }
    }
    
    func cancel() {
        let slot: FlowSlot? = state.withLock { state in
            if state.failure == nil { state.failure = .transport(.terminated) }
            state.cancelled = true
            state.ready = false
            let slot = state.flowSlot
            state.connection = nil
            state.flowSlot = nil
            return slot
        }
        slot?.release()
    }

    // MARK: - Helpers

    private func activeConnection() throws -> NetworkConnection<TCP> {
        try state.withLock { state in
            if let failure = state.failure { throw failure }
            if state.cancelled { throw AnywhereError.transport(.terminated) }
            guard let connection = state.connection else { throw AnywhereError.transport(.notConnected) }
            return connection
        }
    }

    private func latchedFailure() -> AnywhereError? {
        state.withLock { $0.failure }
    }

    private static func makeProtocolStack() -> TCP {
        TCP()
            .noDelay(true)
            .keepalive(idleTimeInSeconds: 30, count: 3, intervalInSeconds: 10)
            .connectionTimeout(connectTimeout)
    }
}
