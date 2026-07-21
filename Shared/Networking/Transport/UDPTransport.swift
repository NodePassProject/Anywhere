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

    private struct State {
        var connection: NetworkConnection<UDP>?
        var flowSlot: FlowSlot?
        var ready = false
        var cancelled = false
        var failure: AnywhereError?
    }

    private let state = Mutex(State())

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
        state.withLock { $0.ready && !$0.cancelled && $0.failure == nil }
    }

    // MARK: - Connect
    
    func connect() async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "invalid port \(port)"))
        }
        let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(.udp, context: "[UDP] \(endpointDescription)")

        let connection = NetworkConnection(to: endpoint) { UDP() }
        installStateHandlers(connection)

        let live: Bool = state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.connection = connection
            state.ready = true
            return true
        }
        guard live else {
            slot.release()
            throw AnywhereError.transport(.terminated)
        }
    }

    private func installStateHandlers(_ connection: NetworkConnection<UDP>) {
        connection.onStateUpdate { [weak self] _, update in
            switch update {
            case .failed(let error), .waiting(let error):
                self?.latchFailure(error.anywhereError(op: .connect))
            default:
                break
            }
        }
        .onViabilityUpdate { [weak self] _, viable in
            guard !viable else { return }
            self?.latchFailure(.transport(.terminated))
        }
    }

    private func latchFailure(_ error: AnywhereError) {
        state.withLock { state in
            guard state.failure == nil, !state.cancelled else { return }
            state.failure = error
        }
    }

    // MARK: - DatagramTransport

    func send(_ datagram: Data) async throws {
        let connection = try activeConnection()
        do {
            try await connection.send(datagram)
        } catch {
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
                throw latchedFailure() ?? AnywhereError.networkFailure(error, op: .receive)
            }
            if !message.content.isEmpty { return message.content }
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

    private func activeConnection() throws -> NetworkConnection<UDP> {
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
}
