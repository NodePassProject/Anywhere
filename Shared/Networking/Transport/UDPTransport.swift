//
//  UDPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Network
import Synchronization

nonisolated protocol UDPTransportEngine: AnyObject, Sendable {
    func send(_ datagram: Data) async throws
    func receive() async throws -> Data
}

nonisolated final class UDPTransport: DatagramTransport, Sendable {

    // MARK: State

    private struct State {
        var engine: (any UDPTransportEngine)?
        var flowSlot: FlowSlot?
        var ready = false
        var cancelled = false
        var failure: AnywhereError?
    }

    private let state = Mutex(State())

    private let host: String
    private let port: UInt16
    private let resolvesViaProxyDNS: Bool
    let endpointDescription: String
    
    init(host: String, port: UInt16, resolvesViaProxyDNS: Bool = false) {
        self.host = host
        self.port = port
        self.resolvesViaProxyDNS = resolvesViaProxyDNS
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
        let endpointHost = await NWEndpoint.Host.dialHost(for: host, viaProxyDNS: resolvesViaProxyDNS)
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
        let slot = FlowSlot(context: "[UDP] \(endpointDescription)")
        
        let engine: any UDPTransportEngine
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            engine = ModernUDPEngine(endpoint: endpoint)
        } else {
            engine = LegacyUDPEngine(endpoint: endpoint)
        }

        let live: Bool = state.withLock { state in
            guard !state.cancelled else { return false }
            state.flowSlot = slot
            state.engine = engine
            state.ready = true
            return true
        }
        guard live else {
            slot.release()
            throw AnywhereError.transport(.terminated)
        }
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
        // Engines tear down on release; in-flight operations end via task cancellation.
        let (_, slot): ((any UDPTransportEngine)?, FlowSlot?) = state.withLock { state in
            if state.failure == nil { state.failure = .transport(.terminated) }
            state.cancelled = true
            state.ready = false
            let pair = (state.engine, state.flowSlot)
            state.engine = nil
            state.flowSlot = nil
            return pair
        }
        slot?.release()
    }

    // MARK: - Helpers

    private func activeEngine() throws -> any UDPTransportEngine {
        try state.withLock { state in
            if let failure = state.failure { throw failure }
            if state.cancelled { throw AnywhereError.transport(.terminated) }
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
nonisolated final class ModernUDPEngine: UDPTransportEngine, Sendable {

    private let connection: NetworkConnection<UDP>

    init(endpoint: NWEndpoint) {
        connection = NetworkConnection(to: endpoint) { UDP() }
    }

    func send(_ datagram: Data) async throws {
        try await connection.send(datagram)
    }

    func receive() async throws -> Data {
        let message = try await connection.receive()
        return message.content
    }
}
