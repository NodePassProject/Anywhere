//
//  TLSStreamTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TLSStreamTransport")

// MARK: - TLSStreamTransport

nonisolated final class TLSStreamTransport: Sendable {

    private let host: String
    private let port: UInt16
    private let sni: String
    private let alpn: [String]
    private let tunnel: ProxyConnection?

    private enum Phase: PhaseTransitionable {
        case idle
        case connecting(TLSClient)
        case ready(TLSRecordConnection)
        case cancelled

        var isCancelled: Bool {
            if case .cancelled = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .ready):
                return true
            case (_, .cancelled):
                return !old.isCancelled
            default:
                return false
            }
        }
    }
    private let phase = Mutex<Phase>(.idle)

    // MARK: Initialization

    /// - Parameter sni: TLS SNI hostname; defaults to `host` when `nil`.
    init(host: String, port: UInt16, sni: String?, alpn: [String] = ["h2"], tunnel: ProxyConnection? = nil) {
        self.host = host
        self.port = port
        self.sni = sni ?? host
        self.alpn = alpn
        self.tunnel = tunnel
    }

    // MARK: - Connect

    func connect() async throws {
        let configuration = TLSConfiguration(
            serverName: sni,
            alpn: alpn
        )
        let client = TLSClient(configuration: configuration)
        let claimed = phase.withLock { Phase.transition(&$0, to: .connecting(client)) }
        guard claimed else { throw AnywhereError.transport(.terminated) }

        do {
            let connection: TLSRecordConnection
            if let tunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            let published = phase.withLock { Phase.transition(&$0, to: .ready(connection)) }
            guard published else {
                connection.cancel()
                throw AnywhereError.transport(.terminated)
            }
        } catch {
            _ = phase.withLock { Phase.transition(&$0, to: .cancelled) }
            client.cancel()
            throw error
        }
    }

    // MARK: - Send

    func send(_ data: Data) async throws {
        guard let tlsConnection = phase.withLock({ if case .ready(let c) = $0 { c } else { nil } }) else {
            throw AnywhereError.transport(.notConnected)
        }
        try await tlsConnection.send(data)
    }

    // MARK: - Receive

    func receive() async throws -> Data? {
        guard let tlsConnection = phase.withLock({ if case .ready(let c) = $0 { c } else { nil } }) else {
            throw AnywhereError.transport(.notConnected)
        }
        return try await tlsConnection.receive()
    }

    // MARK: - Cancel

    func cancel() {
        enum Doomed { case client(TLSClient), connection(TLSRecordConnection), none }
        let doomed: Doomed = phase.withLock { phase in
            defer { Phase.transition(&phase, to: .cancelled) }
            switch phase {
            case .connecting(let client): return .client(client)
            case .ready(let connection): return .connection(connection)
            case .idle, .cancelled: return .none
            }
        }
        switch doomed {
        case .client(let client): client.cancel()
        case .connection(let connection): connection.cancel()
        case .none: break
        }
    }
}
