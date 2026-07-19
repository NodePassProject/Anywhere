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

    /// TLS session state established by ``connect()``: the handshake client (dropped once the record
    /// connection is live) and the live record connection, plus readiness. Held in a mutex so the
    /// abortive nil-swap in ``cancel()`` is atomic against the in-flight send/receive that read it.
    /// Consumers drive send/receive serially, so the connection reference is only ever taken out and
    /// awaited off-lock — the record connection serializes its own writes internally.
    private struct State {
        var tlsClient: TLSClient?
        var tlsConnection: TLSRecordConnection?
        var isReady = false
    }
    private let state = Mutex(State())

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
        state.withLock { $0.tlsClient = client }

        do {
            let connection: TLSRecordConnection
            if let tunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            state.withLock { state in
                state.tlsConnection = connection
                state.tlsClient = nil
                state.isReady = true
            }
        } catch {
            let client = state.withLock { state -> TLSClient? in
                let client = state.tlsClient
                state.tlsClient = nil
                return client
            }
            client?.cancel()
            throw error
        }
    }

    // MARK: - Send

    func send(_ data: Data) async throws {
        guard let tlsConnection = state.withLock({ $0.isReady ? $0.tlsConnection : nil }) else {
            throw AnywhereError.transport(.notConnected)
        }
        try await tlsConnection.send(data)
    }

    // MARK: - Receive

    func receive() async throws -> Data? {
        guard let tlsConnection = state.withLock({ $0.isReady ? $0.tlsConnection : nil }) else {
            throw AnywhereError.transport(.notConnected)
        }
        return try await tlsConnection.receive()
    }

    // MARK: - Cancel

    func cancel() {
        let (client, connection) = state.withLock { state -> (TLSClient?, TLSRecordConnection?) in
            state.isReady = false
            let client = state.tlsClient
            let connection = state.tlsConnection
            state.tlsClient = nil
            state.tlsConnection = nil
            return (client, connection)
        }
        client?.cancel()
        connection?.cancel()
    }
}
