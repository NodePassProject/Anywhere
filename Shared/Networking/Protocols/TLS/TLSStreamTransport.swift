//
//  TLSStreamTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TLSStreamTransport")

// MARK: - Error

enum TLSStreamError: Error, LocalizedError {
    case connectionFailed(String)
    case notConnected

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let message): return "TLS stream connection failed: \(message)"
        case .notConnected: return "TLS stream not connected"
        }
    }
}

// MARK: - TLSStreamTransport

nonisolated class TLSStreamTransport {

    private let host: String
    private let port: UInt16
    private let sni: String
    private let alpn: [String]
    private let tunnel: ProxyConnection?

    private var tlsClient: TLSClient?
    private var tlsConnection: TLSRecordConnection?

    private(set) var isReady = false

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
        self.tlsClient = client

        do {
            let connection: TLSRecordConnection
            if let tunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            self.tlsConnection = connection
            self.tlsClient = nil
            self.isReady = true
        } catch {
            self.tlsClient?.cancel()
            self.tlsClient = nil
            throw error
        }
    }

    // MARK: - Send

    func send(_ data: Data) async throws {
        guard let tlsConnection, isReady else {
            throw TLSStreamError.notConnected
        }
        try await tlsConnection.send(data)
    }

    // MARK: - Receive

    func receive() async throws -> Data? {
        guard let tlsConnection, isReady else {
            throw TLSStreamError.notConnected
        }
        return try await tlsConnection.receive()
    }

    // MARK: - Callback bridges (for the still-callback Naive consumers)

    func connect(completion: @escaping (Error?) -> Void) {
        Task {
            do { try await connect(); completion(nil) }
            catch { completion(error) }
        }
    }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard let tlsConnection, isReady else {
            completion(TLSStreamError.notConnected)
            return
        }
        tlsConnection.send(data: data, completion: completion)
    }

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard let tlsConnection, isReady else {
            completion(nil, TLSStreamError.notConnected)
            return
        }
        tlsConnection.receive(completion: completion)
    }

    // MARK: - Cancel

    func cancel() {
        isReady = false
        tlsClient?.cancel()
        tlsClient = nil
        tlsConnection?.cancel()
        tlsConnection = nil
    }
}
