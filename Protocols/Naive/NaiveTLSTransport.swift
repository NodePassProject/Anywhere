//
//  NaiveTLSTransport.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "NaiveTLS")

// MARK: - Error

enum NaiveTLSError: Error, LocalizedError {
    case connectionFailed(String)
    case notConnected

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let msg): return "Naive TLS connection failed: \(msg)"
        case .notConnected: return "Naive TLS not connected"
        }
    }
}

// MARK: - NaiveTLSTransport

/// TLS transport for NaiveProxy connections using ``NWTransport`` + ``TLSClient``.
///
/// Reuses Anywhere's existing TLS infrastructure to establish a TLS 1.3 connection
/// to the proxy server. The ALPN protocol list is configurable (e.g. `["h2"]` for
/// HTTP/2, `["http/1.1"]` for HTTP/1.1). After the handshake, all I/O goes through
/// a ``TLSRecordConnection`` which handles TLS record encryption/decryption.
///
/// Supports both direct connections and connections tunneled through an existing
/// ``ProxyConnection`` (for proxy chaining).
class NaiveTLSTransport {

    private let host: String
    private let port: UInt16
    private let sni: String
    private let alpn: [String]
    private let tunnel: ProxyConnection?

    private var tlsClient: TLSClient?
    private var tlsConnection: TLSRecordConnection?

    private(set) var isReady = false

    // MARK: Initialization

    /// Creates a new TLS transport.
    ///
    /// - Parameters:
    ///   - host: The proxy server hostname or IP address.
    ///   - port: The proxy server port.
    ///   - sni: TLS SNI override. Defaults to `host` if `nil`.
    ///   - alpn: ALPN protocol list for TLS negotiation. Defaults to `["h2"]`.
    ///   - tunnel: Optional proxy connection to tunnel through (for proxy chaining).
    init(host: String, port: UInt16, sni: String?, alpn: [String] = ["h2"], tunnel: ProxyConnection? = nil) {
        self.host = host
        self.port = port
        self.sni = sni ?? host
        self.alpn = alpn
        self.tunnel = tunnel
    }

    // MARK: - Connect

    /// Establishes a TLS connection to the proxy server.
    ///
    /// Uses ``NWTransport`` for TCP (or tunnels through an existing ``ProxyConnection``)
    /// and ``TLSClient`` for the TLS 1.3 handshake. On success, stores the
    /// ``TLSRecordConnection`` for subsequent I/O.
    ///
    /// - Parameter completion: Called with `nil` on success or an error on failure.
    func connect(completion: @escaping (Error?) -> Void) {
        let config = TLSConfiguration(
            serverName: sni,
            alpn: alpn
        )
        let client = TLSClient(configuration: config)
        self.tlsClient = client

        let handleResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let connection):
                self.tlsConnection = connection
                self.tlsClient = nil  // Free handshake state
                self.isReady = true
                completion(nil)
            case .failure(let error):
                self.tlsClient = nil
                logger.error("[NaiveTLS] Connection failed: \(error.localizedDescription, privacy: .public)")
                completion(error)
            }
        }

        if let tunnel {
            client.connect(overTunnel: tunnel, completion: handleResult)
        } else {
            client.connect(host: host, port: port, completion: handleResult)
        }
    }

    // MARK: - Send

    /// Sends data through the TLS connection.
    ///
    /// Data is encrypted into TLS Application Data records by the underlying
    /// ``TLSRecordConnection``.
    ///
    /// - Parameters:
    ///   - data: The plaintext data to send.
    ///   - completion: Called with `nil` on success or an error on failure.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard let tlsConnection, isReady else {
            completion(NaiveTLSError.notConnected)
            return
        }
        tlsConnection.send(data: data, completion: completion)
    }

    // MARK: - Receive

    /// Receives decrypted data from the TLS connection.
    ///
    /// - Parameter completion: Called with `(data, nil)` on success, `(nil, nil)` for EOF,
    ///   or `(nil, error)` on failure.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard let tlsConnection, isReady else {
            completion(nil, NaiveTLSError.notConnected)
            return
        }
        tlsConnection.receive(completion: completion)
    }

    // MARK: - Cancel

    /// Closes the TLS connection and releases all resources.
    func cancel() {
        isReady = false
        tlsClient?.cancel()
        tlsClient = nil
        tlsConnection?.cancel()
        tlsConnection = nil
    }
}
