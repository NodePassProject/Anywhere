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

/// TLS transport for NaiveProxy connections using ``BSDSocket`` + ``TLSClient``.
///
/// Reuses Anywhere's existing TLS infrastructure to establish a TLS 1.3 connection
/// to the proxy server with ALPN `["h2"]` for HTTP/2 negotiation. After the
/// handshake, all I/O goes through a ``TLSRecordConnection`` which handles
/// TLS record encryption/decryption over the raw socket.
class NaiveTLSTransport {

    private let host: String
    private let port: UInt16
    private let sni: String
    private let insecure: Bool

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
    ///   - insecure: If `true`, skips certificate validation (testing only).
    init(host: String, port: UInt16, sni: String?, insecure: Bool = false) {
        self.host = host
        self.port = port
        self.sni = sni ?? host
        self.insecure = insecure
    }

    // MARK: - Connect

    /// Establishes a TLS connection to the proxy server with ALPN `["h2"]`.
    ///
    /// Uses ``BSDSocket`` for TCP and ``TLSClient`` for the TLS 1.3 handshake.
    /// On success, stores the ``TLSRecordConnection`` for subsequent I/O.
    ///
    /// - Parameter completion: Called with `nil` on success or an error on failure.
    func connect(completion: @escaping (Error?) -> Void) {
        let config = TLSConfiguration(
            serverName: sni,
            alpn: ["h2"],
            allowInsecure: insecure
        )
        let client = TLSClient(configuration: config)
        self.tlsClient = client

        client.connect(host: host, port: port) { [weak self] result in
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
                completion(NaiveTLSError.connectionFailed(error.localizedDescription))
            }
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
