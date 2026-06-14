//
//  TLSStreamTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TLSStream")

// MARK: - Error

enum TLSStreamError: Error, LocalizedError {
    case connectionFailed(String)
    case notConnected

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let msg): return "TLS stream connection failed: \(msg)"
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

    func connect(completion: @escaping (Error?) -> Void) {
        let configuration = TLSConfiguration(
            serverName: sni,
            alpn: alpn
        )
        let client = TLSClient(configuration: configuration)
        self.tlsClient = client

        let handleResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let connection):
                self.tlsConnection = connection
                self.tlsClient = nil
                self.isReady = true
                completion(nil)
            case .failure(let error):
                self.tlsClient?.cancel()
                self.tlsClient = nil
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

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard let tlsConnection, isReady else {
            completion(TLSStreamError.notConnected)
            return
        }
        tlsConnection.send(data: data, completion: completion)
    }

    // MARK: - Receive

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
