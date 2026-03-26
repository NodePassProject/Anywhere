//
//  TLSProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over a standard TLS ``TLSRecordConnection`` transport.
class TLSProxyConnection: ProxyConnection {
    private let tlsConnection: TLSRecordConnection

    /// Creates a new TLS-backed proxy connection.
    ///
    /// - Parameter tlsConnection: The underlying TLS record connection.
    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
    }

    /// The negotiated TLS version from the handshake.
    override var outerTLSVersion: TLSVersion? { TLSVersion(rawValue: tlsConnection.tlsVersion) }

    override var isConnected: Bool {
        tlsConnection.connection?.isTransportReady ?? false
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        tlsConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                if case RealityError.decryptionFailed = error {
                    completion(data, error)
                    return
                }
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        tlsConnection.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receiveRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        tlsConnection.sendRaw(data: data)
    }
}
