//
//  RealityProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over a ``TLSRecordConnection`` transport.
class RealityProxyConnection: ProxyConnection {
    private let realityConnection: TLSRecordConnection

    /// Creates a new Reality-backed proxy connection.
    ///
    /// - Parameter realityConnection: The underlying TLS record connection.
    init(realityConnection: TLSRecordConnection) {
        self.realityConnection = realityConnection
    }

    /// Reality always negotiates TLS 1.3.
    override var outerTLSVersion: TLSVersion? { .tls13 }

    override var isConnected: Bool {
        realityConnection.connection?.isTransportReady ?? false
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        realityConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        realityConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        realityConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                // Pass through decryption failures with raw data for Vision direct copy mode
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
        realityConnection.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        realityConnection.receiveRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        realityConnection.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        realityConnection.sendRaw(data: data)
    }
}
