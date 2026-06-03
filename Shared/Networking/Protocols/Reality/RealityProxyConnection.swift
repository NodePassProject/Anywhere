//
//  RealityProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

/// Proxy connection over a ``TLSRecordConnection`` transport.
nonisolated class RealityProxyConnection: ProxyConnection {
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
        realityConnection.receive { data, error in
            if let error {
                // An AEAD authentication failure on a Reality connection means
                // the record no longer decrypts with the handshake-derived keys
                // — the server may have switched to Vision direct-copy. Surface
                // the Reality-specific diagnostic for that one case; every other
                // record-layer error (MAC, padding, malformed framing, alerts)
                // propagates with its real description.
                if case TLSRecordError.recordAuthenticationFailed = error {
                    completion(nil, RealityError.decryptionFailed)
                    return
                }
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            completion(data, nil)
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
