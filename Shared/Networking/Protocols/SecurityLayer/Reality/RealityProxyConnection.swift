//
//  RealityProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class RealityProxyConnection: ProxyConnection {
    private let realityConnection: TLSRecordConnection

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
                // AEAD auth failure means the record no longer decrypts with the derived
                // keys — the server may have switched to Vision direct-copy. Only that
                // case maps to the Reality-specific error; everything else propagates.
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
