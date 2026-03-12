//
//  HTTPUpgradeProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over an ``HTTPUpgradeConnection`` transport (raw TCP after HTTP upgrade).
class HTTPUpgradeProxyConnection: ProxyConnection {
    private let huConnection: HTTPUpgradeConnection

    init(huConnection: HTTPUpgradeConnection) {
        self.huConnection = huConnection
    }

    override var isConnected: Bool {
        huConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        huConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        huConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        huConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
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
        huConnection.cancel()
    }
}
