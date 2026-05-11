//
//  HTTPUpgradeProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over an ``HTTPUpgradeConnection`` transport (raw TCP after HTTP upgrade).
nonisolated class HTTPUpgradeProxyConnection: ProxyConnection {
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
        huConnection.receive { data, error in
            completion(data, error)
        }
    }

    override func cancel() {
        huConnection.cancel()
    }
}
