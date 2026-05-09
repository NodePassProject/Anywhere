//
//  GRPCProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/23/26.
//

import Foundation

/// Proxy connection over a ``GRPCConnection`` transport.
class GRPCProxyConnection: ProxyConnection {
    private let grpcConnection: GRPCConnection

    init(grpcConnection: GRPCConnection) {
        self.grpcConnection = grpcConnection
    }

    override var isConnected: Bool {
        grpcConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        grpcConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        grpcConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        grpcConnection.receive { data, error in
            completion(data, error)
        }
    }

    override func cancel() {
        grpcConnection.cancel()
    }
}
