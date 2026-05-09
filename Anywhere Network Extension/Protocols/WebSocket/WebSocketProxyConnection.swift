//
//  WebSocketProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over a ``WebSocketConnection`` transport.
class WebSocketProxyConnection: ProxyConnection {
    private let wsConnection: WebSocketConnection

    init(wsConnection: WebSocketConnection) {
        self.wsConnection = wsConnection
    }

    override var isConnected: Bool {
        wsConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        wsConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        wsConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        wsConnection.receive { data, error in
            completion(data, error)
        }
    }

    override func cancel() {
        wsConnection.cancel()
    }
}
