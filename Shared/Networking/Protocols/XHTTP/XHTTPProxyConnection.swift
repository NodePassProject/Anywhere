//
//  XHTTPProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over an ``XHTTPConnection`` transport.
nonisolated class XHTTPProxyConnection: ProxyConnection {
    private let xhttpConnection: XHTTPConnection

    init(xhttpConnection: XHTTPConnection) {
        self.xhttpConnection = xhttpConnection
    }

    override var isConnected: Bool {
        xhttpConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        xhttpConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        xhttpConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        xhttpConnection.receive { data, error in
            completion(data, error)
        }
    }

    override func cancel() {
        xhttpConnection.cancel()
    }
}
