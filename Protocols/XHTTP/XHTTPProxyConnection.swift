//
//  XHTTPProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over an ``XHTTPConnection`` transport.
class XHTTPProxyConnection: ProxyConnection {
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
        xhttpConnection.receive { [weak self] data, error in
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
        xhttpConnection.cancel()
    }
}
