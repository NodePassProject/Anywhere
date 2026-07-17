//
//  XHTTPProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated final class XHTTPProxyConnection: ProxyConnection {
    private let xhttpConnection: XHTTPConnection

    init(xhttpConnection: XHTTPConnection) {
        self.xhttpConnection = xhttpConnection
    }

    var isConnected: Bool {
        xhttpConnection.isConnected
    }

    func sendRaw(_ data: Data) async throws {
        try await xhttpConnection.send(data)
    }

    func receiveRaw() async throws -> Data? {
        try await xhttpConnection.receive()
    }

    func cancel() {
        xhttpConnection.cancel()
    }
}
