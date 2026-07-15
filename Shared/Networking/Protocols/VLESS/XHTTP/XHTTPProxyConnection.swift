//
//  XHTTPProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class XHTTPProxyConnection: ProxyConnection {
    private let xhttpConnection: XHTTPConnection

    init(xhttpConnection: XHTTPConnection) {
        self.xhttpConnection = xhttpConnection
        super.init()
    }

    override var isConnected: Bool {
        xhttpConnection.isConnected
    }

    override func sendRaw(_ data: Data) async throws {
        try await xhttpConnection.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        try await xhttpConnection.receive()
    }

    override func cancel() {
        xhttpConnection.cancel()
    }
}
