//
//  WebSocketProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class WebSocketProxyConnection: ProxyConnection {
    private let wsConnection: WebSocketConnection

    init(wsConnection: WebSocketConnection) {
        self.wsConnection = wsConnection
        super.init()
    }

    override var isConnected: Bool {
        wsConnection.isConnected
    }

    override func sendRaw(_ data: Data) async throws {
        try await wsConnection.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        try await wsConnection.receive()
    }

    override func cancel() {
        wsConnection.cancel()
    }
}
