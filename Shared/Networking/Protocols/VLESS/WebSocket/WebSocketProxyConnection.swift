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
    }

    var isConnected: Bool {
        wsConnection.isConnected
    }

    func sendRaw(_ data: Data) async throws {
        try await wsConnection.send(data)
    }

    func receiveRaw() async throws -> Data? {
        try await wsConnection.receive()
    }

    func cancel() {
        wsConnection.cancel()
    }
}
