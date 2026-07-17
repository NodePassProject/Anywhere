//
//  HTTPUpgradeProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated final class HTTPUpgradeProxyConnection: ProxyConnection {
    private let huConnection: HTTPUpgradeConnection

    init(huConnection: HTTPUpgradeConnection) {
        self.huConnection = huConnection
    }

    var isConnected: Bool {
        huConnection.isConnected
    }

    func sendRaw(_ data: Data) async throws {
        try await huConnection.send(data)
    }

    func receiveRaw() async throws -> Data? {
        try await huConnection.receive()
    }

    func cancel() {
        huConnection.cancel()
    }
}
