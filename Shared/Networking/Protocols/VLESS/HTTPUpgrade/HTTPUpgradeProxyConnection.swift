//
//  HTTPUpgradeProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class HTTPUpgradeProxyConnection: AsyncProxyConnection {
    private let huConnection: HTTPUpgradeConnection

    init(huConnection: HTTPUpgradeConnection) {
        self.huConnection = huConnection
        super.init()
    }

    override var isConnected: Bool {
        huConnection.isConnected
    }

    override func sendRaw(_ data: Data) async throws {
        try await huConnection.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        try await huConnection.receive()
    }

    override func performCancel() {
        huConnection.cancel()
    }
}
