//
//  GRPCProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/23/26.
//

import Foundation

nonisolated class GRPCProxyConnection: ProxyConnection {
    private let grpcConnection: GRPCConnection

    init(grpcConnection: GRPCConnection) {
        self.grpcConnection = grpcConnection
        super.init()
    }

    override var isConnected: Bool {
        grpcConnection.isConnected
    }

    override func sendRaw(_ data: Data) async throws {
        try await grpcConnection.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        try await grpcConnection.receive()
    }

    override func cancel() {
        grpcConnection.cancel()
    }
}
