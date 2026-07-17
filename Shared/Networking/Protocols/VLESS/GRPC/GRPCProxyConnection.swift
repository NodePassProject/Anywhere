//
//  GRPCProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/23/26.
//

import Foundation

nonisolated final class GRPCProxyConnection: ProxyConnection {
    private let grpcConnection: GRPCConnection

    init(grpcConnection: GRPCConnection) {
        self.grpcConnection = grpcConnection
    }

    var isConnected: Bool {
        grpcConnection.isConnected
    }

    func sendRaw(_ data: Data) async throws {
        try await grpcConnection.send(data)
    }

    func receiveRaw() async throws -> Data? {
        try await grpcConnection.receive()
    }

    func cancel() {
        grpcConnection.cancel()
    }
}
