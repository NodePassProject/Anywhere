//
//  DirectProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class DirectProxyConnection: ProxyConnection, Sendable {

    private let transport: any ByteTransport

    init(transport: any ByteTransport) {
        self.transport = transport
    }

    var isConnected: Bool { transport.isReady }

    func sendRaw(_ data: Data) async throws {
        try await transport.send(data)
    }

    func receiveRaw() async throws -> Data? {
        switch try await transport.receive() {
        case .bytes(let data): return data
        case .end: return nil
        }
    }

    func cancel() {
        transport.cancel()
    }
}
