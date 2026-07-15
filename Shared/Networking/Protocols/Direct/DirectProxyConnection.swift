//
//  DirectProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class DirectProxyConnection: AsyncProxyConnection, @unchecked Sendable {

    private let transport: any AsyncByteTransport

    init(transport: any AsyncByteTransport) {
        self.transport = transport
        super.init()
    }

    override var isConnected: Bool { transport.isReady }

    override func sendRaw(_ data: Data) async throws {
        try await transport.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        switch try await transport.receive() {
        case .bytes(let data): return data
        case .end: return nil
        }
    }

    override func closeWrite() async throws {
        try await transport.finishSend()
    }

    override func performCancel() {
        transport.cancel()
    }
}
