//
//  TunneledTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

nonisolated final class TunneledTransport: AsyncByteTransport, @unchecked Sendable {
    private let tunnel: ProxyConnection

    init(tunnel: ProxyConnection) {
        self.tunnel = tunnel
    }

    var isReady: Bool { tunnel.isConnected }

    func send(_ data: Data) async throws {
        try await tunnel.sendRaw(data)
    }

    func finishSend() async throws {
        try await tunnel.closeWrite()
    }

    func receive() async throws -> TransportChunk {
        if let data = try await tunnel.receiveRaw(), !data.isEmpty {
            return .bytes(data)
        }
        return .end
    }

    func cancel() {
        tunnel.cancel()
    }
}
