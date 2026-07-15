//
//  DirectUDPProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// A `ProxyConnection` over an async-native datagram transport; each `send`/`receive`
/// preserves one datagram boundary. Pull-native — `receiveRaw()` is one
/// `await transport.receive()`, so no push adapter or receive buffer is needed.
nonisolated final class DirectUDPProxyConnection: ProxyConnection {

    private let transport: any AsyncDatagramTransport

    init(transport: any AsyncDatagramTransport) {
        self.transport = transport
        super.init()
    }

    override var isConnected: Bool { transport.isReady }
    override var deliversDatagrams: Bool { true }

    override func sendRaw(_ data: Data) async throws {
        try await transport.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        // The datagram transport throws on terminal failure and never signals a clean
        // EOF, so this only returns data (or propagates the throw).
        try await transport.receive()
    }

    override func cancel() {
        transport.cancel()
    }
}
