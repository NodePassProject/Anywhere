//
//  TrojanConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TrojanConnection")

// MARK: - TrojanConnection

/// Prepends the Trojan TCP request header to the first outbound payload inside the same TLS record; server replies are unframed pass-through.
nonisolated final class TrojanConnection: AsyncProxyConnection {
    private let inner: ProxyConnection
    private var pendingHeader: Data?

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.pendingHeader = TrojanProtocol.buildRequestHeader(
            passwordKey: TrojanProtocol.passwordKey(password),
            command: TrojanProtocol.commandTCP,
            host: destinationHost,
            port: destinationPort
        )
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    override func sendRaw(_ data: Data) async throws {
        try await inner.sendRaw(consumeHeader().map { $0 + data } ?? data)
    }

    override func receiveRaw() async throws -> Data? {
        try await inner.receiveRaw()
    }

    override func performCancel() {
        inner.cancel()
    }

    /// Returns the header on the first call and `nil` thereafter.
    private func consumeHeader() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let header = pendingHeader
        pendingHeader = nil
        return header
    }
}
