//
//  TrojanConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TrojanConnection")

nonisolated final class TrojanConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let pendingHeader: Mutex<Data?>

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.pendingHeader = Mutex(TrojanProtocol.buildRequestHeader(
            passwordKey: TrojanProtocol.passwordKey(password),
            command: TrojanProtocol.commandTCP,
            host: destinationHost,
            port: destinationPort
        ))
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

    override func cancel() {
        inner.cancel()
    }

    /// Returns the header on the first call and `nil` thereafter.
    private func consumeHeader() -> Data? {
        pendingHeader.withLock { header in
            defer { header = nil }
            return header
        }
    }
}
