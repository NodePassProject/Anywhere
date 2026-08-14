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
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    func sendRaw(_ data: Data) async throws {
        let header = consumeHeader()
        try await inner.sendRaw(header.map { $0 + data } ?? data)
    }

    func receiveRaw() async throws -> Data? {
        try await inner.receiveRaw()
    }

    func cancel() {
        inner.cancel()
    }

    private func consumeHeader() -> Data? {
        pendingHeader.withLock { header in
            defer { header = nil }
            return header
        }
    }
}
