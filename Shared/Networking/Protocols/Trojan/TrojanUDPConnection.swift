//
//  TrojanUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TrojanUDPConnection")

nonisolated final class TrojanUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let destinationHost: String
    private let destinationPort: UInt16

    private let pendingHeader: Mutex<Data?>
    private let receiveBuffer = Mutex(Data())

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        let passwordKey = TrojanProtocol.passwordKey(password)
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.pendingHeader = Mutex(TrojanProtocol.buildRequestHeader(
            passwordKey: passwordKey,
            command: TrojanProtocol.commandUDP,
            host: destinationHost,
            port: destinationPort
        ))
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    func sendRaw(_ data: Data) async throws {
        let header = consumeHeader()
        let packet = TrojanProtocol.encodeUDPPacket(host: destinationHost, port: destinationPort, payload: data)
        try await inner.sendRaw(header.map { $0 + packet } ?? packet)
    }

    private func consumeHeader() -> Data? {
        pendingHeader.withLock { header in
            defer { header = nil }
            return header
        }
    }

    func receiveRaw() async throws -> Data? {
        try await nextPacket()
    }

    func cancel() {
        inner.cancel()
    }

    // MARK: - Framing

    private func nextPacket() async throws -> Data? {
        while true {
            let parsed: Data? = try receiveBuffer.withLock { buffer in
                guard let parsed = try TrojanProtocol.tryDecodeUDPPacket(buffer: buffer) else { return nil }
                buffer.removeFirst(parsed.consumed)
                return parsed.payload
            }
            if let parsed {
                return parsed
            }

            guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                return nil
            }
            receiveBuffer.withLock { $0.append(data) }
        }
    }
}
