//
//  TrojanUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TrojanUDPConnection")

// MARK: - TrojanUDPConnection

/// Each datagram is framed as `addr:port + length + CRLF + payload`, after a one-shot UDP request header.
nonisolated final class TrojanUDPConnection: AsyncProxyConnection {
    private let inner: ProxyConnection
    private let passwordKey: Data
    private let destinationHost: String
    private let destinationPort: UInt16

    private var headerSent = false
    /// Leftover TLS stream bytes carried across receives until a full packet is framed.
    private var receiveBuffer = Data()

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.passwordKey = TrojanProtocol.passwordKey(password)
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    override var deliversDatagrams: Bool { true }

    override func sendRaw(_ data: Data) async throws {
        try await inner.sendRaw(frame(data))
    }

    override func receiveRaw() async throws -> Data? {
        try await nextPacket()
    }

    override func performCancel() {
        inner.cancel()
    }

    // MARK: - Framing

    private func frame(_ payload: Data) -> Data {
        var out = Data()
        lock.lock()
        if !headerSent {
            out.append(TrojanProtocol.buildRequestHeader(
                passwordKey: passwordKey,
                command: TrojanProtocol.commandUDP,
                host: destinationHost,
                port: destinationPort
            ))
            headerSent = true
        }
        lock.unlock()
        out.append(TrojanProtocol.encodeUDPPacket(host: destinationHost, port: destinationPort, payload: payload))
        return out
    }

    private func nextPacket() async throws -> Data? {
        while true {
            let parsed: (payload: Data, consumed: Int)? = try lock.withLock {
                try TrojanProtocol.tryDecodeUDPPacket(buffer: receiveBuffer)
            }
            if let parsed {
                lock.withLock { receiveBuffer.removeFirst(parsed.consumed) }
                return parsed.payload
            }

            guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                return nil
            }
            lock.withLock { receiveBuffer.append(data) }
        }
    }
}
