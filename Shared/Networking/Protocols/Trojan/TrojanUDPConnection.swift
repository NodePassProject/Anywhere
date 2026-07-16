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
    private let passwordKey: Data
    private let destinationHost: String
    private let destinationPort: UInt16

    private let headerSent = Atomic<Bool>(false)
    /// Leftover TLS stream bytes carried across receives until a full packet is framed.
    private let receiveBuffer = Mutex(Data())

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.passwordKey = TrojanProtocol.passwordKey(password)
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    func sendRaw(_ data: Data) async throws {
        try await inner.sendRaw(frame(data))
    }

    func receiveRaw() async throws -> Data? {
        try await nextPacket()
    }

    func cancel() {
        inner.cancel()
    }

    // MARK: - Framing

    private func frame(_ payload: Data) -> Data {
        var out = Data()
        if !headerSent.exchange(true, ordering: .acquiringAndReleasing) {
            out.append(TrojanProtocol.buildRequestHeader(
                passwordKey: passwordKey,
                command: TrojanProtocol.commandUDP,
                host: destinationHost,
                port: destinationPort
            ))
        }
        out.append(TrojanProtocol.encodeUDPPacket(host: destinationHost, port: destinationPort, payload: payload))
        return out
    }

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
