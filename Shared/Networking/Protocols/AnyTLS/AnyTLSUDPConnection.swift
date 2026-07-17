//
//  AnyTLSUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated final class AnyTLSUDPConnection: ProxyConnection, UDPFramingCapable {

    private let inner: AnyTLSStream

    let udpState = Mutex(UDPFramingState())

    init(inner: AnyTLSStream) {
        self.inner = inner
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    // MARK: - Send

    func sendRaw(_ data: Data) async throws {
        try await inner.sendRaw(frameUDPPacket(data))
    }

    // MARK: - Receive

    func receiveRaw() async throws -> Data? {
        if let packet = udpState.withLock({ extractUDPPacket(from: &$0) }) {
            return packet
        }
        while true {
            guard let data = try await inner.receiveRaw() else { return nil }
            let packet = udpState.withLock { state -> Data? in
                state.buffer.append(data)
                return extractUDPPacket(from: &state)
            }
            if let packet { return packet }
        }
    }

    // MARK: - Cancel

    func cancel() {
        udpState.withLock { clearUDPBuffer(&$0) }
        inner.cancel()
    }
}
