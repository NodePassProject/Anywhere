//
//  AnyTLSUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

/// UDP-over-AnyTLS wrapper: after the UoT request `[isConnect=1][SocksaddrSerializer(dest)]`,
/// every datagram in either direction is `[length BE u16][payload]`.
nonisolated final class AnyTLSUDPConnection: AsyncProxyConnection, UDPFramingCapable {

    private let inner: AnyTLSStream

    let udpState = Mutex(UDPFramingState())

    /// Serializes framed datagram writes across the wire `await`; see `VLESSUDPConnection`.
    private let sendMutex = AsyncMutex()

    init(inner: AnyTLSStream) {
        self.inner = inner
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    override var deliversDatagrams: Bool { true }

    // MARK: - Send

    override func sendRaw(_ data: Data) async throws {
        try await sendMutex.withLock {
            try await inner.sendRaw(frameUDPPacket(data))
        }
    }

    // MARK: - Receive

    override func receiveRaw() async throws -> Data? {
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

    override func performCancel() {
        udpState.withLock { clearUDPBuffer(&$0) }
        inner.cancel()
    }
}
