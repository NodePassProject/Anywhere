//
//  VLESSUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated final class VLESSUDPConnection: ProxyConnection, UDPFramingCapable {

    private let inner: ProxyConnection

    let udpState = Mutex(UDPFramingState())

    /// Serializes framed datagram writes across the wire `await`. The datagram flow
    /// submits sends fire-and-forget, so without this two datagrams could interleave
    /// their length-prefixed frames on the stream transport and corrupt it. UDP
    /// tolerates whole-datagram reordering; only intra-frame interleaving is fatal.
    private let sendMutex = AsyncMutex()

    init(inner: ProxyConnection) {
        self.inner = inner
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    override var deliversDatagrams: Bool { true }

    // MARK: - Send: length-prefix each datagram, then hand off to the TCP-style inner.

    override func sendRaw(_ data: Data) async throws {
        try await sendMutex.withLock {
            try await inner.sendRaw(frameUDPPacket(data))
        }
    }

    // MARK: - Receive: pull one framed packet at a time.

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

    override func cancel() {
        udpState.withLock { clearUDPBuffer(&$0) }
        inner.cancel()
    }
}
