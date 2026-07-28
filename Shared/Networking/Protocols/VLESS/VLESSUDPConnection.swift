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

    /// Ordered send pipeline: each framed datagram reaches the stream transport in submission
    /// order, so a datagram's length-prefixed frame never interleaves another's. UDP tolerates
    /// whole-datagram reordering; only intra-frame interleaving is fatal.
    private let sendChain = SerialSender()

    init(inner: ProxyConnection) {
        self.inner = inner
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    // MARK: - Send: length-prefix each datagram, then hand off to the TCP-style inner.

    func sendRaw(_ data: Data) async throws {
        let frame = frameUDPPacket(data)
        let inner = self.inner
        try await sendChain.run { try await inner.sendRaw(frame) }
    }

    // MARK: - Receive: pull one framed packet at a time.

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
        sendChain.cancel()
        inner.cancel()
    }
}
