//
//  TrojanUDPConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/22/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Trojan-UDP")

// MARK: - TrojanUDPConnection

/// Wraps a TLS-backed ProxyConnection as a Trojan UDP-over-TCP session.
///
/// Each outgoing datagram is framed as `addr:port + length + CRLF + payload`
/// on top of the Trojan UDP request header (sent once). The inbound side
/// buffers stream bytes from TLS and emits one payload per `receiveRaw` call,
/// silently dropping the per-packet header — the upper layer only sees raw
/// UDP payloads addressed to the destination it originally requested.
final class TrojanUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let passwordKey: Data
    private let dstHost: String
    private let dstPort: UInt16

    private var headerSent = false
    /// Accumulates TLS stream bytes across receives; packets are decoded as
    /// soon as enough bytes arrive and leftovers carry over to the next call.
    private var receiveBuffer = Data()

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.passwordKey = TrojanProtocol.passwordKey(password)
        self.dstHost = destinationHost
        self.dstPort = destinationPort
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: frame(data), completion: completion)
    }

    override func sendRaw(data: Data) {
        inner.sendRaw(data: frame(data))
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        deliverNextPacket(completion: completion)
    }

    override func cancel() {
        inner.cancel()
    }

    // MARK: - Framing

    /// Prepends the one-shot request header (first call only) to a framed UDP packet.
    private func frame(_ payload: Data) -> Data {
        var out = Data()
        lock.lock()
        if !headerSent {
            out.append(TrojanProtocol.buildRequestHeader(
                passwordKey: passwordKey,
                command: TrojanProtocol.commandUDP,
                host: dstHost,
                port: dstPort
            ))
            headerSent = true
        }
        lock.unlock()
        out.append(TrojanProtocol.encodeUDPPacket(host: dstHost, port: dstPort, payload: payload))
        return out
    }

    /// Tries to decode one complete packet from `receiveBuffer`. If the buffer
    /// is short, reads more from `inner` and retries.
    private func deliverNextPacket(completion: @escaping (Data?, Error?) -> Void) {
        do {
            let parsed: (payload: Data, consumed: Int)? = try lock.withLock {
                try TrojanProtocol.tryDecodeUDPPacket(buffer: receiveBuffer)
            }
            if let parsed {
                lock.withLock { receiveBuffer.removeFirst(parsed.consumed) }
                completion(parsed.payload, nil)
                return
            }
        } catch {
            completion(nil, error)
            return
        }

        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Trojan UDP deallocated"))
                return
            }
            if let error {
                completion(nil, error)
                return
            }
            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }
            self.lock.withLock { self.receiveBuffer.append(data) }
            self.deliverNextPacket(completion: completion)
        }
    }
}
