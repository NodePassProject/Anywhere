//
//  TrojanUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TrojanUDPConnection")

// MARK: - TrojanUDPConnection

/// Wraps a TLS-backed ProxyConnection as a Trojan UDP-over-TCP session: each datagram
/// is framed as `addr:port + length + CRLF + payload` after a one-shot UDP request header.
nonisolated final class TrojanUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let passwordKey: Data
    private let dstHost: String
    private let dstPort: UInt16

    private var headerSent = false
    /// Buffers TLS stream bytes across receives; leftovers carry over to the next call.
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
    override var deliversDatagrams: Bool { true }

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
