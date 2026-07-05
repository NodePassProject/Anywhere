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
nonisolated final class AnyTLSUDPConnection: ProxyConnection, UDPFramingCapable {

    private let inner: AnyTLSStream

    let udpState = Mutex(UDPFramingState())

    init(inner: AnyTLSStream) {
        self.inner = inner
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    override var deliversDatagrams: Bool { true }

    // MARK: - Send

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        super.send(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        super.send(data: frameUDPPacket(data))
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        inner.sendRaw(data: data)
    }

    // MARK: - Receive

    override func receive(completion: @escaping (Data?, Error?) -> Void) {
        if let packet = udpState.withLock({ extractUDPPacket(from: &$0) }) {
            completion(packet, nil)
            return
        }
        receiveMore(completion: completion)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw(completion: completion)
    }

    private func receiveMore(completion: @escaping (Data?, Error?) -> Void) {
        inner.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(nil, error)
                return
            }
            guard let data else {
                completion(nil, nil)
                return
            }
            let packet = self.udpState.withLock { state -> Data? in
                state.buffer.append(data)
                return self.extractUDPPacket(from: &state)
            }
            if let packet {
                completion(packet, nil)
            } else {
                self.receiveMore(completion: completion)
            }
        }
    }

    override func cancel() {
        udpState.withLock { clearUDPBuffer(&$0) }
        inner.cancel()
    }
}
