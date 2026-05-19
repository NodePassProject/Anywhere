//
//  AnyTLSUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

/// UDP-over-AnyTLS wrapper.
///
/// Wraps an `AnyTLSStream` whose other end is the AnyTLS server's UoT
/// handler. Once the UoT request `[isConnect=1][SocksaddrSerializer(dest)]`
/// has been written by `connectWithAnyTLS`, every UDP datagram in either
/// direction is just `[length BE u16][payload]` — exactly the framing the
/// shared `UDPFramingCapable` helper provides.
nonisolated final class AnyTLSUDPConnection: ProxyConnection, UDPFramingCapable {

    private let inner: AnyTLSStream

    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

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
        udpLock.lock()
        if let packet = extractUDPPacket() {
            udpLock.unlock()
            completion(packet, nil)
            return
        }
        udpLock.unlock()
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
            self.udpLock.lock()
            self.udpBuffer.append(data)
            if let packet = self.extractUDPPacket() {
                self.udpLock.unlock()
                completion(packet, nil)
            } else {
                self.udpLock.unlock()
                self.receiveMore(completion: completion)
            }
        }
    }

    override func cancel() {
        udpLock.lock()
        clearUDPBuffer()
        udpLock.unlock()
        inner.cancel()
    }
}
