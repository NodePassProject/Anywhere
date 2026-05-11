//
//  VLESSUDPConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

nonisolated final class VLESSUDPConnection: ProxyConnection, UDPFramingCapable {

    private let inner: ProxyConnection

    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    init(inner: ProxyConnection) {
        self.inner = inner
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    // MARK: - Send: frame payload then hand off to the TCP-style inner.

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

    // MARK: - Receive: pull one framed packet at a time.

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

    // MARK: - Cancel

    override func cancel() {
        udpLock.lock()
        clearUDPBuffer()
        udpLock.unlock()
        inner.cancel()
    }

    // MARK: - Direct (Vision bypass) passthroughs

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveDirectRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendDirectRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        inner.sendDirectRaw(data: data)
    }
}
