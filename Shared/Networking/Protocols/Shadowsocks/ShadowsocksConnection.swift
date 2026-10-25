//
//  ShadowsocksConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/6/26.
//

import Foundation
import Synchronization

// MARK: - ShadowsocksConnection

nonisolated final class ShadowsocksConnection: ProxyConnection {
    private let inner: ProxyConnection
    
    private struct SendState {
        var addressHeader: Data?
        var writer: ShadowsocksAEADWriter
    }
    private let sendState: Mutex<SendState>
    
    private let reader: Mutex<ShadowsocksAEADReader>

    private let sendChain = SerialSender()

    init(inner: ProxyConnection, cipher: ShadowsocksCipher, masterKey: Data, addressHeader: Data) {
        self.inner = inner
        self.sendState = Mutex(SendState(
            addressHeader: addressHeader,
            writer: ShadowsocksAEADWriter(cipher: cipher, masterKey: masterKey)
        ))
        self.reader = Mutex(ShadowsocksAEADReader(cipher: cipher, masterKey: masterKey))
    }

    var isConnected: Bool { inner.isConnected }

    func sendRaw(_ data: Data) async throws {
        let pending: SerialSender.Pending = try sendState.withLock { state in
            var plaintext = Data()
            if let header = state.addressHeader {
                plaintext.append(header)
                state.addressHeader = nil
            }
            plaintext.append(data)
            let encrypted = try state.writer.seal(plaintext: plaintext)
            let inner = self.inner
            return sendChain.submit { try await inner.sendRaw(encrypted) }
        }
        try await pending.value()
    }

    func receiveRaw() async throws -> Data? {
        while true {
            guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                return nil
            }
            let plaintext = try reader.withLock { try $0.open(ciphertext: data) }
            if plaintext.isEmpty {
                continue
            }
            return plaintext
        }
    }

    func cancel() {
        sendChain.cancel()
        inner.cancel()
    }
}

// MARK: - ShadowsocksUDPConnection

nonisolated final class ShadowsocksUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let cipher: ShadowsocksCipher
    private let masterKey: Data
    private let dstHost: String
    private let dstPort: UInt16

    init(inner: ProxyConnection, cipher: ShadowsocksCipher, masterKey: Data, dstHost: String, dstPort: UInt16) {
        self.inner = inner
        self.cipher = cipher
        self.masterKey = masterKey
        self.dstHost = dstHost
        self.dstPort = dstPort
    }

    var isConnected: Bool { inner.isConnected }
    var deliversDatagrams: Bool { true }

    func sendRaw(_ data: Data) async throws {
        let packet = ShadowsocksProtocol.encodeUDPPacket(host: dstHost, port: dstPort, payload: data)
        let encrypted = try ShadowsocksUDPCrypto.encrypt(cipher: cipher, masterKey: masterKey, payload: packet)
        try await inner.send(encrypted)
    }

    func receiveRaw() async throws -> Data? {
        while true {
            guard let data = try await inner.receive() else {
                return nil
            }
            if let decrypted = try? ShadowsocksUDPCrypto.decrypt(cipher: cipher, masterKey: masterKey, data: data),
               let parsed = ShadowsocksProtocol.decodeUDPPacket(data: decrypted) {
                return parsed.payload
            }
        }
    }

    func cancel() {
        inner.cancel()
    }
}
