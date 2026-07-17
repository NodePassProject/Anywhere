//
//  ShadowsocksConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/6/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "ShadowsocksConnection")

// MARK: - ShadowsocksConnection

/// Address header is prepended to the first send, encrypted as part of the AEAD stream.
nonisolated final class ShadowsocksConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let writer: ShadowsocksAEADWriter
    private let reader: ShadowsocksAEADReader
    private let addressHeader: Mutex<Data?>

    init(inner: ProxyConnection, cipher: ShadowsocksCipher, masterKey: Data, addressHeader: Data) {
        self.inner = inner
        self.writer = ShadowsocksAEADWriter(cipher: cipher, masterKey: masterKey)
        self.reader = ShadowsocksAEADReader(cipher: cipher, masterKey: masterKey)
        self.addressHeader = Mutex(addressHeader)
    }

    var isConnected: Bool { inner.isConnected }

    func sendRaw(_ data: Data) async throws {
        var plaintext = Data()
        addressHeader.withLock { header in
            if let h = header {
                plaintext.append(h)
                header = nil
            }
        }
        plaintext.append(data)

        let encrypted = try writer.seal(plaintext: plaintext)
        try await inner.sendRaw(encrypted)
    }

    func receiveRaw() async throws -> Data? {
        while true {
            guard let data = try await inner.receiveRaw(), !data.isEmpty else {
                return nil
            }
            let plaintext = try reader.open(ciphertext: data)
            if plaintext.isEmpty {
                continue
            }
            return plaintext
        }
    }

    func cancel() {
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
        // `inner.send` so any UoT framing wraps each encrypted datagram.
        try await inner.send(encrypted)
    }

    func receiveRaw() async throws -> Data? {
        guard let data = try await inner.receive(), !data.isEmpty else {
            return nil
        }
        let decrypted = try ShadowsocksUDPCrypto.decrypt(cipher: cipher, masterKey: masterKey, data: data)
        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: decrypted) else {
            throw ShadowsocksError.invalidAddress
        }
        return parsed.payload
    }

    func cancel() {
        inner.cancel()
    }
}
