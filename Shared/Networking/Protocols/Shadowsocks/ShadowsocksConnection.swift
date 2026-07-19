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

    /// Send-path state: the one-shot address header plus the AEAD writer (salt, nonce).
    /// The connection is what crosses concurrency domains; one Mutex makes the header
    /// hand-off and the writer's nonce advance a single atomic step per send.
    private struct SendState {
        var addressHeader: Data?
        var writer: ShadowsocksAEADWriter
    }
    private let sendState: Mutex<SendState>

    /// Receive-path AEAD + reassembly state, guarded at the sharing boundary.
    private let reader: Mutex<ShadowsocksAEADReader>

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
        let encrypted = try sendState.withLock { state in
            var plaintext = Data()
            if let header = state.addressHeader {
                plaintext.append(header)
                state.addressHeader = nil
            }
            plaintext.append(data)
            return try state.writer.seal(plaintext: plaintext)
        }
        try await inner.sendRaw(encrypted)
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
            throw AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "invalid address header"))
        }
        return parsed.payload
    }

    func cancel() {
        inner.cancel()
    }
}
