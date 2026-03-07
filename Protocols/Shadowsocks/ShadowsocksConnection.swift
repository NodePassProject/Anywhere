//
//  ShadowsocksConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/6/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "Shadowsocks")

// MARK: - ShadowsocksConnection

/// Wraps a transport-layer ProxyConnection with Shadowsocks AEAD encryption.
///
/// The address header is prepended to the first `send()` call's data
/// (encrypted as part of the stream, not a separate message).
/// Shadowsocks has no response header, so `responseHeaderReceived` starts as `true`.
class ShadowsocksConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let writer: ShadowsocksAEADWriter
    private let reader: ShadowsocksAEADReader
    private var addressHeader: Data?

    init(inner: ProxyConnection, cipher: ShadowsocksCipher, masterKey: Data, addressHeader: Data) {
        self.inner = inner
        self.writer = ShadowsocksAEADWriter(cipher: cipher, masterKey: masterKey)
        self.reader = ShadowsocksAEADReader(cipher: cipher, masterKey: masterKey)
        self.addressHeader = addressHeader
        super.init()
        self.responseHeaderReceived = true
    }

    override var isConnected: Bool { inner.isConnected }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            var plaintext = Data()
            // Prepend address header to first send
            lock.lock()
            if let header = addressHeader {
                plaintext.append(header)
                addressHeader = nil
            }
            lock.unlock()
            plaintext.append(data)

            let encrypted = try writer.seal(plaintext: plaintext)
            inner.sendRaw(data: encrypted, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[SS] Send error: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
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

            do {
                let plaintext = try self.reader.open(ciphertext: data)
                if plaintext.isEmpty {
                    self.receiveRaw(completion: completion)
                } else {
                    completion(plaintext, nil)
                }
            } catch {
                completion(nil, error)
            }
        }
    }

    override func cancel() {
        inner.cancel()
    }
}

// MARK: - ShadowsocksUDPConnection

/// Wraps a transport-layer ProxyConnection with Shadowsocks per-packet UDP encryption.
class ShadowsocksUDPConnection: ProxyConnection {
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
        super.init()
        self.responseHeaderReceived = true
    }

    override var isConnected: Bool { inner.isConnected }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            let packet = ShadowsocksProtocol.encodeUDPPacket(host: dstHost, port: dstPort, payload: data)
            let encrypted = try ShadowsocksUDPCrypto.encrypt(cipher: cipher, masterKey: masterKey, payload: packet)
            inner.sendRaw(data: encrypted, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[SS-UDP] Send error: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
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

            do {
                let decrypted = try ShadowsocksUDPCrypto.decrypt(cipher: self.cipher, masterKey: self.masterKey, data: data)
                guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: decrypted) else {
                    completion(nil, ShadowsocksError.invalidAddress)
                    return
                }
                completion(parsed.payload, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    override func cancel() {
        inner.cancel()
    }
}
