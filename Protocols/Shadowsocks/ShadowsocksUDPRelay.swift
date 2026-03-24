//
//  ShadowsocksUDPRelay.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/7/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Network
import os.log
import Security

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "SS-UDP-Relay")

// MARK: - ShadowsocksUDPRelay

/// Direct UDP relay with Shadowsocks per-packet encryption.
///
/// Creates a UDP connection directly to the SS server and handles per-packet
/// encryption/decryption. Supports both legacy SS and SS 2022 formats.
///
/// Unlike the TCP-based ``ShadowsocksUDPConnection``, this class sends
/// actual UDP datagrams to the SS server, matching the server's UDP handler.
class ShadowsocksUDPRelay {

    enum Mode {
        /// Legacy SS: salt + AEAD_seal(address + payload)
        case legacy(cipher: ShadowsocksCipher, masterKey: Data)
        /// SS 2022 AES variant: AES-ECB header + per-session AEAD
        case ss2022AES(cipher: ShadowsocksCipher, psk: Data)
        /// SS 2022 ChaCha20 variant: XChaCha20-Poly1305
        case ss2022ChaCha(psk: Data)
    }

    private let mode: Mode
    private let dstHost: String
    private let dstPort: UInt16

    // UDP connection
    private var connection: NWConnection?
    private var cancelled = false

    // SS 2022 AES session state
    private var sessionID: UInt64 = 0
    private var packetID: UInt64 = 0
    private var sessionCipher: Data?         // AEAD key for outgoing packets
    private var remoteSessionID: UInt64 = 0
    private var remoteSessionCipher: Data?   // AEAD key for incoming packets

    init(mode: Mode, dstHost: String, dstPort: UInt16) {
        self.mode = mode
        self.dstHost = dstHost
        self.dstPort = dstPort

        // Initialize SS 2022 session if needed
        switch mode {
        case .ss2022AES(let cipher, let psk):
            var sid: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &sid) { ptr in
                SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
            }
            sessionID = sid
            var sidBE = sid.bigEndian
            let sidData = Data(bytes: &sidBE, count: 8)
            sessionCipher = ShadowsocksKeyDerivation.deriveSessionKey(psk: psk, salt: sidData, keySize: cipher.keySize)

        case .ss2022ChaCha:
            var sid: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &sid) { ptr in
                SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
            }
            sessionID = sid

        case .legacy:
            break
        }
    }

    /// Connects the UDP connection to the Shadowsocks server.
    func connect(serverHost: String, serverPort: UInt16, lwipQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        // Resolve via proxy DNS cache (shared with NWTransport/TCP connections)
        let resolvedHost = ProxyDNSCache.shared.resolveHost(serverHost) ?? serverHost

        let host = NWEndpoint.Host(resolvedHost)
        guard let port = NWEndpoint.Port(rawValue: serverPort) else {
            lwipQueue.async { completion(SocketError.connectionFailed("Invalid port")) }
            return
        }

        let connection = NWConnection(host: host, port: port, using: .udp)
        self.connection = connection

        var completed = false
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.cancelled, !completed else { return }
            switch state {
            case .ready:
                completed = true
                connection.stateUpdateHandler = nil
                lwipQueue.async { completion(nil) }
            case .failed(let error):
                completed = true
                connection.stateUpdateHandler = nil
                self.connection = nil
                lwipQueue.async { completion(SocketError.connectionFailed(error.localizedDescription)) }
            default:
                break
            }
        }

        connection.start(queue: .global())
    }

    /// Encrypts and sends a UDP payload to the SS server.
    func send(data: Data) {
        guard let connection, !cancelled else { return }
        do {
            let encrypted = try encryptPacket(payload: data)
            connection.send(content: encrypted, completion: .contentProcessed({ _ in }))
        } catch {
            logger.error("[SS-UDP] Encrypt error: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Starts receiving and decrypting datagrams asynchronously.
    func startReceiving(handler: @escaping (Data) -> Void) {
        guard let connection, !cancelled else { return }
        receiveNext(connection: connection, handler: handler)
    }

    private func receiveNext(connection: NWConnection, handler: @escaping (Data) -> Void) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, !data.isEmpty {
                do {
                    let payload = try self.decryptPacket(data)
                    handler(payload)
                } catch {
                    logger.error("[SS-UDP] Decrypt error: \(error.localizedDescription, privacy: .public)")
                }
            }
            // UDP doesn't have EOF, continue receiving
            if error == nil {
                self.receiveNext(connection: connection, handler: handler)
            }
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        connection?.forceCancel()
        connection = nil
    }

    // MARK: - Packet Encryption

    private func encryptPacket(payload: Data) throws -> Data {
        let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: dstHost, port: dstPort)

        switch mode {
        case .legacy(let cipher, let masterKey):
            let packet = ShadowsocksProtocol.encodeUDPPacket(host: dstHost, port: dstPort, payload: payload)
            return try ShadowsocksUDPCrypto.encrypt(cipher: cipher, masterKey: masterKey, payload: packet)

        case .ss2022AES(let cipher, let psk):
            guard let sessionKey = sessionCipher else { throw ShadowsocksError.decryptionFailed }

            packetID += 1
            // Header: sessionID(8) + packetID(8)
            var header = Data(capacity: 16)
            var sidBE = sessionID.bigEndian
            header.append(Data(bytes: &sidBE, count: 8))
            var pidBE = packetID.bigEndian
            header.append(Data(bytes: &pidBE, count: 8))

            // Body: type(0) + timestamp(8) + paddingLen(2) + padding + address + payload
            let paddingLen = (dstPort == 53 && payload.count < 900)
                ? Int.random(in: 1...(900 - payload.count))
                : 0

            var body = Data()
            body.append(0) // HeaderTypeClient
            var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
            body.append(Data(bytes: &timestamp, count: 8))
            var paddingLenBE = UInt16(paddingLen).bigEndian
            body.append(Data(bytes: &paddingLenBE, count: 2))
            if paddingLen > 0 {
                body.append(Data(repeating: 0, count: paddingLen))
            }
            body.append(addressHeader)
            body.append(payload)

            // AEAD seal: nonce = header[4:16]
            let nonce = Data(header[4..<16])
            let sealedBody = try ShadowsocksAEADCrypto.seal(
                cipher: cipher, key: sessionKey, nonce: nonce, plaintext: body
            )

            // AES-ECB encrypt header
            let encryptedHeader = try ssAESECBEncrypt(key: psk, block: header)

            var packet = Data()
            packet.append(encryptedHeader)
            packet.append(sealedBody)
            return packet

        case .ss2022ChaCha(let psk):
            packetID += 1
            // 24-byte random nonce
            var nonceBytes = [UInt8](repeating: 0, count: 24)
            _ = SecRandomCopyBytes(kSecRandomDefault, 24, &nonceBytes)
            let nonce = Data(nonceBytes)

            // Body: sessionID(8) + packetID(8) + type(0) + timestamp(8) + paddingLen(2) + padding + address + payload
            let paddingLen = (dstPort == 53 && payload.count < 900)
                ? Int.random(in: 1...(900 - payload.count))
                : 0

            var body = Data()
            var sidBE = sessionID.bigEndian
            body.append(Data(bytes: &sidBE, count: 8))
            var pidBE = packetID.bigEndian
            body.append(Data(bytes: &pidBE, count: 8))
            body.append(0) // HeaderTypeClient
            var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
            body.append(Data(bytes: &timestamp, count: 8))
            var paddingLenBE = UInt16(paddingLen).bigEndian
            body.append(Data(bytes: &paddingLenBE, count: 2))
            if paddingLen > 0 {
                body.append(Data(repeating: 0, count: paddingLen))
            }
            body.append(addressHeader)
            body.append(payload)

            let sealed = try XChaCha20Poly1305.seal(key: psk, nonce: nonce, plaintext: body)

            var packet = Data()
            packet.append(nonce)
            packet.append(sealed)
            return packet
        }
    }

    // MARK: - Packet Decryption

    private func decryptPacket(_ data: Data) throws -> Data {
        switch mode {
        case .legacy(let cipher, let masterKey):
            let decrypted = try ShadowsocksUDPCrypto.decrypt(cipher: cipher, masterKey: masterKey, data: data)
            guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: decrypted) else {
                throw ShadowsocksError.invalidAddress
            }
            return parsed.payload

        case .ss2022AES(let cipher, let psk):
            guard data.count >= 16 + 16 else { throw ShadowsocksError.decryptionFailed }

            // AES-ECB decrypt header
            let header = try ssAESECBDecrypt(key: psk, block: Data(data.prefix(16)))

            // Parse sessionID
            var sidBE: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &sidBE) { ptr in
                header[0..<8].copyBytes(to: ptr)
            }
            let remoteSession = UInt64(bigEndian: sidBE)

            // Get or derive remote session cipher
            let remoteCipherKey: Data
            if remoteSession == remoteSessionID, let cached = remoteSessionCipher {
                remoteCipherKey = cached
            } else {
                var rsBE = remoteSession.bigEndian
                let rsData = Data(bytes: &rsBE, count: 8)
                remoteCipherKey = ShadowsocksKeyDerivation.deriveSessionKey(psk: psk, salt: rsData, keySize: cipher.keySize)
                remoteSessionID = remoteSession
                remoteSessionCipher = remoteCipherKey
            }

            // AEAD open: nonce = header[4:16]
            let nonce = Data(header[4..<16])
            let sealedBody = Data(data.suffix(from: data.startIndex + 16))
            let body = try ShadowsocksAEADCrypto.open(
                cipher: cipher, key: remoteCipherKey, nonce: nonce, ciphertext: sealedBody
            )

            return try parseServerUDPBody(body, withClientSessionID: true)

        case .ss2022ChaCha(let psk):
            guard data.count >= 24 + 16 else { throw ShadowsocksError.decryptionFailed }

            let nonce = Data(data.prefix(24))
            let ciphertext = Data(data.suffix(from: data.startIndex + 24))
            let body = try XChaCha20Poly1305.open(key: psk, nonce: nonce, ciphertext: ciphertext)

            // Body: sessionID(8) + packetID(8) + type + timestamp + clientSessionID + paddingLen + padding + address + payload
            guard body.count >= 8 + 8 else { throw ShadowsocksError.decryptionFailed }
            // Skip sessionID + packetID
            let innerBody = Data(body.suffix(from: body.startIndex + 16))
            return try parseServerUDPBody(innerBody, withClientSessionID: true)
        }
    }

    /// Parses a decrypted SS 2022 server UDP body:
    /// type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + address + payload
    private func parseServerUDPBody(_ body: Data, withClientSessionID: Bool) throws -> Data {
        guard body.count >= 1 + 8 + (withClientSessionID ? 8 : 0) + 2 else {
            throw ShadowsocksError.decryptionFailed
        }

        var offset = body.startIndex
        let headerType = body[offset]
        offset += 1
        guard headerType == 1 else { throw ShadowsocksError.badHeaderType }

        // Validate timestamp
        var epochBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &epochBE) { ptr in
            body[offset..<offset+8].copyBytes(to: ptr)
        }
        let epoch = Int64(UInt64(bigEndian: epochBE))
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > 30 {
            throw ShadowsocksError.badTimestamp
        }
        offset += 8

        if withClientSessionID {
            var clientSidBE: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &clientSidBE) { ptr in
                body[offset..<offset+8].copyBytes(to: ptr)
            }
            let clientSid = UInt64(bigEndian: clientSidBE)
            guard clientSid == sessionID else {
                throw ShadowsocksError.decryptionFailed
            }
            offset += 8
        }

        // Padding
        guard body.endIndex - offset >= 2 else { throw ShadowsocksError.decryptionFailed }
        let paddingLen = Int(UInt16(body[offset]) << 8 | UInt16(body[offset + 1]))
        offset += 2
        offset += paddingLen

        // Parse address header + payload
        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: Data(body[offset...])) else {
            throw ShadowsocksError.invalidAddress
        }
        return parsed.payload
    }
}

// MARK: - AES-ECB Helpers (module-internal)

private func ssAESECBEncrypt(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else { throw ShadowsocksError.decryptionFailed }
    var outBytes = [UInt8](repeating: 0, count: 16 + kCCBlockSizeAES128)
    var outLen: Int = 0
    let status = key.withUnsafeBytes { keyPtr in
        block.withUnsafeBytes { blockPtr in
            CCCrypt(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyPtr.baseAddress!, key.count,
                nil,
                blockPtr.baseAddress!, 16,
                &outBytes, outBytes.count,
                &outLen
            )
        }
    }
    guard status == kCCSuccess else { throw ShadowsocksError.decryptionFailed }
    return Data(outBytes.prefix(16))
}

private func ssAESECBDecrypt(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else { throw ShadowsocksError.decryptionFailed }
    var outBytes = [UInt8](repeating: 0, count: 16 + kCCBlockSizeAES128)
    var outLen: Int = 0
    let status = key.withUnsafeBytes { keyPtr in
        block.withUnsafeBytes { blockPtr in
            CCCrypt(
                CCOperation(kCCDecrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyPtr.baseAddress!, key.count,
                nil,
                blockPtr.baseAddress!, 16,
                &outBytes, outBytes.count,
                &outLen
            )
        }
    }
    guard status == kCCSuccess else { throw ShadowsocksError.decryptionFailed }
    return Data(outBytes.prefix(16))
}
