//
//  Shadowsocks2022.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/7/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import os.log
import Security

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "SS2022")

// MARK: - Constants

private let headerTypeClient: UInt8 = 0
private let headerTypeServer: UInt8 = 1
private let maxPaddingLength = 900
private let maxTimestampDiff: Int64 = 30
private let tagSize = 16

// MARK: - Shadowsocks2022Connection (TCP)

/// Wraps a transport-layer ProxyConnection with Shadowsocks 2022 AEAD encryption.
///
/// Request format: salt + seal(fixedHeader) + seal(variableHeader+payload) [+ AEAD chunks]
/// Response format: salt + seal(fixedHeader) + seal(data) [+ AEAD chunks]
class Shadowsocks2022Connection: ProxyConnection {
    private let inner: ProxyConnection
    private let cipher: ShadowsocksCipher
    private let psk: Data
    private let pskList: [Data]       // all PSKs (for multi-user identity headers)
    private let pskHashes: [Data]     // BLAKE3 hash of pskList[1..], first 16 bytes each

    // Write state
    private var requestSalt: Data?
    private var writeNonce: ShadowsocksNonce
    private var writeSubkey: Data?
    private var handshakeSent = false

    // Read state
    private var readNonce: ShadowsocksNonce
    private var readSubkey: Data?
    private var readBuffer = Data()
    private var responseHeaderParsed = false
    private var pendingVarHeaderLen: Int? = nil    // set when fixed header parsed but variable header not yet available
    private var pendingPayloadLength: Int? = nil   // set when length chunk decoded but payload not yet available

    // Address header for first request
    private var addressHeader: Data?

    init(inner: ProxyConnection, cipher: ShadowsocksCipher, pskList: [Data], addressHeader: Data) {
        self.inner = inner
        self.cipher = cipher
        self.pskList = pskList
        self.psk = pskList.last!
        self.addressHeader = addressHeader

        // Precompute pskHashes: for each PSK at index 1+, first 16 bytes of BLAKE3 hash
        var hashes: [Data] = []
        for i in 1..<pskList.count {
            hashes.append(ShadowsocksKeyDerivation.blake3Hash16(pskList[i]))
        }
        self.pskHashes = hashes

        self.writeNonce = ShadowsocksNonce(size: cipher.nonceSize)
        self.readNonce = ShadowsocksNonce(size: cipher.nonceSize)
        super.init()
        self.responseHeaderReceived = true
    }

    override var isConnected: Bool { inner.isConnected }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            lock.lock()
            let needsHandshake = !handshakeSent
            let header = addressHeader
            if needsHandshake {
                handshakeSent = true
                addressHeader = nil
            }
            lock.unlock()

            if needsHandshake {
                let output = try buildRequest(payload: data, addressHeader: header!)
                inner.sendRaw(data: output, completion: completion)
            } else {
                let encrypted = try sealChunks(plaintext: data)
                inner.sendRaw(data: encrypted, completion: completion)
            }
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[SS2022] Send error: \(error.localizedDescription, privacy: .public)")
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
                let plaintext = try self.processReceived(data)
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

    // MARK: - Request Construction

    private func buildRequest(payload: Data, addressHeader: Data) throws -> Data {
        let keySize = cipher.keySize

        // Generate random salt
        var saltBytes = [UInt8](repeating: 0, count: keySize)
        _ = SecRandomCopyBytes(kSecRandomDefault, keySize, &saltBytes)
        let salt = Data(saltBytes)
        self.requestSalt = salt

        // Derive session key via BLAKE3
        let sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk: psk, salt: salt, keySize: keySize)
        self.writeSubkey = sessionKey

        var output = Data()
        output.append(salt)

        // Write extended identity headers for multi-user mode
        if pskList.count >= 2 {
            try writeIdentityHeaders(into: &output, salt: salt)
        }

        // Fixed header: type(1) + timestamp(8) + variableHeaderLen(2) = 11 bytes
        let paddingLen = payload.count < maxPaddingLength ? Int.random(in: 1...maxPaddingLength) : 0
        let variableHeaderLen = addressHeader.count + 2 + paddingLen + payload.count

        var fixedHeader = Data(capacity: 11)
        fixedHeader.append(headerTypeClient)
        var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
        fixedHeader.append(Data(bytes: &timestamp, count: 8))
        var varLenBE = UInt16(variableHeaderLen).bigEndian
        fixedHeader.append(Data(bytes: &varLenBE, count: 2))

        // Seal fixed header (one AEAD chunk)
        let nonce0 = writeNonce.next()
        let sealedFixed = try ShadowsocksAEADCrypto.seal(
            cipher: cipher, key: sessionKey, nonce: nonce0, plaintext: fixedHeader
        )
        output.append(sealedFixed)

        // Variable header: address + paddingLen(2) + padding + payload
        var variableHeader = Data(capacity: variableHeaderLen)
        variableHeader.append(addressHeader)
        var paddingLenBE = UInt16(paddingLen).bigEndian
        variableHeader.append(Data(bytes: &paddingLenBE, count: 2))
        if paddingLen > 0 {
            variableHeader.append(Data(repeating: 0, count: paddingLen))
        }
        variableHeader.append(payload)

        // Seal variable header (one AEAD chunk)
        let nonce1 = writeNonce.next()
        let sealedVariable = try ShadowsocksAEADCrypto.seal(
            cipher: cipher, key: sessionKey, nonce: nonce1, plaintext: variableHeader
        )
        output.append(sealedVariable)

        return output
    }

    /// Writes extended identity headers for multi-user mode.
    /// For each PSK from 0 to pskList.count-2:
    ///   identitySubkey = BLAKE3.DeriveKey("shadowsocks 2022 identity subkey", psk[i] + salt)
    ///   plaintext = blake3Hash16(psk[i+1])
    ///   header = AES-ECB(identitySubkey, plaintext)
    private func writeIdentityHeaders(into output: inout Data, salt: Data) throws {
        let keySize = cipher.keySize
        for i in 0..<(pskList.count - 1) {
            let identitySubkey = ShadowsocksKeyDerivation.deriveIdentitySubkey(
                psk: pskList[i], salt: salt, keySize: keySize
            )
            let pskHash = pskHashes[i]
            let encryptedHeader = try aesECBEncrypt(key: identitySubkey, block: pskHash)
            output.append(encryptedHeader)
        }
    }

    /// Encrypts data into standard AEAD chunks (for subsequent sends after handshake).
    private func sealChunks(plaintext: Data) throws -> Data {
        guard let subkey = writeSubkey else { throw ShadowsocksError.decryptionFailed }
        let maxPayload = ShadowsocksAEADWriter.maxPayloadSize
        var output = Data()
        var offset = 0

        while offset < plaintext.count {
            let remaining = plaintext.count - offset
            let chunkSize = min(remaining, maxPayload)
            let chunk = plaintext[plaintext.startIndex.advanced(by: offset)..<plaintext.startIndex.advanced(by: offset + chunkSize)]

            // Encrypted 2-byte length
            let lengthBytes = Data([UInt8(chunkSize >> 8), UInt8(chunkSize & 0xFF)])
            let encLen = try ShadowsocksAEADCrypto.seal(
                cipher: cipher, key: subkey, nonce: writeNonce.next(), plaintext: lengthBytes
            )
            output.append(encLen)

            // Encrypted payload
            let encPayload = try ShadowsocksAEADCrypto.seal(
                cipher: cipher, key: subkey, nonce: writeNonce.next(), plaintext: Data(chunk)
            )
            output.append(encPayload)

            offset += chunkSize
        }

        return output
    }

    // MARK: - Response Parsing

    private func processReceived(_ data: Data) throws -> Data {
        readBuffer.append(data)
        var output = Data()

        // Try to finish parsing the variable header if we're waiting for more data
        if let varLen = pendingVarHeaderLen {
            guard let parsed = try parseVariableHeader(varLen: varLen) else {
                return Data() // still need more data
            }
            output.append(parsed)
        }

        if !responseHeaderParsed {
            guard let parsed = try parseResponseHeader() else {
                return Data() // need more data
            }
            output.append(parsed)
        }

        // Only decrypt standard AEAD chunks after the full response header is parsed
        if responseHeaderParsed {
            let chunks = try decryptChunks()
            output.append(chunks)
        }

        return output
    }

    private func parseResponseHeader() throws -> Data? {
        let keySize = cipher.keySize

        // Need: salt(keySize) + sealed fixed header(1+8+keySize+2 + tagSize)
        let fixedHeaderPlainLen = 1 + 8 + keySize + 2
        let minNeeded = keySize + fixedHeaderPlainLen + tagSize
        guard readBuffer.count >= minNeeded else { return nil }

        // Read salt
        let salt = Data(readBuffer.prefix(keySize))
        readBuffer.removeFirst(keySize)

        // Derive read session key
        let sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk: psk, salt: salt, keySize: keySize)
        self.readSubkey = sessionKey

        // Read and decrypt fixed header chunk
        let fixedChunkLen = fixedHeaderPlainLen + tagSize
        guard readBuffer.count >= fixedChunkLen else {
            // Put salt back (shouldn't happen given our minNeeded check)
            readBuffer.insert(contentsOf: salt, at: readBuffer.startIndex)
            self.readSubkey = nil
            return nil
        }

        let fixedChunk = Data(readBuffer.prefix(fixedChunkLen))
        readBuffer.removeFirst(fixedChunkLen)

        let fixedHeader = try ShadowsocksAEADCrypto.open(
            cipher: cipher, key: sessionKey, nonce: readNonce.next(), ciphertext: fixedChunk
        )

        // Parse fixed header: type(1) + timestamp(8) + requestSalt(keySize) + length(2)
        guard fixedHeader.count == fixedHeaderPlainLen else {
            throw ShadowsocksError.decryptionFailed
        }

        var offset = fixedHeader.startIndex
        let headerType = fixedHeader[offset]
        offset += 1

        guard headerType == headerTypeServer else {
            throw ShadowsocksError.badHeaderType
        }

        // Validate timestamp
        var epochBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &epochBE) { ptr in
            fixedHeader[offset..<offset+8].copyBytes(to: ptr)
        }
        let epoch = Int64(UInt64(bigEndian: epochBE))
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > maxTimestampDiff {
            throw ShadowsocksError.badTimestamp
        }
        offset += 8

        // Validate request salt
        let responseSalt = Data(fixedHeader[offset..<offset+keySize])
        offset += keySize
        if let requestSalt, responseSalt != requestSalt {
            throw ShadowsocksError.badRequestSalt
        }

        // Read variable length
        let varLen = Int(UInt16(fixedHeader[offset]) << 8 | UInt16(fixedHeader[offset + 1]))

        // Try to read and decrypt variable header chunk
        if let varData = try parseVariableHeader(varLen: varLen) {
            return varData
        } else {
            // Not enough data for variable header yet — save state and wait
            return Data()
        }
    }

    /// Parses the variable-length response header chunk. Returns nil if not enough data yet.
    private func parseVariableHeader(varLen: Int) throws -> Data? {
        let varChunkLen = varLen + tagSize
        guard readBuffer.count >= varChunkLen else {
            // Save varLen so we can retry when more data arrives
            pendingVarHeaderLen = varLen
            return nil
        }

        let varChunk = Data(readBuffer.prefix(varChunkLen))
        readBuffer.removeFirst(varChunkLen)

        guard let subkey = readSubkey else {
            throw ShadowsocksError.decryptionFailed
        }

        let varData = try ShadowsocksAEADCrypto.open(
            cipher: cipher, key: subkey, nonce: readNonce.next(), ciphertext: varChunk
        )

        pendingVarHeaderLen = nil
        responseHeaderParsed = true
        return varData
    }

    /// Decrypts standard AEAD chunks from the read buffer.
    private func decryptChunks() throws -> Data {
        guard let subkey = readSubkey else { return Data() }
        var output = Data()

        while true {
            let payloadLen: Int

            if let pending = pendingPayloadLength {
                // We already decoded the length chunk in a previous call
                payloadLen = pending
            } else {
                // Need encrypted length: 2 + tagSize
                let lenNeeded = 2 + tagSize
                guard readBuffer.count >= lenNeeded else { break }

                let encLen = Data(readBuffer.prefix(lenNeeded))
                let lenData = try ShadowsocksAEADCrypto.open(
                    cipher: cipher, key: subkey, nonce: readNonce.next(), ciphertext: encLen
                )
                guard lenData.count == 2 else { throw ShadowsocksError.decryptionFailed }
                readBuffer.removeFirst(lenNeeded)

                payloadLen = Int(UInt16(lenData[lenData.startIndex]) << 8 | UInt16(lenData[lenData.startIndex + 1]))
            }

            let payloadNeeded = payloadLen + tagSize
            guard readBuffer.count >= payloadNeeded else {
                // Save state — length nonce already consumed, wait for payload data
                pendingPayloadLength = payloadLen
                break
            }

            pendingPayloadLength = nil

            let encPayload = Data(readBuffer.prefix(payloadNeeded))
            readBuffer.removeFirst(payloadNeeded)

            let payload = try ShadowsocksAEADCrypto.open(
                cipher: cipher, key: subkey, nonce: readNonce.next(), ciphertext: encPayload
            )
            output.append(payload)
        }

        return output
    }
}

// MARK: - Shadowsocks2022UDPConnection (AES variant)

/// Wraps a transport connection with Shadowsocks 2022 per-packet UDP encryption (AES variant).
///
/// Packet format (outgoing):
///   AES-ECB(sessionID(8) + packetID(8)) + AEAD(type + timestamp + paddingLen + padding + address + payload)
///   AEAD nonce = packetHeader[4:16]
///
/// Packet format (incoming):
///   AES-ECB(sessionID(8) + packetID(8)) + AEAD(type + timestamp + clientSessionID + paddingLen + padding + address + payload)
class Shadowsocks2022AESUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let cipher: ShadowsocksCipher
    private let psk: Data             // last PSK (for session key derivation)
    private let pskList: [Data]       // all PSKs
    private let pskHashes: [Data]     // BLAKE3 hash of pskList[1..], first 16 bytes each
    private let headerEncryptPSK: Data  // pskList[0] for AES-ECB header encryption
    private let dstHost: String
    private let dstPort: UInt16

    // Session state
    private let sessionID: UInt64
    private var packetID: UInt64 = 0
    private let sessionCipher: Data  // AEAD key derived from sessionID

    // Remote session tracking
    private var remoteSessionID: UInt64 = 0
    private var remoteSessionCipher: Data?

    init(inner: ProxyConnection, cipher: ShadowsocksCipher, pskList: [Data], dstHost: String, dstPort: UInt16) {
        self.inner = inner
        self.cipher = cipher
        self.pskList = pskList
        self.psk = pskList.last!
        self.headerEncryptPSK = pskList.first!
        self.dstHost = dstHost
        self.dstPort = dstPort

        // Precompute pskHashes
        var hashes: [Data] = []
        for i in 1..<pskList.count {
            hashes.append(ShadowsocksKeyDerivation.blake3Hash16(pskList[i]))
        }
        self.pskHashes = hashes

        // Generate random session ID
        var sid: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &sid) { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
        }
        self.sessionID = sid

        // Derive per-session AEAD key from SessionKey(lastPSK, sessionID_bytes, keySize)
        var sidBE = sid.bigEndian
        let sidData = Data(bytes: &sidBE, count: 8)
        self.sessionCipher = ShadowsocksKeyDerivation.deriveSessionKey(psk: pskList.last!, salt: sidData, keySize: cipher.keySize)

        super.init()
        self.responseHeaderReceived = true
    }

    override var isConnected: Bool { inner.isConnected }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            let encrypted = try encryptPacket(payload: data)
            inner.sendRaw(data: encrypted, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[SS2022-UDP] Send error: \(error.localizedDescription, privacy: .public)")
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
                let payload = try self.decryptPacket(data)
                completion(payload, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    override func cancel() {
        inner.cancel()
    }

    private func encryptPacket(payload: Data) throws -> Data {
        // Build packet header: sessionID(8) + packetID(8) = 16 bytes
        packetID += 1
        var header = Data(capacity: 16)
        var sidBE = sessionID.bigEndian
        header.append(Data(bytes: &sidBE, count: 8))
        var pidBE = packetID.bigEndian
        header.append(Data(bytes: &pidBE, count: 8))

        // Build identity headers for multi-user mode
        var identityData = Data()
        if pskList.count >= 2 {
            for i in 0..<(pskList.count - 1) {
                // identityHeader = AES-ECB(psk[i], pskHash[i] XOR header[0:16])
                var xored = Data(count: 16)
                let pskHash = pskHashes[i]
                for j in 0..<16 {
                    xored[j] = pskHash[j] ^ header[j]
                }
                let encrypted = try aesECBEncrypt(key: pskList[i], block: xored)
                identityData.append(encrypted)
            }
        }

        // Build body: type(1) + timestamp(8) + paddingLen(2) + padding + address + payload
        let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: dstHost, port: dstPort)
        let paddingLen = (dstPort == 53 && payload.count < maxPaddingLength)
            ? Int.random(in: 1...(maxPaddingLength - payload.count))
            : 0

        var body = Data()
        body.append(headerTypeClient)
        var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
        body.append(Data(bytes: &timestamp, count: 8))
        var paddingLenBE = UInt16(paddingLen).bigEndian
        body.append(Data(bytes: &paddingLenBE, count: 2))
        if paddingLen > 0 {
            body.append(Data(repeating: 0, count: paddingLen))
        }
        body.append(addressHeader)
        body.append(payload)

        // AEAD seal body: nonce = header[4:16] (last 12 bytes of header)
        let nonce = Data(header[4..<16])
        let sealedBody = try ShadowsocksAEADCrypto.seal(
            cipher: cipher, key: sessionCipher, nonce: nonce, plaintext: body
        )

        // AES-ECB encrypt the 16-byte header using first PSK
        let encryptedHeader = try aesECBEncrypt(key: headerEncryptPSK, block: header)

        var packet = Data()
        packet.append(encryptedHeader)
        packet.append(identityData)
        packet.append(sealedBody)
        return packet
    }

    private func decryptPacket(_ data: Data) throws -> Data {
        guard data.count >= 16 + tagSize else {
            throw ShadowsocksError.decryptionFailed
        }

        // AES-ECB decrypt the 16-byte header using last PSK (server sends encrypted with user PSK)
        let encryptedHeader = Data(data.prefix(16))
        let header = try aesECBDecrypt(key: psk, block: encryptedHeader)

        // Parse sessionID + packetID
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

        // AEAD open body: nonce = header[4:16]
        let nonce = Data(header[4..<16])
        let sealedBody = Data(data.suffix(from: data.startIndex + 16))
        let body = try ShadowsocksAEADCrypto.open(
            cipher: cipher, key: remoteCipherKey, nonce: nonce, ciphertext: sealedBody
        )

        // Parse body: type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + address + payload
        guard body.count >= 1 + 8 + 8 + 2 else {
            throw ShadowsocksError.decryptionFailed
        }

        var offset = body.startIndex
        let headerType = body[offset]
        offset += 1

        guard headerType == headerTypeServer else {
            throw ShadowsocksError.badHeaderType
        }

        // Validate timestamp
        var epochBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &epochBE) { ptr in
            body[offset..<offset+8].copyBytes(to: ptr)
        }
        let epoch = Int64(UInt64(bigEndian: epochBE))
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > maxTimestampDiff {
            throw ShadowsocksError.badTimestamp
        }
        offset += 8

        // Client session ID (must match ours)
        var clientSidBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &clientSidBE) { ptr in
            body[offset..<offset+8].copyBytes(to: ptr)
        }
        let clientSid = UInt64(bigEndian: clientSidBE)
        guard clientSid == sessionID else {
            throw ShadowsocksError.decryptionFailed
        }
        offset += 8

        // Padding
        guard body.endIndex - offset >= 2 else { throw ShadowsocksError.decryptionFailed }
        let paddingLen = Int(UInt16(body[offset]) << 8 | UInt16(body[offset + 1]))
        offset += 2
        offset += paddingLen

        // Skip address header
        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: Data(body[offset...])) else {
            throw ShadowsocksError.invalidAddress
        }

        return parsed.payload
    }
}

// MARK: - Shadowsocks2022ChaChaUDPConnection

/// Wraps a transport connection with Shadowsocks 2022 per-packet UDP encryption (ChaCha20 variant).
///
/// Uses XChaCha20-Poly1305 with 24-byte nonce.
/// Packet format: nonce(24) + XChaCha20-Poly1305(sessionID + packetID + type + timestamp + padding + address + payload)
class Shadowsocks2022ChaChaUDPConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let psk: Data
    private let dstHost: String
    private let dstPort: UInt16

    // Session state
    private let sessionID: UInt64
    private var packetID: UInt64 = 0

    init(inner: ProxyConnection, psk: Data, dstHost: String, dstPort: UInt16) {
        self.inner = inner
        self.psk = psk
        self.dstHost = dstHost
        self.dstPort = dstPort

        // Generate random session ID
        var sid: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &sid) { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
        }
        self.sessionID = sid
        super.init()
        self.responseHeaderReceived = true
    }

    override var isConnected: Bool { inner.isConnected }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            let encrypted = try encryptPacket(payload: data)
            inner.sendRaw(data: encrypted, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[SS2022-ChaCha-UDP] Send error: \(error.localizedDescription, privacy: .public)")
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
                let payload = try self.decryptPacket(data)
                completion(payload, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    override func cancel() {
        inner.cancel()
    }

    private func encryptPacket(payload: Data) throws -> Data {
        // Generate 24-byte nonce
        var nonceBytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, 24, &nonceBytes)
        let nonce = Data(nonceBytes)

        // Build body: sessionID(8) + packetID(8) + type(1) + timestamp(8) + paddingLen(2) + padding + address + payload
        let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: dstHost, port: dstPort)
        let paddingLen = (dstPort == 53 && payload.count < maxPaddingLength)
            ? Int.random(in: 1...(maxPaddingLength - payload.count))
            : 0

        packetID += 1
        var body = Data()
        var sidBE = sessionID.bigEndian
        body.append(Data(bytes: &sidBE, count: 8))
        var pidBE = packetID.bigEndian
        body.append(Data(bytes: &pidBE, count: 8))
        body.append(headerTypeClient)
        var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
        body.append(Data(bytes: &timestamp, count: 8))
        var paddingLenBE = UInt16(paddingLen).bigEndian
        body.append(Data(bytes: &paddingLenBE, count: 2))
        if paddingLen > 0 {
            body.append(Data(repeating: 0, count: paddingLen))
        }
        body.append(addressHeader)
        body.append(payload)

        // XChaCha20-Poly1305 seal
        let sealed = try XChaCha20Poly1305.seal(key: psk, nonce: nonce, plaintext: body)

        var packet = Data()
        packet.append(nonce)
        packet.append(sealed)
        return packet
    }

    private func decryptPacket(_ data: Data) throws -> Data {
        guard data.count >= 24 + tagSize else {
            throw ShadowsocksError.decryptionFailed
        }

        let nonce = Data(data.prefix(24))
        let ciphertext = Data(data.suffix(from: data.startIndex + 24))

        let body = try XChaCha20Poly1305.open(key: psk, nonce: nonce, ciphertext: ciphertext)

        // Parse: sessionID(8) + packetID(8) + type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + address + payload
        guard body.count >= 8 + 8 + 1 + 8 + 8 + 2 else {
            throw ShadowsocksError.decryptionFailed
        }

        var offset = body.startIndex
        offset += 8 // skip sessionID
        offset += 8 // skip packetID

        let headerType = body[offset]
        offset += 1
        guard headerType == headerTypeServer else {
            throw ShadowsocksError.badHeaderType
        }

        // Validate timestamp
        var epochBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &epochBE) { ptr in
            body[offset..<offset+8].copyBytes(to: ptr)
        }
        let epoch = Int64(UInt64(bigEndian: epochBE))
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > maxTimestampDiff {
            throw ShadowsocksError.badTimestamp
        }
        offset += 8

        // Client session ID
        var clientSidBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &clientSidBE) { ptr in
            body[offset..<offset+8].copyBytes(to: ptr)
        }
        let clientSid = UInt64(bigEndian: clientSidBE)
        guard clientSid == sessionID else {
            throw ShadowsocksError.decryptionFailed
        }
        offset += 8

        // Padding
        guard body.endIndex - offset >= 2 else { throw ShadowsocksError.decryptionFailed }
        let paddingLen = Int(UInt16(body[offset]) << 8 | UInt16(body[offset + 1]))
        offset += 2
        offset += paddingLen

        // Skip address header
        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: Data(body[offset...])) else {
            throw ShadowsocksError.invalidAddress
        }

        return parsed.payload
    }
}

// MARK: - AES-ECB Single Block

private func aesECBEncrypt(key: Data, block: Data) throws -> Data {
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
                nil, // no IV for ECB
                blockPtr.baseAddress!, 16,
                &outBytes, outBytes.count,
                &outLen
            )
        }
    }
    guard status == kCCSuccess else { throw ShadowsocksError.decryptionFailed }
    return Data(outBytes.prefix(16))
}

private func aesECBDecrypt(key: Data, block: Data) throws -> Data {
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

// MARK: - XChaCha20-Poly1305

/// XChaCha20-Poly1305 implementation using HChaCha20 + ChaChaPoly.
enum XChaCha20Poly1305 {

    static func seal(key: Data, nonce: Data, plaintext: Data) throws -> Data {
        guard nonce.count == 24, key.count == 32 else {
            throw ShadowsocksError.decryptionFailed
        }

        // HChaCha20: derive subkey from key + nonce[0:16]
        let subkey = hChaCha20(key: key, nonce: Data(nonce.prefix(16)))

        // Standard ChaCha20-Poly1305 with subkey and nonce = [0,0,0,0] + nonce[16:24]
        var chachaNonce = Data(repeating: 0, count: 4)
        chachaNonce.append(nonce[nonce.startIndex + 16..<nonce.startIndex + 24])

        let symmetricKey = SymmetricKey(data: subkey)
        let nonceObj = try ChaChaPoly.Nonce(data: chachaNonce)
        let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: nonceObj)
        return sealed.ciphertext + sealed.tag
    }

    static func open(key: Data, nonce: Data, ciphertext: Data) throws -> Data {
        guard nonce.count == 24, key.count == 32 else {
            throw ShadowsocksError.decryptionFailed
        }
        guard ciphertext.count >= 16 else {
            throw ShadowsocksError.decryptionFailed
        }

        let subkey = hChaCha20(key: key, nonce: Data(nonce.prefix(16)))

        var chachaNonce = Data(repeating: 0, count: 4)
        chachaNonce.append(nonce[nonce.startIndex + 16..<nonce.startIndex + 24])

        let symmetricKey = SymmetricKey(data: subkey)
        let nonceObj = try ChaChaPoly.Nonce(data: chachaNonce)
        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)
        let box = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
        return try ChaChaPoly.open(box, using: symmetricKey)
    }

    /// HChaCha20: derives a 256-bit subkey from a 256-bit key and 128-bit nonce.
    private static func hChaCha20(key: Data, nonce: Data) -> Data {
        // Initial state (same as ChaCha20)
        var state: [UInt32] = Array(repeating: 0, count: 16)

        // Constants: "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574

        // Key (little-endian)
        key.withUnsafeBytes { ptr in
            for i in 0..<8 {
                state[4 + i] = ptr.load(fromByteOffset: i * 4, as: UInt32.self).littleEndian
            }
        }

        // Nonce (little-endian)
        nonce.withUnsafeBytes { ptr in
            for i in 0..<4 {
                state[12 + i] = ptr.load(fromByteOffset: i * 4, as: UInt32.self).littleEndian
            }
        }

        // 20 rounds (10 double rounds)
        for _ in 0..<10 {
            // Column rounds
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 1, 5, 9, 13)
            quarterRound(&state, 2, 6, 10, 14)
            quarterRound(&state, 3, 7, 11, 15)
            // Diagonal rounds
            quarterRound(&state, 0, 5, 10, 15)
            quarterRound(&state, 1, 6, 11, 12)
            quarterRound(&state, 2, 7, 8, 13)
            quarterRound(&state, 3, 4, 9, 14)
        }

        // Output: words 0..3 and 12..15 (8 words = 32 bytes)
        var output = Data(capacity: 32)
        for i in [0, 1, 2, 3, 12, 13, 14, 15] {
            var word = state[i].littleEndian
            output.append(Data(bytes: &word, count: 4))
        }
        return output
    }

    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] = s[a] &+ s[b]; s[d] = (s[d] ^ s[a]).rotatedLeft(by: 16)
        s[c] = s[c] &+ s[d]; s[b] = (s[b] ^ s[c]).rotatedLeft(by: 12)
        s[a] = s[a] &+ s[b]; s[d] = (s[d] ^ s[a]).rotatedLeft(by: 8)
        s[c] = s[c] &+ s[d]; s[b] = (s[b] ^ s[c]).rotatedLeft(by: 7)
    }
}

private extension UInt32 {
    func rotatedLeft(by count: Int) -> UInt32 {
        return (self << count) | (self >> (32 - count))
    }
}
