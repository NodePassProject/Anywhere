//
//  RealityClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import CryptoKit
import Security
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "Reality")

// MARK: - RealityClient

/// Client for establishing authenticated Reality connections over TLS 1.3.
///
/// Performs a TLS 1.3 handshake with Reality-specific extensions:
/// - Embeds authentication metadata in the ClientHello SessionId (AES-GCM encrypted).
/// - Uses X25519 ECDH with the server's public key for mutual authentication.
/// - Derives application-layer encryption keys from the TLS 1.3 handshake transcript.
///
/// After a successful handshake, returns a ``TLSRecordConnection`` that wraps
/// the underlying ``BSDSocket`` with TLS record encryption/decryption.
class RealityClient {
    private let configuration: RealityConfiguration
    private var connection: BSDSocket?

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var authKey: Data?
    private var storedClientHello: Data?

    // TLS 1.3 session state (cleared after handshake)
    private var keyDerivation: TLS13KeyDerivation?
    private var handshakeSecret: Data?
    private var handshakeKeys: TLSHandshakeKeys?
    private var applicationKeys: TLSApplicationKeys?
    private var handshakeTranscript: Data?
    private var serverHandshakeSeqNum: UInt64 = 0

    // MARK: Initialization

    /// Creates a new Reality client with the given configuration.
    ///
    /// - Parameter configuration: The Reality server configuration (public key, shortId, SNI).
    init(configuration: RealityConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API

    /// Connects to a Reality server and performs the TLS handshake.
    ///
    /// - Parameters:
    ///   - host: The server hostname or IP address.
    ///   - port: The server port number.
    ///   - completion: Called with the established ``TLSRecordConnection`` or an error.
    func connect(
        host: String,
        port: UInt16,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let socket = BSDSocket()
        self.connection = socket

        socket.connect(host: host, port: port, queue: .global()) { [weak self] error in
            if let error {
                logger.error("[Reality] TCP connection failed: \(error.localizedDescription, privacy: .public)")
                completion(.failure(RealityError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(RealityError.connectionFailed("Client deallocated")))
                return
            }

            self.performRealityHandshake(completion: completion)
        }
    }

    /// Cancels the connection and releases all resources.
    func cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = nil
    }

    // MARK: - Handshake

    /// Performs the Reality TLS handshake: sends ClientHello, processes ServerHello,
    /// derives encryption keys, and sends Client Finished.
    private func performRealityHandshake(
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let privateKey = ephemeralPrivateKey else {
            logger.error("[Reality] No ephemeral key for handshake")
            completion(.failure(RealityError.handshakeFailed("No ephemeral key")))
            return
        }

        do {
            let clientHello = try buildRealityClientHello(privateKey: privateKey)

            // Store for TLS transcript (without 5-byte TLS record header)
            storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

            guard let connection else {
                completion(.failure(RealityError.connectionFailed("Connection cancelled")))
                return
            }
            connection.send(data: clientHello) { [weak self] error in
                guard let self else { return }

                if let error {
                    logger.error("[Reality] Failed to send ClientHello: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                    return
                }

                self.receiveServerResponse(completion: completion)
            }
        } catch {
            logger.error("[Reality] Failed to build ClientHello: \(error.localizedDescription, privacy: .public)")
            completion(.failure(error))
        }
    }

    // MARK: - ClientHello

    /// Builds a TLS ClientHello with Reality authentication metadata.
    ///
    /// Embeds version, timestamp, and shortId in the SessionId field,
    /// encrypted with AES-GCM using a key derived from ECDH with the server.
    ///
    /// - Parameter privateKey: The ephemeral X25519 private key for this connection.
    /// - Returns: A complete TLS record containing the ClientHello.
    private func buildRealityClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        _ = random.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        // Build SessionId with Reality metadata in first 16 bytes
        var sessionId = Data(count: 32)
        sessionId[0] = 26  // Xray-core version 26.1.18
        sessionId[1] = 1
        sessionId[2] = 18
        sessionId[3] = 0

        let timestamp = UInt32(Date().timeIntervalSince1970)
        sessionId[4] = UInt8((timestamp >> 24) & 0xFF)
        sessionId[5] = UInt8((timestamp >> 16) & 0xFF)
        sessionId[6] = UInt8((timestamp >> 8) & 0xFF)
        sessionId[7] = UInt8(timestamp & 0xFF)

        let shortIdLen = min(configuration.shortId.count, 8)
        for i in 0..<shortIdLen {
            sessionId[8 + i] = configuration.shortId[i]
        }

        // ECDH with server's public key to derive auth key
        let serverPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: configuration.publicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)

        let salt = random.prefix(20)
        let info = "REALITY".data(using: .utf8)!
        authKey = deriveKey(sharedSecret: sharedSecret, salt: salt, info: info, outputLength: 32)

        guard let authKey else {
            throw RealityError.handshakeFailed("Failed to derive auth key")
        }

        // Build ClientHello with zero SessionId for AAD (matching Xray-core)
        let zeroSessionId = Data(count: 32)
        let rawClientHelloForAAD = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: zeroSessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation
        )

        // Encrypt first 16 bytes of SessionId using AES-GCM
        let nonce = random.suffix(12)
        let plaintext = sessionId.prefix(16)

        let encryptedSessionId = try TLSRecordCrypto.encryptAESGCM(
            plaintext: Data(plaintext),
            key: authKey,
            nonce: Data(nonce),
            aad: rawClientHelloForAAD
        )

        // Build final ClientHello with encrypted sessionId
        let finalClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: encryptedSessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation
        )

        return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: finalClientHello)
    }

    // MARK: - Server Response Processing

    /// Receives and processes the server's TLS response.
    private func receiveServerResponse(
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let connection else {
            completion(.failure(RealityError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive(maximumLength: 65536) { [weak self] data, _, error in
            guard let self else { return }

            if let error {
                logger.error("[Reality] Error receiving server response: \(error.localizedDescription, privacy: .public)")
                completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let data, data.count >= 5 else {
                logger.error("[Reality] No server response or too short")
                completion(.failure(RealityError.handshakeFailed("No server response")))
                return
            }

            let contentType = data[0]

            if contentType == 0x16 { // Handshake
                self.continueReceivingHandshake(buffer: data, completion: completion)
            } else if contentType == 0x15 { // Alert
                let alertLevel = data.count > 5 ? data[5] : 0
                let alertDesc = data.count > 6 ? data[6] : 0
                logger.error("[Reality] TLS Alert: level=\(alertLevel, privacy: .public), desc=\(alertDesc, privacy: .public)")
                completion(.failure(RealityError.handshakeFailed("TLS Alert: level=\(alertLevel), desc=\(alertDesc)")))
            } else {
                logger.error("[Reality] Unexpected content type: 0x\(String(format: "%02x", contentType), privacy: .public)")
                completion(.failure(RealityError.handshakeFailed("Unexpected content type: \(contentType)")))
            }
        }
    }

    /// Continues receiving handshake messages until ServerHello is complete.
    private func continueReceivingHandshake(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard buffer.count >= 100 else {
            // Need more data
            guard let connection else {
                completion(.failure(RealityError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    logger.error("[Reality] Error receiving more data: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                    return
                }

                var newBuffer = buffer
                if let moreData {
                    newBuffer.append(moreData)
                }

                self.continueReceivingHandshake(buffer: newBuffer, completion: completion)
            }
            return
        }

        guard verifyServerResponse(data: buffer) else {
            logger.error("[Reality] Server verification failed")
            completion(.failure(RealityError.authenticationFailed))
            return
        }

        guard let (serverKeyShare, cipherSuite) = parseServerHello(data: buffer),
              let privateKey = ephemeralPrivateKey,
              let clientHello = storedClientHello else {
            logger.error("[Reality] Failed to parse ServerHello or missing keys")
            completion(.failure(RealityError.handshakeFailed("Failed to parse ServerHello")))
            return
        }

        do {
            let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyShare)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

            let serverHello = extractServerHelloMessage(from: buffer)

            keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            var transcript = Data()
            transcript.append(clientHello)
            transcript.append(serverHello)

            let (hs, keys) = keyDerivation!.deriveHandshakeKeys(sharedSecret: sharedSecretData, transcript: transcript)
            handshakeSecret = hs
            handshakeKeys = keys
            handshakeTranscript = transcript

            consumeRemainingHandshake(buffer: buffer, completion: completion)
        } catch {
            logger.error("[Reality] Failed to derive TLS keys: \(error.localizedDescription, privacy: .public)")
            completion(.failure(RealityError.handshakeFailed("Key derivation failed")))
        }
    }

    // MARK: - ServerHello Parsing

    /// Extracts the ServerHello handshake message from the buffer (without TLS record header).
    private func extractServerHelloMessage(from buffer: Data) -> Data {
        var offset = 0
        while offset + 5 < buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if contentType == 0x16 {
                let recordStart = offset + 5
                if recordStart < buffer.count && buffer[recordStart] == 0x02 {
                    return buffer.subdata(in: recordStart..<min(recordStart + recordLen, buffer.count))
                }
            }

            offset += 5 + recordLen
        }
        return Data()
    }

    /// Parses the ServerHello to extract the server's X25519 key share and cipher suite.
    ///
    /// - Parameter data: The raw TLS data containing the ServerHello record.
    /// - Returns: A tuple of (keyShare, cipherSuite) or `nil` if parsing fails.
    private func parseServerHello(data: Data) -> (keyShare: Data, cipherSuite: UInt16)? {
        #if NETWORK_EXTENSION
        var keyShareBuf = Data(count: 32)
        var cipherSuite: UInt16 = 0

        let ok = data.withUnsafeBytes { ptr -> Int32 in
            keyShareBuf.withUnsafeMutableBytes { ksBuf in
                parse_server_hello(
                    ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    ptr.count,
                    ksBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    &cipherSuite
                )
            }
        }

        guard ok == 1 else { return nil }
        return (keyShareBuf, cipherSuite)
        #else
        return parseServerHelloSwift(data: data)
        #endif
    }

    /// Swift fallback for ServerHello parsing (used in main app target).
    private func parseServerHelloSwift(data: Data) -> (keyShare: Data, cipherSuite: UInt16)? {
        var offset = 0

        while offset + 5 < data.count {
            let contentType = data[offset]
            guard contentType == 0x16 else { break }

            let recordLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            offset += 5

            guard offset + recordLen <= data.count else { break }
            guard data[offset] == 0x02 else {
                offset += recordLen
                continue
            }

            var shOffset = offset + 1 + 3 + 2 + 32
            guard shOffset < data.count else { return nil }

            let sessionIdLen = Int(data[shOffset])
            shOffset += 1 + sessionIdLen

            guard shOffset + 2 <= data.count else { return nil }
            let cipherSuite = UInt16(data[shOffset]) << 8 | UInt16(data[shOffset + 1])

            shOffset += 3
            guard shOffset + 2 <= data.count else { return nil }

            let extLen = Int(data[shOffset]) << 8 | Int(data[shOffset + 1])
            shOffset += 2

            let extEnd = shOffset + extLen
            guard extEnd <= data.count else { return nil }

            while shOffset + 4 <= extEnd {
                let extType = Int(data[shOffset]) << 8 | Int(data[shOffset + 1])
                let extDataLen = Int(data[shOffset + 2]) << 8 | Int(data[shOffset + 3])
                shOffset += 4

                if extType == 0x0033 {
                    guard shOffset + 4 <= data.count else { return nil }
                    let group = Int(data[shOffset]) << 8 | Int(data[shOffset + 1])
                    let keyLen = Int(data[shOffset + 2]) << 8 | Int(data[shOffset + 3])
                    shOffset += 4

                    if group == 0x001d && keyLen == 32 {
                        guard shOffset + 32 <= data.count else { return nil }
                        return (data.subdata(in: shOffset..<(shOffset + 32)), cipherSuite)
                    }
                }

                shOffset += extDataLen
            }

            break
        }

        return nil
    }

    // MARK: - Encrypted Handshake Processing

    /// Consumes remaining TLS handshake records (encrypted), looking for Server Finished.
    ///
    /// Once Server Finished is found, derives application keys and sends Client Finished.
    private func consumeRemainingHandshake(
        buffer: Data,
        startOffset: Int = 0,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let keys = handshakeKeys, let kd = keyDerivation else {
            completion(.failure(RealityError.handshakeFailed("Missing handshake keys")))
            return
        }

        var offset = startOffset
        var fullTranscript = handshakeTranscript ?? Data()
        var foundServerFinished = false

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == 0x14 || contentType == 0x16 {
                // ChangeCipherSpec or plaintext handshake — skip
                offset += 5 + recordLen
                continue
            } else if contentType == 0x17 {
                // Encrypted handshake (Application Data wrapper)
                let recordHeader = buffer.subdata(in: offset..<(offset + 5))
                let ciphertext = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))

                do {
                    let seqNum = serverHandshakeSeqNum
                    let decrypted = try TLSRecordCrypto.decryptRecord(
                        ciphertext: ciphertext,
                        key: keys.serverKey,
                        iv: keys.serverIV,
                        seqNum: seqNum,
                        recordHeader: recordHeader
                    )
                    serverHandshakeSeqNum += 1

                    // Add decrypted handshake messages to transcript
                    var hsOffset = 0
                    while hsOffset + 4 <= decrypted.count {
                        let hsType = decrypted[hsOffset]
                        let hsLen = Int(decrypted[hsOffset + 1]) << 16 | Int(decrypted[hsOffset + 2]) << 8 | Int(decrypted[hsOffset + 3])

                        guard hsOffset + 4 + hsLen <= decrypted.count else { break }

                        let hsMessage = decrypted.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                        fullTranscript.append(hsMessage)

                        if hsType == 0x14 { // Finished
                            foundServerFinished = true
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch {
                    logger.error("[Reality] Failed to decrypt handshake record: \(error.localizedDescription, privacy: .public)")
                }
            }

            offset += 5 + recordLen
        }

        let processedOffset = offset
        handshakeTranscript = fullTranscript

        if foundServerFinished {
            applicationKeys = kd.deriveApplicationKeys(handshakeSecret: handshakeSecret!, fullTranscript: fullTranscript)

            sendClientFinished { [weak self] error in
                guard let self else { return }

                if let error {
                    logger.error("[Reality] Failed to send Client Finished: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(RealityError.handshakeFailed("Failed to send Client Finished")))
                    return
                }

                guard let appKeys = self.applicationKeys else {
                    logger.error("[Reality] Application keys not available")
                    completion(.failure(RealityError.handshakeFailed("Application keys not available")))
                    return
                }

                let realityConnection = TLSRecordConnection(
                    clientKey: appKeys.clientKey,
                    clientIV: appKeys.clientIV,
                    serverKey: appKeys.serverKey,
                    serverIV: appKeys.serverIV
                )
                realityConnection.connection = self.connection
                self.connection = nil

                self.clearHandshakeState()
                completion(.success(realityConnection))
            }
        } else {
            // Need more handshake data
            guard let connection else {
                completion(.failure(RealityError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    logger.warning("[Reality] Error receiving more handshake data: \(error.localizedDescription, privacy: .public)")
                }

                var newBuffer = buffer
                if let moreData {
                    newBuffer.append(moreData)
                }

                self.consumeRemainingHandshake(buffer: newBuffer, startOffset: processedOffset, completion: completion)
            }
        }
    }

    // MARK: - Client Finished

    /// Sends the ChangeCipherSpec and encrypted Client Finished messages.
    private func sendClientFinished(completion: @escaping (Error?) -> Void) {
        guard let keys = handshakeKeys,
              let transcript = handshakeTranscript,
              let kd = keyDerivation else {
            completion(RealityError.handshakeFailed("Missing handshake keys"))
            return
        }

        // ChangeCipherSpec record
        var ccsRecord = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

        // Build and encrypt Client Finished
        let verifyData = kd.computeFinishedVerifyData(clientTrafficSecret: keys.clientTrafficSecret, transcript: transcript)

        var finishedMsg = Data()
        finishedMsg.append(0x14) // Handshake type: Finished
        finishedMsg.append(0x00)
        finishedMsg.append(0x00)
        finishedMsg.append(UInt8(verifyData.count))
        finishedMsg.append(verifyData)

        do {
            let finishedRecord = try TLSRecordCrypto.encryptHandshakeRecord(
                plaintext: finishedMsg,
                key: keys.clientKey,
                iv: keys.clientIV,
                seqNum: 0
            )
            ccsRecord.append(finishedRecord)

            guard let connection else {
                completion(RealityError.connectionFailed("Connection cancelled"))
                return
            }
            connection.send(data: ccsRecord, completion: completion)
        } catch {
            completion(error)
        }
    }

    // MARK: - Verification

    /// Verifies the server response contains a valid ServerHello.
    private func verifyServerResponse(data: Data) -> Bool {
        guard authKey != nil else { return false }

        var offset = 0
        while offset + 5 < data.count {
            let contentType = data[offset]
            if contentType != 0x16 { break }

            let recordLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            offset += 5

            if offset + recordLen > data.count { break }

            if data[offset] == 0x02 { // ServerHello
                return true
            }

            offset += recordLen
        }

        return false
    }

    // MARK: - Helpers

    /// Frees handshake-only state to reduce memory after the connection is established.
    private func clearHandshakeState() {
        ephemeralPrivateKey = nil
        authKey = nil
        storedClientHello = nil
        keyDerivation = nil
        handshakeSecret = nil
        handshakeKeys = nil
        handshakeTranscript = nil
    }

    /// Derives a symmetric key from a shared secret using HKDF.
    ///
    /// - Parameters:
    ///   - sharedSecret: The X25519 shared secret.
    ///   - salt: The HKDF salt.
    ///   - info: The HKDF info string.
    ///   - outputLength: The desired output key length in bytes.
    /// - Returns: The derived key data, or `nil` on failure.
    private func deriveKey(sharedSecret: SharedSecret, salt: Data, info: Data, outputLength: Int) -> Data? {
        let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputLength
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }
}
