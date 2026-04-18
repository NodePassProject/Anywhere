//
//  RealityClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "Reality")

// MARK: - RealityClient

/// Client for establishing authenticated Reality connections over TLS 1.3.
///
/// Performs a TLS 1.3 handshake with Reality-specific extensions:
/// - Embeds authentication metadata in the ClientHello SessionId (AES-GCM encrypted).
/// - Uses X25519 ECDH with the server's public key for mutual authentication.
/// - Derives application-layer encryption keys from the TLS 1.3 handshake transcript.
///
/// After a successful handshake, returns a ``TLSRecordConnection`` that wraps
/// the underlying ``RawTCPSocket`` with TLS record encryption/decryption.
class RealityClient {
    private let configuration: RealityConfiguration
    private var connection: (any RawTransport)?

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var authKey: Data?
    private var storedClientHello: Data?
    private var mlkemPrivateKeyStorage: Any? // MLKEM768.PrivateKey on iOS 26+

    /// TLS 1.3 session state (cleared after handshake by reassigning a
    /// fresh ``TLS13HandshakeState``).
    private var tls13 = TLS13HandshakeState()
    private var serverCertVerified = false

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

        guard let privateKey = ephemeralPrivateKey else {
            completion(.failure(RealityError.handshakeFailed("No ephemeral key")))
            return
        }

        // Build ClientHello before connecting so it can be sent via TCP Fast Open
        // (included in the SYN packet, saving one round trip).
        let clientHello: Data
        do {
            clientHello = try buildRealityClientHello(privateKey: privateKey)
        } catch {
            logger.error("[Reality] Failed to build ClientHello: \(error.localizedDescription)")
            completion(.failure(error))
            return
        }
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        let transport = RawTCPSocket()
        self.connection = transport

        transport.connect(host: host, port: port, initialData: clientHello) { [weak self] error in
            if let error {
                logger.error("[Reality] TCP connection failed: \(error.localizedDescription)")
                completion(.failure(RealityError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(RealityError.connectionFailed("Client deallocated")))
                return
            }

            // ClientHello already sent via TFO, proceed directly to server response
            self.receiveServerResponse(completion: completion)
        }
    }

    /// Connects over an existing proxy tunnel and performs the Reality handshake.
    ///
    /// Used for proxy chaining: the tunnel provides raw TCP I/O to the remote server.
    ///
    /// - Parameters:
    ///   - tunnel: The proxy connection providing a TCP tunnel to the server.
    ///   - completion: Called with the established ``TLSRecordConnection`` or an error.
    func connect(
        overTunnel tunnel: ProxyConnection,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.connection = TunneledTransport(tunnel: tunnel)
        performRealityHandshake(completion: completion)
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
                    logger.error("[Reality] Failed to send ClientHello: \(error.localizedDescription)")
                    completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                    return
                }

                self.receiveServerResponse(completion: completion)
            }
        } catch {
            logger.error("[Reality] Failed to build ClientHello: \(error.localizedDescription)")
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
        guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw RealityError.handshakeFailed("Failed to generate random bytes")
        }

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

        // Copy shortId into bytes 8-15, zero-padded to 8 bytes (matching Xray-core's fixed [8]byte)
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

        // Generate ML-KEM-768 key pair for PQ hybrid key share (iOS 26+)
        var mlkemEncapsulationKey: Data?
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            if let mlkemPK = try? CryptoKit.MLKEM768.PrivateKey() {
                mlkemPrivateKeyStorage = mlkemPK
                mlkemEncapsulationKey = Data(mlkemPK.publicKey.rawRepresentation)
            }
        }

        // Build ClientHello with zero SessionId for AAD (matching Xray-core)
        let zeroSessionId = Data(count: 32)
        let rawClientHelloForAAD = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: zeroSessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            mlkemEncapsulationKey: mlkemEncapsulationKey
        )

        // Encrypt first 16 bytes of SessionId using AES-GCM
        let nonce = random.suffix(12)
        let plaintext = sessionId.prefix(16)

        let encryptedSessionId = try TLSRecordCrypto.encryptAESGCM(
            plaintext: Data(plaintext),
            key: SymmetricKey(data: authKey),
            nonce: Data(nonce),
            aad: rawClientHelloForAAD
        )

        // Build final ClientHello with encrypted sessionId
        let finalClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: encryptedSessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            mlkemEncapsulationKey: mlkemEncapsulationKey
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
                logger.error("[Reality] Error receiving server response: \(error.localizedDescription)")
                completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let data, data.count >= 5 else {
                let len = data?.count ?? 0
                let hex = data.map { $0.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ") } ?? "nil"
                logger.error("[Reality] No server response or too short (len=\(len), data=\(hex))")
                completion(.failure(RealityError.handshakeFailed("No server response")))
                return
            }

            let contentType = data[0]

            if contentType == 0x16 { // Handshake
                self.continueReceivingHandshake(buffer: data, completion: completion)
            } else if contentType == 0x15 { // Alert
                let alertLevel = data.count > 5 ? data[5] : 0
                let alertDesc = data.count > 6 ? data[6] : 0
                logger.error("[Reality] TLS Alert: level=\(alertLevel), desc=\(alertDesc)")
                completion(.failure(RealityError.handshakeFailed("TLS Alert: level=\(alertLevel), desc=\(alertDesc)")))
            } else {
                let hex = data.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
                logger.error("[Reality] Unexpected content type: 0x\(String(format: "%02x", contentType)), first 32 bytes: \(hex)")
                completion(.failure(RealityError.handshakeFailed("Unexpected content type: \(contentType)")))
            }
        }
    }

    /// Continues receiving handshake messages until ServerHello is complete.
    private func continueReceivingHandshake(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Wait until we have a complete TLS record containing ServerHello.
        // The server may split the response across multiple TCP segments,
        // so we must check the record's declared length before parsing.
        if !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                completion(.failure(RealityError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    logger.error("[Reality] Error receiving more data: \(error.localizedDescription)")
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

        guard let (serverKeyShare, keyShareGroup, cipherSuite) = parseServerHello(data: buffer),
              let privateKey = ephemeralPrivateKey,
              let clientHello = storedClientHello else {
            logger.error("[Reality] Failed to parse ServerHello or missing keys")
            completion(.failure(RealityError.handshakeFailed("Failed to parse ServerHello")))
            return
        }

        do {
            let sharedSecretData: Data
            if keyShareGroup == 0x11EC && serverKeyShare.count == 1120 {
                // X25519MLKEM768 hybrid: shared_secret = mlkem_ss || x25519_ss
                let mlkemCiphertext = serverKeyShare.prefix(1088)
                let x25519Key = serverKeyShare.suffix(32)
                let x25519PubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519Key)
                let x25519SS = try privateKey.sharedSecretFromKeyAgreement(with: x25519PubKey)
                let x25519Data = x25519SS.withUnsafeBytes { Data($0) }
                let mlkemData = try decapsulateMLKEM(ciphertext: Data(mlkemCiphertext))
                sharedSecretData = mlkemData + x25519Data
            } else {
                // Pure X25519
                let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyShare)
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
                sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
            }

            let serverHello = extractServerHelloMessage(from: buffer)

            tls13.keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            var transcript = Data()
            transcript.append(clientHello)
            transcript.append(serverHello)

            let (hs, keys) = tls13.keyDerivation!.deriveHandshakeKeys(sharedSecret: sharedSecretData, transcript: transcript)
            tls13.handshakeSecret = hs
            tls13.handshakeKeys = keys
            tls13.handshakeTranscript = transcript

            consumeRemainingHandshake(buffer: buffer, completion: completion)
        } catch {
            logger.error("[Reality] Failed to derive TLS keys: \(error.localizedDescription)")
            completion(.failure(RealityError.handshakeFailed("Key derivation failed")))
        }
    }

    // MARK: - ServerHello Parsing

    /// Returns `true` when the buffer contains at least one complete TLS Handshake
    /// record whose payload starts with a ServerHello (type 0x02).
    ///
    /// Returns `false` when a record header indicates more bytes than are
    /// currently buffered — the caller should read more data and retry.
    private func bufferContainsCompleteServerHello(_ buffer: Data) -> Bool {
        var offset = 0
        while offset + 5 <= buffer.count {
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            // Incomplete record — need more data from the network
            if offset + 5 + recordLen > buffer.count { return false }

            // Complete Handshake record containing a ServerHello
            if buffer[offset] == 0x16 && offset + 5 < buffer.count && buffer[offset + 5] == 0x02 {
                return true
            }

            offset += 5 + recordLen
        }

        // All records complete but no ServerHello found — let parseServerHello handle the error
        return offset > 0
    }

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

    /// Parses the ServerHello to extract the server's key share, group, and cipher suite.
    ///
    /// - Parameter data: The raw TLS data containing the ServerHello record.
    /// - Returns: A tuple of (keyShareData, group, cipherSuite) or `nil` if parsing fails.
    private func parseServerHello(data: Data) -> (keyShare: Data, group: UInt16, cipherSuite: UInt16)? {
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

                    if group == 0x001D && keyLen == 32 {
                        // Pure X25519
                        guard shOffset + 32 <= data.count else { return nil }
                        return (data.subdata(in: shOffset..<(shOffset + 32)), 0x001D, cipherSuite)
                    } else if group == 0x11EC && keyLen == 1120 {
                        // X25519MLKEM768 hybrid: 1088 bytes ML-KEM ciphertext + 32 bytes X25519
                        guard shOffset + 1120 <= data.count else { return nil }
                        return (data.subdata(in: shOffset..<(shOffset + 1120)), 0x11EC, cipherSuite)
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
        guard let keys = tls13.handshakeKeys, let kd = tls13.keyDerivation else {
            completion(.failure(RealityError.handshakeFailed("Missing handshake keys")))
            return
        }

        var offset = startOffset
        var fullTranscript = tls13.handshakeTranscript ?? Data()
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
                    let seqNum = tls13.serverHandshakeSeqNum
                    let decrypted = try TLSRecordCrypto.decryptRecord(
                        ciphertext: ciphertext,
                        key: SymmetricKey(data: keys.serverKey),
                        iv: keys.serverIV,
                        seqNum: seqNum,
                        recordHeader: recordHeader,
                        cipherSuite: kd.cipherSuite
                    )
                    tls13.serverHandshakeSeqNum += 1

                    // Add decrypted handshake messages to transcript
                    var hsOffset = 0
                    while hsOffset + 4 <= decrypted.count {
                        let hsType = decrypted[hsOffset]
                        let hsLen = Int(decrypted[hsOffset + 1]) << 16 | Int(decrypted[hsOffset + 2]) << 8 | Int(decrypted[hsOffset + 3])

                        guard hsOffset + 4 + hsLen <= decrypted.count else { break }

                        let hsMessage = decrypted.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                        fullTranscript.append(hsMessage)

                        if hsType == 0x0B { // Certificate
                            let certBody = decrypted.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))
                            serverCertVerified = verifyRealityCertificate(certBody: certBody)
                        }

                        if hsType == 0x14 { // Finished
                            foundServerFinished = true
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch {
                    logger.error("[Reality] Failed to decrypt handshake record: \(error.localizedDescription)")
                }
            }

            offset += 5 + recordLen

            // After Server Finished, subsequent records (e.g. NewSessionTicket) are
            // encrypted with application keys. Stop here and let TLSRecordConnection
            // handle them so the sequence numbers stay in sync.
            if foundServerFinished { break }
        }

        let processedOffset = offset
        tls13.handshakeTranscript = fullTranscript

        if foundServerFinished {
            guard serverCertVerified else {
                logger.error("[Reality] Server certificate verification failed - not an authenticated Reality server")
                completion(.failure(RealityError.authenticationFailed))
                return
            }

            tls13.applicationKeys = kd.deriveApplicationKeys(handshakeSecret: tls13.handshakeSecret!, fullTranscript: fullTranscript)

            sendClientFinished { [weak self] error in
                guard let self else { return }

                if let error {
                    logger.error("[Reality] Failed to send Client Finished: \(error.localizedDescription)")
                    completion(.failure(RealityError.handshakeFailed("Failed to send Client Finished")))
                    return
                }

                guard let appKeys = self.tls13.applicationKeys else {
                    logger.error("[Reality] Application keys not available")
                    completion(.failure(RealityError.handshakeFailed("Application keys not available")))
                    return
                }

                let realityConnection = TLSRecordConnection(
                    clientKey: appKeys.clientKey,
                    clientIV: appKeys.clientIV,
                    serverKey: appKeys.serverKey,
                    serverIV: appKeys.serverIV,
                    cipherSuite: self.tls13.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
                )
                realityConnection.connection = self.connection
                self.connection = nil

                // Feed remaining buffer data (post-Finished records like NewSessionTicket)
                // to TLSRecordConnection so they are decrypted with application keys
                // and sequence numbers stay in sync.
                let remaining = buffer.subdata(in: processedOffset..<buffer.count)
                if !remaining.isEmpty {
                    realityConnection.prependToReceiveBuffer(remaining)
                }

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
                    logger.warning("[Reality] Error receiving more handshake data: \(error.localizedDescription)")
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
        guard let keys = tls13.handshakeKeys,
              let transcript = tls13.handshakeTranscript,
              let kd = tls13.keyDerivation else {
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
                key: SymmetricKey(data: keys.clientKey),
                iv: keys.clientIV,
                seqNum: 0,
                cipherSuite: tls13.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
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

    // MARK: - Certificate Verification

    /// Verifies the Reality server's certificate using HMAC-SHA512.
    ///
    /// The Reality server signs its ed25519 certificate with `HMAC-SHA512(AuthKey, publicKey)`.
    /// This matches Xray-core's `VerifyPeerCertificate` in `reality.go`.
    private func verifyRealityCertificate(certBody: Data) -> Bool {
        guard let authKey else { return false }

        // Extract first certificate DER from TLS Certificate message body
        guard let certDER = Self.extractFirstCertificate(from: certBody) else { return false }

        // Extract ed25519 public key and signature from the certificate
        guard let (publicKey, signature) = Self.extractEd25519Components(from: certDER) else {
            return false
        }

        // Verify: signature == HMAC-SHA512(AuthKey, publicKey)
        let hmac = HMAC<SHA512>.authenticationCode(for: publicKey, using: SymmetricKey(data: authKey))
        return Data(hmac) == signature
    }

    /// Extracts the first DER certificate from a TLS 1.3 Certificate message body.
    ///
    /// Format: contextLen(1) + context + listLen(3) + [certLen(3) + certDER + extLen(2) + ext]*
    private static func extractFirstCertificate(from certBody: Data) -> Data? {
        var offset = 0

        // Request context length (0 for server certificate)
        guard offset < certBody.count else { return nil }
        let contextLen = Int(certBody[offset])
        offset += 1 + contextLen

        // Certificate list length (3 bytes)
        guard offset + 3 <= certBody.count else { return nil }
        offset += 3

        // First certificate data length (3 bytes)
        guard offset + 3 <= certBody.count else { return nil }
        let certLen = Int(certBody[offset]) << 16 | Int(certBody[offset + 1]) << 8 | Int(certBody[offset + 2])
        offset += 3

        guard certLen > 0, offset + certLen <= certBody.count else { return nil }
        return certBody.subdata(in: offset..<(offset + certLen))
    }

    /// Extracts ed25519 public key and signature from a DER X.509 certificate.
    ///
    /// Returns `nil` if the certificate does not use ed25519, indicating it's
    /// a real website certificate rather than a Reality server certificate.
    private static func extractEd25519Components(from certDER: Data) -> (publicKey: Data, signature: Data)? {
        var offset = 0

        // Outer SEQUENCE (Certificate)
        guard parseDERSequence(certDER, offset: &offset) != nil else { return nil }

        // TBSCertificate SEQUENCE
        let tbsHeaderStart = offset
        guard let tbsLen = parseDERSequence(certDER, offset: &offset) else { return nil }
        let tbsEnd = offset + tbsLen

        // Search TBSCertificate for ed25519 OID (1.3.101.112 = 06 03 2b 65 70)
        // followed by BIT STRING containing 32-byte public key (03 21 00 <32 bytes>)
        var publicKey: Data?
        for i in tbsHeaderStart..<tbsEnd {
            guard i + 40 <= tbsEnd else { break }
            if certDER[i] == 0x06 && certDER[i + 1] == 0x03 &&
               certDER[i + 2] == 0x2b && certDER[i + 3] == 0x65 && certDER[i + 4] == 0x70 &&
               certDER[i + 5] == 0x03 && certDER[i + 6] == 0x21 && certDER[i + 7] == 0x00 {
                publicKey = certDER.subdata(in: (i + 8)..<(i + 8 + 32))
                break
            }
        }
        guard let pubKey = publicKey else { return nil }

        // Skip past TBSCertificate
        offset = tbsEnd

        // signatureAlgorithm SEQUENCE (skip)
        guard let sigAlgLen = parseDERSequence(certDER, offset: &offset) else { return nil }
        offset += sigAlgLen

        // signatureValue BIT STRING
        guard offset < certDER.count, certDER[offset] == 0x03 else { return nil }
        offset += 1
        guard let sigBitStringLen = parseDERLength(certDER, offset: &offset) else { return nil }
        guard sigBitStringLen >= 1, offset < certDER.count, certDER[offset] == 0x00 else { return nil }
        let signature = certDER.subdata(in: (offset + 1)..<(offset + sigBitStringLen))

        return (pubKey, signature)
    }

    /// Parses a DER SEQUENCE tag and returns the content length.
    private static func parseDERSequence(_ data: Data, offset: inout Int) -> Int? {
        guard offset < data.count, data[offset] == 0x30 else { return nil }
        offset += 1
        return parseDERLength(data, offset: &offset)
    }

    /// Parses a DER length encoding.
    private static func parseDERLength(_ data: Data, offset: inout Int) -> Int? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        offset += 1

        if first < 0x80 {
            return Int(first)
        }

        let numBytes = Int(first & 0x7F)
        guard numBytes > 0, numBytes <= 3, offset + numBytes <= data.count else { return nil }

        var length = 0
        for _ in 0..<numBytes {
            length = (length << 8) | Int(data[offset])
            offset += 1
        }
        return length
    }

    // MARK: - Helpers

    /// Frees handshake-only state to reduce memory after the connection is established.
    private func clearHandshakeState() {
        ephemeralPrivateKey = nil
        authKey = nil
        storedClientHello = nil
        mlkemPrivateKeyStorage = nil
        tls13 = TLS13HandshakeState()
        serverCertVerified = false
    }

    /// Decapsulates an ML-KEM-768 ciphertext using the stored private key.
    private func decapsulateMLKEM(ciphertext: Data) throws -> Data {
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            guard let pk = mlkemPrivateKeyStorage as? CryptoKit.MLKEM768.PrivateKey else {
                throw RealityError.handshakeFailed("ML-KEM private key not available")
            }
            let sharedSecret = try pk.decapsulate(ciphertext)
            return sharedSecret.withUnsafeBytes { Data($0) }
        }
        throw RealityError.handshakeFailed("ML-KEM not supported on this platform")
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
