//
//  RealityClient.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Compression
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "Reality")

// MARK: - RealityClient

/// Reality client: embeds AES-GCM–encrypted auth metadata in the ClientHello SessionId,
/// performs X25519 ECDH mutual authentication, and derives TLS 1.3 keys from the transcript.
nonisolated class RealityClient {
    private let configuration: RealityConfiguration
    private var connection: (any RawTransport)?

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var authKey: Data?
    private var storedClientHello: Data?
    private var mlkemPrivateKeyStorage: Any? // MLKEM768.PrivateKey when the SDK provides it.

    private var tls13 = TLS13HandshakeState()
    private var serverCertVerified = false

    // MARK: Initialization

    init(configuration: RealityConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API

    /// Connects to a Reality server and performs the TLS handshake.
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

        // Build the ClientHello first so TCP Fast Open can carry it in the SYN.
        let clientHello: Data
        do {
            clientHello = try buildRealityClientHello(privateKey: privateKey)
        } catch {
            completion(.failure(error))
            return
        }
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        let transport = RawTCPSocket()
        self.connection = transport

        transport.connect(host: host, port: port, initialData: clientHello) { [weak self] error in
            if let error {
                completion(.failure(RealityError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(RealityError.connectionFailed("Client deallocated")))
                return
            }

            self.receiveServerResponse(completion: completion)
        }
    }

    /// Connects over an existing proxy tunnel (proxy chaining) and performs the Reality handshake.
    func connect(
        overTunnel tunnel: ProxyConnection,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.connection = TunneledTransport(tunnel: tunnel)
        performRealityHandshake(completion: completion)
    }

    func cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = nil
    }

    // MARK: - Handshake

    private func performRealityHandshake(
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let privateKey = ephemeralPrivateKey else {
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
                    completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                    return
                }

                self.receiveServerResponse(completion: completion)
            }
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - ClientHello

    /// Builds a TLS ClientHello with the Reality SessionId (version + timestamp + shortId,
    /// AES-GCM encrypted with a key derived from ECDH with the server).
    private func buildRealityClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw RealityError.handshakeFailed("Failed to generate random bytes")
        }

        // Build SessionId with Reality metadata in first 16 bytes
        var sessionId = Data(count: 32)
        sessionId[0] = 26  // Xray-core version 26.4.25
        sessionId[1] = 4
        sessionId[2] = 25
        sessionId[3] = 0

        let timestamp = UInt32(Date().timeIntervalSince1970)
        sessionId[4] = UInt8((timestamp >> 24) & 0xFF)
        sessionId[5] = UInt8((timestamp >> 16) & 0xFF)
        sessionId[6] = UInt8((timestamp >> 8) & 0xFF)
        sessionId[7] = UInt8(timestamp & 0xFF)

        // shortId in bytes 8-15, zero-padded to 8 bytes (matching Xray-core's fixed [8]byte)
        let shortIdLen = min(configuration.shortId.count, 8)
        for i in 0..<shortIdLen {
            sessionId[8 + i] = configuration.shortId[i]
        }

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
        #if compiler(>=6.2)
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            if let mlkemPK = try? CryptoKit.MLKEM768.PrivateKey() {
                mlkemPrivateKeyStorage = mlkemPK
                mlkemEncapsulationKey = Data(mlkemPK.publicKey.rawRepresentation)
            }
        }
        #endif

        // The zero-SessionId ClientHello is the AES-GCM AAD (Xray-core protocol);
        // the field is patched in place below.
        let zeroSessionId = Data(count: 32)
        var rawClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: zeroSessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            mlkemEncapsulationKey: mlkemEncapsulationKey
        )

        // AES-GCM output is ciphertext (16 B) + tag (16 B) = 32 B, filling the SessionId field exactly.
        let nonce = random.suffix(12)
        let plaintext = sessionId.prefix(16)

        let encryptedSessionId = try TLSRecordCrypto.encryptAESGCM(
            plaintext: Data(plaintext),
            key: SymmetricKey(data: authKey),
            nonce: Data(nonce),
            aad: rawClientHello
        )

        // SessionId offset: type(1) + length(3) + legacy_version(2) + random(32) + sid_len(1) = 39.
        let sessionIdOffset = 1 + 3 + 2 + 32 + 1
        rawClientHello.replaceSubrange(sessionIdOffset..<(sessionIdOffset + 32), with: encryptedSessionId)

        return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: rawClientHello)
    }

    // MARK: - Server Response Processing

    /// Buffers the server's TLS response until a full 5-byte record header is available
    /// (partial chunks are plausible through proxy chains).
    private func receiveServerResponse(
        buffer: Data = Data(),
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if buffer.count >= 5 {
            let contentType = buffer[0]

            if contentType == 0x16 { // Handshake
                self.continueReceivingHandshake(buffer: buffer, completion: completion)
            } else if contentType == 0x15 { // Alert
                let alertLevel = buffer.count > 5 ? buffer[5] : 0
                let alertDesc = buffer.count > 6 ? buffer[6] : 0
                completion(.failure(RealityError.handshakeFailed("TLS Alert: level=\(alertLevel), desc=\(alertDesc)")))
            } else {
                completion(.failure(RealityError.handshakeFailed("Unexpected content type: \(contentType)")))
            }
            return
        }

        guard let connection else {
            completion(.failure(RealityError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive() { [weak self] data, _, error in
            guard let self else { return }

            if let error {
                completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let data, !data.isEmpty else {
                completion(.failure(RealityError.handshakeFailed("No server response")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(data)
            self.receiveServerResponse(buffer: newBuffer, completion: completion)
        }
    }

    private func continueReceivingHandshake(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                completion(.failure(RealityError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive() { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                    return
                }

                guard let moreData, !moreData.isEmpty else {
                    completion(.failure(RealityError.handshakeFailed("Connection closed before ServerHello")))
                    return
                }

                var newBuffer = buffer
                newBuffer.append(moreData)

                self.continueReceivingHandshake(buffer: newBuffer, completion: completion)
            }
            return
        }

        guard verifyServerResponse(data: buffer) else {
            completion(.failure(RealityError.authenticationFailed))
            return
        }

        guard let (serverKeyShare, keyShareGroup, cipherSuite) = parseServerHello(data: buffer),
              let privateKey = ephemeralPrivateKey,
              let clientHello = storedClientHello else {
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
            completion(.failure(RealityError.handshakeFailed("Key derivation failed")))
        }
    }

    // MARK: - ServerHello Parsing

    /// True when the buffer holds a complete Handshake record starting with ServerHello (0x02).
    private func bufferContainsCompleteServerHello(_ buffer: Data) -> Bool {
        var offset = 0
        while offset + 5 <= buffer.count {
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if offset + 5 + recordLen > buffer.count { return false }

            if buffer[offset] == 0x16 && offset + 5 < buffer.count && buffer[offset + 5] == 0x02 {
                return true
            }

            offset += 5 + recordLen
        }

        return offset > 0  // records complete but no ServerHello — let parseServerHello handle it
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

    /// Extracts the server's key share, group, and cipher suite from the ServerHello.
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
                let extDataStart = shOffset

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

                // Anchor on extDataStart — the 0x0033 branch may have advanced
                // shOffset past the start of extData without returning.
                shOffset = extDataStart + extDataLen
            }

            break
        }

        return nil
    }

    // MARK: - Encrypted Handshake Processing

    /// Consumes encrypted TLS handshake records until Server Finished, then derives
    /// application keys and sends Client Finished.
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
                        } else if hsType == 0x19 { // CompressedCertificate (RFC 8879)
                            let certBody = decrypted.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))
                            if let decompressed = decompressCertificate(certBody) {
                                serverCertVerified = verifyRealityCertificate(certBody: decompressed)
                            } else {
                                logger.warning("[Reality] Failed to decompress CompressedCertificate")
                            }
                        }

                        if hsType == 0x14 { // Finished
                            foundServerFinished = true
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch {
                    // Decrypt failures fall through to the outer guard below.
                }
            }

            offset += 5 + recordLen

            // Post-Finished records (e.g. NewSessionTicket) use application keys;
            // stop here so TLSRecordConnection handles them with correct sequence numbers.
            if foundServerFinished { break }
        }

        let processedOffset = offset
        tls13.handshakeTranscript = fullTranscript

        if foundServerFinished {
            guard serverCertVerified else {
                completion(.failure(RealityError.authenticationFailed))
                return
            }

            tls13.applicationKeys = kd.deriveApplicationKeys(handshakeSecret: tls13.handshakeSecret!, fullTranscript: fullTranscript)

            sendClientFinished { [weak self] error in
                guard let self else { return }

                if let error {
                    completion(.failure(RealityError.handshakeFailed("Failed to send Client Finished")))
                    return
                }

                guard let appKeys = self.tls13.applicationKeys else {
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

                let remaining = buffer.subdata(in: processedOffset..<buffer.count)
                if !remaining.isEmpty {
                    realityConnection.prependToReceiveBuffer(remaining)
                }

                self.clearHandshakeState()
                completion(.success(realityConnection))
            }
        } else {
            guard let connection else {
                completion(.failure(RealityError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive() { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    completion(.failure(RealityError.handshakeFailed(error.localizedDescription)))
                    return
                }

                guard let moreData, !moreData.isEmpty else {
                    completion(.failure(RealityError.handshakeFailed("Connection closed before Server Finished")))
                    return
                }

                var newBuffer = buffer
                newBuffer.append(moreData)

                self.consumeRemainingHandshake(buffer: newBuffer, startOffset: processedOffset, completion: completion)
            }
        }
    }

    // MARK: - Client Finished

    private func sendClientFinished(completion: @escaping (Error?) -> Void) {
        guard let keys = tls13.handshakeKeys,
              let transcript = tls13.handshakeTranscript,
              let kd = tls13.keyDerivation else {
            completion(RealityError.handshakeFailed("Missing handshake keys"))
            return
        }

        var ccsRecord = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

        let verifyData = kd.computeFinishedVerifyData(clientTrafficSecret: keys.clientTrafficSecret, transcript: transcript)

        var finishedMsg = Data()
        finishedMsg.append(0x14) // Finished
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

    /// Verifies the Reality server certificate: signature == HMAC-SHA512(AuthKey, ed25519PublicKey),
    /// matching Xray-core's `VerifyPeerCertificate` in `reality.go`.
    private func verifyRealityCertificate(certBody: Data) -> Bool {
        guard let authKey else { return false }

        guard let certDER = Self.extractFirstCertificate(from: certBody) else { return false }
        guard let (publicKey, signature) = Self.extractEd25519Components(from: certDER) else {
            return false
        }

        let hmac = HMAC<SHA512>.authenticationCode(for: publicKey, using: SymmetricKey(data: authKey))
        return Self.constantTimeEqual(Data(hmac), signature)
    }

    /// Extracts the first DER certificate from a TLS 1.3 Certificate message body.
    ///
    /// Format: contextLen(1) + context + listLen(3) + [certLen(3) + certDER + extLen(2) + ext]*
    private static func extractFirstCertificate(from certBody: Data) -> Data? {
        var offset = 0

        // request context (1 byte length + context bytes, always 0 for server cert)
        guard offset < certBody.count else { return nil }
        let contextLen = Int(certBody[offset])
        offset += 1 + contextLen

        guard offset + 3 <= certBody.count else { return nil }
        offset += 3  // certificate list length (3 bytes)

        guard offset + 3 <= certBody.count else { return nil }  // first cert data length
        let certLen = Int(certBody[offset]) << 16 | Int(certBody[offset + 1]) << 8 | Int(certBody[offset + 2])
        offset += 3

        guard certLen > 0, offset + certLen <= certBody.count else { return nil }
        return certBody.subdata(in: offset..<(offset + certLen))
    }

    /// Extracts the ed25519 public key and signature from a DER X.509 certificate;
    /// `nil` means a real website certificate rather than a Reality one.
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

        offset = tbsEnd

        guard let sigAlgLen = parseDERSequence(certDER, offset: &offset) else { return nil }
        offset += sigAlgLen  // skip signatureAlgorithm

        guard offset < certDER.count, certDER[offset] == 0x03 else { return nil }  // signatureValue BIT STRING
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

    // MARK: - CompressedCertificate (RFC 8879)

    /// Decompresses a CompressedCertificate (RFC 8879):
    /// algorithm(2) + uncompressed_length(3) + compressed_length(3) + data.
    private func decompressCertificate(_ body: Data) -> Data? {
        guard body.count >= 8 else { return nil }

        let algorithm = UInt16(body[0]) << 8 | UInt16(body[1])
        let uncompressedLength = Int(body[2]) << 16 | Int(body[3]) << 8 | Int(body[4])
        let compressedLength = Int(body[5]) << 16 | Int(body[6]) << 8 | Int(body[7])
        guard 8 + compressedLength <= body.count else { return nil }
        guard uncompressedLength > 0 && uncompressedLength <= 1 << 24 else { return nil }
        let compressed = body.subdata(in: 8..<(8 + compressedLength))

        let compressionAlgorithm: compression_algorithm
        switch algorithm {
        case 0x0001: compressionAlgorithm = COMPRESSION_ZLIB
        case 0x0002: compressionAlgorithm = COMPRESSION_BROTLI
        default:
            logger.warning("[Reality] Unknown certificate compression algorithm: 0x\(String(format: "%04x", algorithm))")
            return nil
        }

        var decompressed = Data(count: uncompressedLength)
        let decodedSize = decompressed.withUnsafeMutableBytes { destPtr in
            compressed.withUnsafeBytes { srcPtr in
                compression_decode_buffer(
                    destPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    uncompressedLength,
                    srcPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    compressed.count,
                    nil,
                    compressionAlgorithm
                )
            }
        }
        guard decodedSize > 0 else {
            logger.warning("[Reality] Certificate decompression failed (algorithm: 0x\(String(format: "%04x", algorithm)))")
            return nil
        }
        return Data(decompressed.prefix(decodedSize))
    }

    // MARK: - Helpers

    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
    }

    private func clearHandshakeState() {
        ephemeralPrivateKey = nil
        authKey = nil
        storedClientHello = nil
        mlkemPrivateKeyStorage = nil
        tls13 = TLS13HandshakeState()
        serverCertVerified = false
    }

    private func decapsulateMLKEM(ciphertext: Data) throws -> Data {
        #if compiler(>=6.2)
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            guard let pk = mlkemPrivateKeyStorage as? CryptoKit.MLKEM768.PrivateKey else {
                throw RealityError.handshakeFailed("ML-KEM private key not available")
            }
            let sharedSecret = try pk.decapsulate(ciphertext)
            return sharedSecret.withUnsafeBytes { Data($0) }
        }
        #endif
        throw RealityError.handshakeFailed("ML-KEM not supported on this platform")
    }

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
