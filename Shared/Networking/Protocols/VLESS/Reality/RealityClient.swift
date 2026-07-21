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

nonisolated private let logger = AnywhereLogger(category: "RealityClient")

actor RealityClient {
    private let configuration: RealityConfiguration
    private var connection: (any ByteTransport)?
    
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var authKey: Data?
    private var storedClientHello: Data?
    private var sentSessionID: Data?
    private var mlkemPrivateKeyStorage: Any?

    private var tls13State = TLS13HandshakeState()
    private var serverCertVerified = false

    // MARK: Initialization

    init(configuration: RealityConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API
    
    func connect(host: String, port: UInt16) async throws -> TLSRecordConnection {
        try await withHandshakeDeadline {
            try await self.performConnect(host: host, port: port)
        }
    }

    private func performConnect(host: String, port: UInt16) async throws -> TLSRecordConnection {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        guard let privateKey = ephemeralPrivateKey else {
            throw AnywhereError.tls(.handshakeFailed(detail: "No ephemeral key"))
        }

        let clientHello = try buildRealityClientHello(privateKey: privateKey)
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        let transport = TCPTransport(host: host, port: port)
        self.connection = transport
        do {
            try await transport.connect(initialData: clientHello)
        } catch {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: error.localizedDescription))
        }

        return try await receiveServerResponse()
    }
    
    func connect(overTunnel tunnel: ProxyConnection) async throws -> TLSRecordConnection {
        try await withHandshakeDeadline {
            try await self.performConnect(overTunnel: tunnel)
        }
    }

    private func performConnect(overTunnel tunnel: ProxyConnection) async throws -> TLSRecordConnection {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        guard let privateKey = ephemeralPrivateKey else {
            throw AnywhereError.tls(.handshakeFailed(detail: "No ephemeral key"))
        }
        self.connection = TunneledTransport(tunnel: tunnel)

        let clientHello = try buildRealityClientHello(privateKey: privateKey)
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        guard let connection = self.connection else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
        }
        do {
            try await connection.send(clientHello)
        } catch {
            throw AnywhereError.tls(.handshakeFailed(detail: error.localizedDescription))
        }

        return try await receiveServerResponse()
    }
    
    private static let handshakeDeadline: Duration = .seconds(30)

    private func withHandshakeDeadline(
        _ handshake: @escaping @Sendable () async throws -> TLSRecordConnection
    ) async throws -> TLSRecordConnection {
        do {
            return try await withDialDeadline(Self.handshakeDeadline, onExpiry: {
                Task { await self.cancel() }
            }, error: {
                AnywhereError.tls(.handshakeFailed(detail: "Reality handshake timed out"))
            }, operation: handshake)
        } catch {
            releaseOnFailure()
            throw error
        }
    }

    func cancel() {
        clearHandshakeState()
        connection?.cancel()
        connection = nil
    }

    private func releaseOnFailure() {
        connection?.cancel()
        connection = nil
        clearHandshakeState()
    }

    // MARK: - ClientHello

    private func buildRealityClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Failed to generate random bytes"))
        }

        // SessionId carries the Reality metadata in the first 16 bytes.
        var sessionId = Data(count: 32)
        sessionId[0] = 26  // protocol version 26.4.25
        sessionId[1] = 4
        sessionId[2] = 25
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

        let serverPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: configuration.publicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)

        let salt = random.prefix(20)
        let info = "REALITY".data(using: .utf8)!
        authKey = deriveKey(sharedSecret: sharedSecret, salt: salt, info: info, outputLength: 32)

        guard let authKey else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Failed to derive auth key"))
        }

        var mlkemEncapsulationKey: Data?
        #if compiler(>=6.2)
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            if let mlkemPrivateKey = try? CryptoKit.MLKEM768.PrivateKey() {
                mlkemPrivateKeyStorage = mlkemPrivateKey
                mlkemEncapsulationKey = Data(mlkemPrivateKey.publicKey.rawRepresentation)
            }
        }
        #endif

        // The zero-SessionId ClientHello is the AES-GCM AAD; the field is patched in place below.
        let zeroSessionId = Data(count: 32)
        var rawClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: zeroSessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            mlkemEncapsulationKey: mlkemEncapsulationKey
        )

        let nonce = random.suffix(12)
        let plaintext = sessionId.prefix(16)

        let encryptedSessionId = try TLSRecordCrypto.encryptAESGCM(
            plaintext: Data(plaintext),
            key: SymmetricKey(data: authKey),
            nonce: Data(nonce),
            aad: rawClientHello
        )

        let sessionIdOffset = 1 + 3 + 2 + 32 + 1
        rawClientHello.replaceSubrange(sessionIdOffset..<(sessionIdOffset + 32), with: encryptedSessionId)
        sentSessionID = encryptedSessionId

        return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: rawClientHello)
    }

    // MARK: - Server Response Processing
    
    private func receiveServerResponse(buffer: Data = Data()) async throws -> TLSRecordConnection {
        var buffer = buffer
        while buffer.count < 5 {
            guard let connection else {
                throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
            }
            switch try await connection.receive() {
            case .bytes(let data):
                buffer.append(data)
            case .end:
                throw AnywhereError.tls(.handshakeFailed(detail: "No server response"))
            }
        }

        let contentType = buffer[buffer.startIndex]
        if contentType == TLSContentType.handshake {
            return try await continueReceivingHandshake(buffer: buffer)
        } else if contentType == TLSContentType.alert {
            let alertLevel = buffer.count > 5 ? buffer[buffer.startIndex + 5] : 0
            let alertDesc = buffer.count > 6 ? buffer[buffer.startIndex + 6] : 0
            throw AnywhereError.tls(.handshakeFailed(detail: "TLS Alert: level=\(alertLevel), desc=\(alertDesc)"))
        } else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Unexpected content type: \(contentType)"))
        }
    }

    private func continueReceivingHandshake(buffer: Data) async throws -> TLSRecordConnection {
        var buffer = buffer
        while !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
            }
            switch try await connection.receive() {
            case .bytes(let moreData):
                buffer.append(moreData)
            case .end:
                throw AnywhereError.tls(.handshakeFailed(detail: "Connection closed before ServerHello"))
            }
        }

        guard verifyServerResponse(data: buffer) else {
            throw AnywhereError.tls(.reality(.authenticationFailed))
        }

        guard let (serverKeyShare, keyShareGroup, cipherSuite) = parseServerHello(data: buffer),
              let privateKey = ephemeralPrivateKey,
              let clientHello = storedClientHello else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Failed to parse ServerHello"))
        }

        do {
            let sharedSecretData: Data
            if keyShareGroup == TLSNamedGroup.x25519MLKEM768 && serverKeyShare.count == 1120 {
                let mlkemCiphertext = serverKeyShare.prefix(1088)
                let x25519Key = serverKeyShare.suffix(32)
                let x25519PubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519Key)
                let x25519SS = try privateKey.sharedSecretFromKeyAgreement(with: x25519PubKey)
                let x25519Data = x25519SS.withUnsafeBytes { Data($0) }
                let mlkemData = try decapsulateMLKEM(ciphertext: Data(mlkemCiphertext))
                sharedSecretData = mlkemData + x25519Data
            } else {
                let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyShare)
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
                sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
            }

            let serverHello = extractServerHelloMessage(from: buffer)

            tls13State.keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            var transcript = Data()
            transcript.append(clientHello)
            transcript.append(serverHello)

            let (handshakeSecret, keys) = tls13State.keyDerivation!.deriveHandshakeKeys(sharedSecret: sharedSecretData, transcript: transcript)
            tls13State.handshakeSecret = handshakeSecret
            tls13State.handshakeKeys = keys
            tls13State.handshakeTranscript = transcript
        } catch {
            throw AnywhereError.tls(.handshakeFailed(detail: "Key derivation failed"))
        }

        return try await consumeRemainingHandshake(buffer: buffer)
    }

    // MARK: - ServerHello Parsing

    private func bufferContainsCompleteServerHello(_ buffer: Data) -> Bool {
        var offset = 0
        while offset + 5 <= buffer.count {
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if offset + 5 + recordLen > buffer.count { return false }

            if buffer[offset] == TLSContentType.handshake && offset + 5 < buffer.count && buffer[offset + 5] == TLSHandshakeType.serverHello {
                return true
            }

            offset += 5 + recordLen
        }

        return offset > 0
    }
    
    private func extractServerHelloMessage(from buffer: Data) -> Data {
        var offset = 0
        while offset + 5 < buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if contentType == TLSContentType.handshake {
                let recordStart = offset + 5
                if recordStart < buffer.count && buffer[recordStart] == TLSHandshakeType.serverHello {
                    return buffer.subdata(in: recordStart..<min(recordStart + recordLen, buffer.count))
                }
            }

            offset += 5 + recordLen
        }
        return Data()
    }

    private func parseServerHello(data: Data) -> (keyShare: Data, group: UInt16, cipherSuite: UInt16)? {
        var offset = 0

        while offset + 5 < data.count {
            let contentType = data[offset]
            guard contentType == TLSContentType.handshake else { break }

            let recordLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            offset += 5

            guard offset + recordLen <= data.count else { break }
            guard data[offset] == TLSHandshakeType.serverHello else {
                offset += recordLen
                continue
            }
            
            let randomOffset = offset + 1 + 3 + 2
            guard randomOffset + 32 <= data.count else { return nil }
            if data.subdata(in: randomOffset..<(randomOffset + 32)) == TLSRandom.helloRetryRequest {
                return nil
            }

            var shOffset = randomOffset + 32
            guard shOffset < data.count else { return nil }

            let sessionIdLen = Int(data[shOffset])
            guard shOffset + 1 + sessionIdLen <= data.count else { return nil }
            let sessionIDEcho = data.subdata(in: (shOffset + 1)..<(shOffset + 1 + sessionIdLen))
            if let sent = sentSessionID, sessionIDEcho != sent {
                return nil
            }
            shOffset += 1 + sessionIdLen

            guard shOffset + 3 <= data.count else { return nil }
            let cipherSuite = UInt16(data[shOffset]) << 8 | UInt16(data[shOffset + 1])
            switch cipherSuite {
            case TLSCipherSuite.TLS_AES_128_GCM_SHA256,
                 TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                 TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                break
            default:
                return nil
            }
            guard data[shOffset + 2] == 0 else { return nil }

            shOffset += 3
            guard shOffset + 2 <= data.count else { return nil }

            let extLen = Int(data[shOffset]) << 8 | Int(data[shOffset + 1])
            shOffset += 2

            let extEnd = shOffset + extLen
            guard extEnd <= data.count else { return nil }

            while shOffset + 4 <= extEnd {
                let extType = UInt16(data[shOffset]) << 8 | UInt16(data[shOffset + 1])
                let extDataLen = Int(data[shOffset + 2]) << 8 | Int(data[shOffset + 3])
                shOffset += 4
                let extDataStart = shOffset

                if extType == TLSExtensionType.keyShare {
                    guard shOffset + 4 <= data.count else { return nil }
                    let group = UInt16(data[shOffset]) << 8 | UInt16(data[shOffset + 1])
                    let keyLen = Int(data[shOffset + 2]) << 8 | Int(data[shOffset + 3])
                    shOffset += 4

                    if group == TLSNamedGroup.x25519 && keyLen == 32 {
                        guard shOffset + 32 <= data.count else { return nil }
                        return (data.subdata(in: shOffset..<(shOffset + 32)), TLSNamedGroup.x25519, cipherSuite)
                    } else if group == TLSNamedGroup.x25519MLKEM768 && keyLen == 1120 {
                        guard shOffset + 1120 <= data.count else { return nil }
                        return (data.subdata(in: shOffset..<(shOffset + 1120)), TLSNamedGroup.x25519MLKEM768, cipherSuite)
                    }
                }

                shOffset = extDataStart + extDataLen
            }

            break
        }

        return nil
    }

    // MARK: - Encrypted Handshake Processing
    
    private func consumeRemainingHandshake(
        buffer initialBuffer: Data,
        startOffset initialOffset: Int = 0
    ) async throws -> TLSRecordConnection {
        var buffer = initialBuffer
        var startOffset = initialOffset

        while true {
            guard let keys = tls13State.handshakeKeys, let keyDerivation = tls13State.keyDerivation else {
                throw AnywhereError.tls(.handshakeFailed(detail: "Missing handshake keys"))
            }
            
            var offset = startOffset
            var fullTranscript = tls13State.handshakeTranscript ?? Data()
            var foundServerFinished = false
            
            while offset + 5 <= buffer.count {
                let contentType = buffer[offset]
                let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])
                
                guard offset + 5 + recordLen <= buffer.count else { break }
                
                if contentType == TLSContentType.changeCipherSpec || contentType == TLSContentType.handshake {
                    offset += 5 + recordLen
                    continue
                } else if contentType == TLSContentType.applicationData {
                    let recordHeader = buffer.subdata(in: offset..<(offset + 5))
                    let ciphertext = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                    
                    do {
                        let seqNum = tls13State.serverHandshakeSeqNum
                        let decrypted = try TLSRecordCrypto.decryptRecord(
                            ciphertext: ciphertext,
                            key: SymmetricKey(data: keys.serverKey),
                            iv: keys.serverIV,
                            seqNum: seqNum,
                            recordHeader: recordHeader,
                            cipherSuite: keyDerivation.cipherSuite
                        )
                        tls13State.serverHandshakeSeqNum += 1
                        
                        var hsOffset = 0
                        while hsOffset + 4 <= decrypted.count {
                            let hsType = decrypted[hsOffset]
                            let hsLen = Int(decrypted[hsOffset + 1]) << 16 | Int(decrypted[hsOffset + 2]) << 8 | Int(decrypted[hsOffset + 3])
                            
                            guard hsOffset + 4 + hsLen <= decrypted.count else { break }
                            
                            let hsMessage = decrypted.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                            let hsBody = decrypted.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))
                            
                            switch hsType {
                            case TLSHandshakeType.certificate:
                                fullTranscript.append(hsMessage)
                                serverCertVerified = verifyRealityCertificate(certBody: hsBody)
                                
                            case TLSHandshakeType.compressedCertificate:
                                fullTranscript.append(hsMessage)
                                if let decompressed = decompressCertificate(hsBody) {
                                    serverCertVerified = verifyRealityCertificate(certBody: decompressed)
                                } else {
                                    logger.warning("[Reality] Failed to decompress CompressedCertificate")
                                }
                                
                            case TLSHandshakeType.finished:
                                let expectedVerifyData = keyDerivation.serverFinishedPayload(
                                    serverTrafficSecret: keys.serverTrafficSecret,
                                    transcript: fullTranscript
                                )
                                guard hsBody.count == expectedVerifyData.count,
                                      Self.constantTimeEqual(hsBody, expectedVerifyData) else {
                                    throw AnywhereError.tls(.handshakeFailed(detail: "Server Finished verification failed"))
                                }
                                fullTranscript.append(hsMessage)
                                foundServerFinished = true
                                
                            default:
                                fullTranscript.append(hsMessage)
                            }
                            
                            hsOffset += 4 + hsLen
                        }
                    } catch let error as AnywhereError {
                        if case .tls(.handshakeFailed) = error { throw error }
                        throw AnywhereError.tls(.handshakeFailed(detail: "Record decryption failed"))
                    } catch {
                        throw AnywhereError.tls(.handshakeFailed(detail: "Record decryption failed"))
                    }
                }
                
                offset += 5 + recordLen
                
                if foundServerFinished { break }
            }
            
            let processedOffset = offset
            tls13State.handshakeTranscript = fullTranscript
            
            if foundServerFinished {
                guard serverCertVerified else {
                    throw AnywhereError.tls(.reality(.authenticationFailed))
                }
                
                tls13State.applicationKeys = keyDerivation.deriveApplicationKeys(handshakeSecret: tls13State.handshakeSecret!, fullTranscript: fullTranscript)
                
                do {
                    try await sendClientFinished()
                } catch {
                    throw AnywhereError.tls(.handshakeFailed(detail: "Failed to send Client Finished"))
                }
                
                guard let appKeys = self.tls13State.applicationKeys else {
                    throw AnywhereError.tls(.handshakeFailed(detail: "Application keys not available"))
                }
                
                let realityConnection = TLSRecordConnection(
                    clientKey: appKeys.clientKey,
                    clientIV: appKeys.clientIV,
                    serverKey: appKeys.serverKey,
                    serverIV: appKeys.serverIV,
                    cipherSuite: self.tls13State.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256,
                    clientAppSecret: appKeys.clientTrafficSecret,
                    serverAppSecret: appKeys.serverTrafficSecret
                )
                realityConnection.adoptTransport(self.connection)
                self.connection = nil
                
                let remaining = buffer.subdata(in: processedOffset..<buffer.count)
                if !remaining.isEmpty {
                    realityConnection.prependToReceiveBuffer(remaining)
                }
                
                self.clearHandshakeState()
                return realityConnection
            } else {
                guard let connection else {
                    throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
                }
                switch try await connection.receive() {
                case .bytes(let moreData):
                    buffer.append(moreData)
                    startOffset = processedOffset
                    continue
                case .end:
                    throw AnywhereError.tls(.handshakeFailed(detail: "Connection closed before Server Finished"))
                }
            }
        }
    }

    // MARK: - Client Finished

    private func sendClientFinished() async throws {
        guard let keys = tls13State.handshakeKeys,
              let transcript = tls13State.handshakeTranscript,
              let kd = tls13State.keyDerivation else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Missing handshake keys"))
        }

        var ccsRecord = Data([TLSContentType.changeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01])

        let verifyData = kd.clientFinishedPayload(clientTrafficSecret: keys.clientTrafficSecret, transcript: transcript)

        var finishedMsg = Data()
        finishedMsg.append(TLSHandshakeType.finished)
        finishedMsg.append(0x00)
        finishedMsg.append(0x00)
        finishedMsg.append(UInt8(verifyData.count))
        finishedMsg.append(verifyData)

        let finishedRecord = try TLSRecordCrypto.encryptHandshakeRecord(
            plaintext: finishedMsg,
            key: SymmetricKey(data: keys.clientKey),
            iv: keys.clientIV,
            sequenceNumber: 0,
            cipherSuite: tls13State.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
        )
        ccsRecord.append(finishedRecord)

        guard let connection else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
        }
        try await connection.send(ccsRecord)
    }

    // MARK: - Verification

    private func verifyServerResponse(data: Data) -> Bool {
        guard authKey != nil else { return false }

        var offset = 0
        while offset + 5 < data.count {
            let contentType = data[offset]
            if contentType != TLSContentType.handshake { break }

            let recordLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            offset += 5

            if offset + recordLen > data.count { break }

            if data[offset] == TLSHandshakeType.serverHello {
                return true
            }

            offset += recordLen
        }

        return false
    }

    // MARK: - Certificate Verification

    private func verifyRealityCertificate(certBody: Data) -> Bool {
        guard let authKey else { return false }

        guard let certDER = Self.extractFirstCertificate(from: certBody) else { return false }
        guard let (publicKey, signature) = Self.extractEd25519Components(from: certDER) else {
            return false
        }

        let hmac = HMAC<SHA512>.authenticationCode(for: publicKey, using: SymmetricKey(data: authKey))
        return Self.constantTimeEqual(Data(hmac), signature)
    }

    private static func extractFirstCertificate(from certBody: Data) -> Data? {
        var offset = 0

        guard offset < certBody.count else { return nil }
        let contextLen = Int(certBody[offset])
        offset += 1 + contextLen

        guard offset + 3 <= certBody.count else { return nil }
        offset += 3

        guard offset + 3 <= certBody.count else { return nil }
        let certLen = Int(certBody[offset]) << 16 | Int(certBody[offset + 1]) << 8 | Int(certBody[offset + 2])
        offset += 3

        guard certLen > 0, offset + certLen <= certBody.count else { return nil }
        return certBody.subdata(in: offset..<(offset + certLen))
    }

    private static func extractEd25519Components(from certDER: Data) -> (publicKey: Data, signature: Data)? {
        var offset = 0

        guard parseDERSequence(certDER, offset: &offset) != nil else { return nil }

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
        offset += sigAlgLen

        guard offset < certDER.count, certDER[offset] == 0x03 else { return nil }
        offset += 1
        guard let sigBitStringLen = parseDERLength(certDER, offset: &offset) else { return nil }
        guard sigBitStringLen >= 1, offset < certDER.count, certDER[offset] == 0x00 else { return nil }
        let signature = certDER.subdata(in: (offset + 1)..<(offset + sigBitStringLen))

        return (pubKey, signature)
    }

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

    // MARK: - CompressedCertificate

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
        sentSessionID = nil
        mlkemPrivateKeyStorage = nil
        tls13State = TLS13HandshakeState()
        serverCertVerified = false
    }

    private func decapsulateMLKEM(ciphertext: Data) throws -> Data {
        #if compiler(>=6.2)
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            guard let mlkemPrivateKey = mlkemPrivateKeyStorage as? CryptoKit.MLKEM768.PrivateKey else {
                throw AnywhereError.tls(.handshakeFailed(detail: "ML-KEM private key not available"))
            }
            let sharedSecret = try mlkemPrivateKey.decapsulate(ciphertext)
            return sharedSecret.withUnsafeBytes { Data($0) }
        }
        #endif
        throw AnywhereError.tls(.handshakeFailed(detail: "ML-KEM not supported on this platform"))
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
