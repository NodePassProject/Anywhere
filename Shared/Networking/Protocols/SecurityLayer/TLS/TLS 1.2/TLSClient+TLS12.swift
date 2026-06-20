//
//  TLSClient+TLS12.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Security

extension TLSClient {

    // MARK: - TLS 1.2 Handshake

    func handleTLS12Handshake(
        buffer: Data,
        clientHello: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        let serverHello = extractServerHelloMessage(from: buffer)
        var transcript = Data()
        transcript.append(clientHello)
        transcript.append(serverHello)
        self.tls12Transcript = transcript

        receiveTLS12HandshakeMessages(buffer: buffer, completion: completion)
    }

    /// Loops until ServerHelloDone (0x0E) is seen.
    private func receiveTLS12HandshakeMessages(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if let result = parseTLS12HandshakeMessages(buffer: buffer) {
            processTLS12HandshakeResult(result, buffer: buffer, completion: completion)
            return
        }

        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive() { [weak self] moreData, isComplete, error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let moreData, !moreData.isEmpty else {
                completion(.failure(TLSError.handshakeFailed("Connection closed before TLS 1.2 handshake completed")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(moreData)
            self.receiveTLS12HandshakeMessages(buffer: newBuffer, completion: completion)
        }
    }

    private struct TLS12HandshakeMessages {
        var certificates: [SecCertificate] = []
        var certificateDERs: [Data] = []
        var serverKeyExchange: Data?
        var serverHelloDoneOffset: Int = 0
        /// Raw handshake message bytes fed into the transcript hash.
        var handshakeBytes: Data = Data()
    }

    /// Returns nil if ServerHelloDone not yet seen.
    private func parseTLS12HandshakeMessages(buffer: Data) -> TLS12HandshakeMessages? {
        var result = TLS12HandshakeMessages()
        var offset = 0
        var foundServerHelloDone = false
        var pastServerHello = false

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == TLSContentType.handshake {
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                var hsOffset = 0

                while hsOffset + 4 <= recordBody.count {
                    let hsType = recordBody[hsOffset]
                    let hsLen = Int(recordBody[hsOffset + 1]) << 16 | Int(recordBody[hsOffset + 2]) << 8 | Int(recordBody[hsOffset + 3])

                    guard hsOffset + 4 + hsLen <= recordBody.count else { break }

                    let hsMessage = recordBody.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                    let hsBody = recordBody.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))

                    switch hsType {
                    case TLSHandshakeType.serverHello:
                        pastServerHello = true

                    case TLSHandshakeType.certificate:
                        if pastServerHello {
                            result.handshakeBytes.append(hsMessage)
                            parseTLS12CertificateMessage(hsBody, into: &result)
                        }

                    case TLSHandshakeType.serverKeyExchange:
                        result.handshakeBytes.append(hsMessage)
                        result.serverKeyExchange = hsBody

                    case TLSHandshakeType.serverHelloDone:
                        result.handshakeBytes.append(hsMessage)
                        result.serverHelloDoneOffset = offset + 5 + hsOffset + 4 + hsLen
                        foundServerHelloDone = true

                    default:
                        if pastServerHello {
                            result.handshakeBytes.append(hsMessage)
                        }
                    }

                    hsOffset += 4 + hsLen
                }
            }

            offset += 5 + recordLen
        }

        return foundServerHelloDone ? result : nil
    }

    private func parseTLS12CertificateMessage(_ body: Data, into result: inout TLS12HandshakeMessages) {
        guard body.count >= 3 else { return }

        var offset = 0
        let listLen = Int(body[offset]) << 16 | Int(body[offset + 1]) << 8 | Int(body[offset + 2])
        offset += 3

        let listEnd = offset + listLen
        guard listEnd <= body.count else { return }

        while offset + 3 <= listEnd {
            let certLen = Int(body[offset]) << 16 | Int(body[offset + 1]) << 8 | Int(body[offset + 2])
            offset += 3

            guard offset + certLen <= listEnd else { break }

            let certData = body.subdata(in: offset..<(offset + certLen))
            offset += certLen

            result.certificateDERs.append(certData)
            if let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                result.certificates.append(cert)
            }
        }
    }

    private func processTLS12HandshakeResult(
        _ messages: TLS12HandshakeMessages,
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        serverCertificates = messages.certificates

        tls12Transcript?.append(messages.handshakeBytes)

        validateCertificate { [weak self] result in
            guard let self else { return }

            switch result {
            case .failure(let error):
                completion(.failure(error))
                return
            case .success:
                break
            }

            do {
                let preMasterSecret: Data
                let clientKeyExchangeBody: Data

                if TLSCipherSuite.isECDHE(self.tls12CipherSuite) {
                    guard let ske = messages.serverKeyExchange else {
                        completion(.failure(TLSError.handshakeFailed("ECDHE cipher suite but no ServerKeyExchange")))
                        return
                    }
                    try self.verifyServerKeyExchange(ske, certificates: messages.certificates)
                    (preMasterSecret, clientKeyExchangeBody) = try self.processECDHEServerKeyExchange(ske)
                } else {
                    (preMasterSecret, clientKeyExchangeBody) = try self.processRSAKeyExchange(certificates: messages.certificates)
                }

                self.completeTLS12Handshake(
                    preMasterSecret: preMasterSecret,
                    clientKeyExchangeBody: clientKeyExchangeBody,
                    remainingBuffer: buffer.count > messages.serverHelloDoneOffset ? Data(buffer[messages.serverHelloDoneOffset...]) : nil,
                    completion: completion
                )
            } catch {
                completion(.failure(error))
            }
        }
    }

    // MARK: - TLS 1.2 ECDHE Key Exchange

    private func processECDHEServerKeyExchange(_ body: Data) throws -> (preMasterSecret: Data, clientKeyExchange: Data) {
        guard body.count >= 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange too short")
        }

        let curveType = body[0]
        guard curveType == 0x03 else {
            throw TLSError.handshakeFailed("Unsupported curve type: \(curveType)")
        }

        let namedCurve = UInt16(body[1]) << 8 | UInt16(body[2])
        let pubKeyLen = Int(body[3])
        guard body.count >= 4 + pubKeyLen else {
            throw TLSError.handshakeFailed("ServerKeyExchange public key truncated")
        }

        let serverPubKeyData = body.subdata(in: 4..<(4 + pubKeyLen))

        switch namedCurve {
        case TLSNamedGroup.x25519:
            let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPubKeyData)
            guard let privateKey = ephemeralPrivateKey else {
                throw TLSError.handshakeFailed("No ephemeral key")
            }
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            var cke = Data()
            let pubKey = privateKey.publicKey.rawRepresentation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        case TLSNamedGroup.secp256:
            let serverPubKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPubKeyData)
            let clientKey = P256.KeyAgreement.PrivateKey()
            self.ecdhP256PrivateKey = clientKey
            let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            var cke = Data()
            let pubKey = clientKey.publicKey.x963Representation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        case TLSNamedGroup.secp384:
            let serverPubKey = try P384.KeyAgreement.PublicKey(x963Representation: serverPubKeyData)
            let clientKey = P384.KeyAgreement.PrivateKey()
            self.ecdhP384PrivateKey = clientKey
            let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            var cke = Data()
            let pubKey = clientKey.publicKey.x963Representation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        default:
            throw TLSError.handshakeFailed("Unsupported ECDHE curve: 0x\(String(format: "%04x", namedCurve))")
        }
    }

    private func verifyServerKeyExchange(_ body: Data, certificates: [SecCertificate]) throws {
        guard let serverCert = certificates.first else {
            throw TLSError.certificateValidationFailed("No server certificate for ServerKeyExchange verification")
        }

        guard body.count >= 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange too short for signature")
        }

        let pubKeyLen = Int(body[3])
        let paramsEnd = 4 + pubKeyLen
        guard body.count >= paramsEnd + 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange missing signature")
        }

        let sigAlgorithm = UInt16(body[paramsEnd]) << 8 | UInt16(body[paramsEnd + 1])
        let sigLen = Int(body[paramsEnd + 2]) << 8 | Int(body[paramsEnd + 3])
        guard body.count >= paramsEnd + 4 + sigLen else {
            throw TLSError.handshakeFailed("ServerKeyExchange signature truncated")
        }

        let signature = body.subdata(in: (paramsEnd + 4)..<(paramsEnd + 4 + sigLen))

        guard let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.certificateValidationFailed("Failed to extract public key")
        }

        guard let clientRandom = clientRandom, let serverRandom = serverRandom else {
            throw TLSError.handshakeFailed("Missing randoms for signature verification")
        }

        var content = clientRandom
        content.append(serverRandom)
        content.append(body.subdata(in: 0..<paramsEnd))

        let secAlgorithm = secKeyAlgorithm(for: sigAlgorithm)

        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            serverPublicKey,
            secAlgorithm,
            content as CFData,
            signature as CFData,
            &error
        )

        if !isValid {
            if CertificatePolicy.allowInsecure {
                return
            }
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            throw TLSError.certificateValidationFailed("ServerKeyExchange signature failed: \(message)")
        }
    }

    // MARK: - TLS 1.2 RSA Key Exchange

    private func processRSAKeyExchange(certificates: [SecCertificate]) throws -> (preMasterSecret: Data, clientKeyExchange: Data) {
        guard let serverCert = certificates.first,
              let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.handshakeFailed("No server certificate for RSA key exchange")
        }

        var preMasterSecret = Data(count: 48)
        preMasterSecret[0] = 0x03
        preMasterSecret[1] = 0x03
        guard preMasterSecret.withUnsafeMutableBytes({ pointer in
            SecRandomCopyBytes(kSecRandomDefault, 46, pointer.baseAddress! + 2)
        }) == errSecSuccess else {
            throw TLSError.handshakeFailed("Failed to generate pre-master secret")
        }

        var encryptError: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            serverPublicKey,
            .rsaEncryptionPKCS1,
            preMasterSecret as CFData,
            &encryptError
        ) as Data? else {
            let message = encryptError?.takeRetainedValue().localizedDescription ?? "RSA encryption failed"
            throw TLSError.handshakeFailed("RSA key exchange failed: \(message)")
        }

        var cke = Data()
        cke.append(UInt8((encrypted.count >> 8) & 0xFF))
        cke.append(UInt8(encrypted.count & 0xFF))
        cke.append(encrypted)

        return (preMasterSecret, cke)
    }

    // MARK: - TLS 1.2 Key Derivation & Finish

    private func completeTLS12Handshake(
        preMasterSecret: Data,
        clientKeyExchangeBody: Data,
        remainingBuffer: Data?,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let cRandom = clientRandom, let sRandom = serverRandom else {
            completion(.failure(TLSError.handshakeFailed("Missing randoms")))
            return
        }

        let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)

        var ckeMessage = Data()
        ckeMessage.append(TLSHandshakeType.clientKeyExchange)
        let ckeLen = clientKeyExchangeBody.count
        ckeMessage.append(UInt8((ckeLen >> 16) & 0xFF))
        ckeMessage.append(UInt8((ckeLen >> 8) & 0xFF))
        ckeMessage.append(UInt8(ckeLen & 0xFF))
        ckeMessage.append(clientKeyExchangeBody)

        tls12Transcript?.append(ckeMessage)

        guard let transcript = tls12Transcript else {
            completion(.failure(TLSError.handshakeFailed("Missing transcript")))
            return
        }

        let masterSecret: Data
        if useExtendedMasterSecret {
            let sessionHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
            masterSecret = TLS12KeyDerivation.extendedMasterSecret(
                preMasterSecret: preMasterSecret,
                sessionHash: sessionHash,
                useSHA384: useSHA384
            )
        } else {
            masterSecret = TLS12KeyDerivation.masterSecret(
                preMasterSecret: preMasterSecret,
                clientRandom: cRandom,
                serverRandom: sRandom,
                useSHA384: useSHA384
            )
        }
        self.masterSecret = masterSecret

        let macLen = TLSCipherSuite.macLength(tls12CipherSuite)
        let keyLen = TLSCipherSuite.keyLength(tls12CipherSuite)
        let ivLen = TLSCipherSuite.ivLength(tls12CipherSuite)

        let keys = TLS12KeyDerivation.keysFromMasterSecret(
            masterSecret: masterSecret,
            clientRandom: cRandom,
            serverRandom: sRandom,
            macLen: macLen,
            keyLen: keyLen,
            ivLen: ivLen,
            useSHA384: useSHA384
        )

        let transcriptHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
        let clientVerifyData = TLS12KeyDerivation.finishedPayload(
            masterSecret: masterSecret, label: "client finished",
            handshakeHash: transcriptHash, useSHA384: useSHA384
        )

        var finishedMessage = Data()
        finishedMessage.append(TLSHandshakeType.finished)
        finishedMessage.append(0x00)
        finishedMessage.append(0x00)
        finishedMessage.append(UInt8(clientVerifyData.count))
        finishedMessage.append(clientVerifyData)

        let version = negotiatedVersion
        var wireData = Data()

        wireData.append(TLSContentType.handshake)
        wireData.append(UInt8(version >> 8))
        wireData.append(UInt8(version & 0xFF))
        wireData.append(UInt8((ckeMessage.count >> 8) & 0xFF))
        wireData.append(UInt8(ckeMessage.count & 0xFF))
        wireData.append(ckeMessage)

        wireData.append(contentsOf: [TLSContentType.changeCipherSpec, UInt8(version >> 8), UInt8(version & 0xFF), 0x00, 0x01, 0x01])

        do {
            let encryptedFinished = try encryptTLS12Handshake(
                plaintext: finishedMessage,
                contentType: TLSContentType.handshake,
                seqNum: 0,
                version: version,
                clientKey: keys.clientKey,
                clientIV: keys.clientIV,
                clientMACKey: keys.clientMACKey
            )
            wireData.append(encryptedFinished)
        } catch {
            completion(.failure(TLSError.handshakeFailed("Failed to encrypt Finished: \(error.localizedDescription)")))
            return
        }

        tls12Transcript?.append(finishedMessage)

        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.send(data: wireData) { [weak self] error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            self.receiveTLS12ServerFinished(
                buffer: remainingBuffer ?? Data(),
                keys: keys,
                completion: completion
            )
        }
    }

    private func encryptTLS12Handshake(
        plaintext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        version: UInt16,
        clientKey: Data,
        clientIV: Data,
        clientMACKey: Data
    ) throws -> Data {
        let isAEAD = TLSCipherSuite.isAEAD(tls12CipherSuite)
        let isChaCha = TLSCipherSuite.isChaCha20(tls12CipherSuite)

        if isAEAD {
            let key = SymmetricKey(data: clientKey)
            let nonce: Data
            let explicitNonce: Data

            if isChaCha {
                var n = clientIV
                n.withUnsafeMutableBytes { pointer in
                    let p = pointer.bindMemory(to: UInt8.self)
                    let base = p.count - 8
                    for i in 0..<8 { p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
                }
                nonce = n
                explicitNonce = Data()
            } else {
                var seqBytes = Data(count: 8)
                for i in 0..<8 { seqBytes[i] = UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
                var n = clientIV
                n.append(seqBytes)
                nonce = n
                explicitNonce = seqBytes
            }

            var aad = Data(capacity: 13)
            for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
            aad.append(contentType)
            aad.append(UInt8(version >> 8))
            aad.append(UInt8(version & 0xFF))
            aad.append(UInt8((plaintext.count >> 8) & 0xFF))
            aad.append(UInt8(plaintext.count & 0xFF))

            let ct: Data
            let tag: Data
            if isChaCha {
                let nonceObj = try ChaChaPoly.Nonce(data: nonce)
                let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
                ct = Data(sealed.ciphertext)
                tag = Data(sealed.tag)
            } else {
                let nonceObj = try AES.GCM.Nonce(data: nonce)
                let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
                ct = Data(sealed.ciphertext)
                tag = Data(sealed.tag)
            }

            let recordPayloadLen = explicitNonce.count + ct.count + tag.count
            var record = Data(capacity: 5 + recordPayloadLen)
            record.append(contentType)
            record.append(UInt8(version >> 8))
            record.append(UInt8(version & 0xFF))
            record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
            record.append(UInt8(recordPayloadLen & 0xFF))
            record.append(explicitNonce)
            record.append(ct)
            record.append(tag)
            return record
        } else {
            let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
            let useSHA256: Bool
            switch tls12CipherSuite {
            case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                useSHA256 = true
            default:
                useSHA256 = false
            }

            let mac = TLS12KeyDerivation.tls10MAC(
                macKey: clientMACKey, seqNum: seqNum,
                contentType: contentType, protocolVersion: version,
                payload: plaintext, useSHA384: useSHA384, useSHA256: useSHA256
            )

            var data = plaintext
            data.append(mac)

            let blockSize = 16
            let paddingLen = blockSize - (data.count % blockSize)
            data.append(contentsOf: [UInt8](repeating: UInt8(paddingLen - 1), count: paddingLen))

            var iv = Data(count: blockSize)
            guard iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, blockSize, $0.baseAddress!) }) == errSecSuccess else {
                throw TLSError.handshakeFailed("Failed to generate IV")
            }

            var encrypted = Data(count: data.count)
            var numBytesEncrypted = 0
            let status = encrypted.withUnsafeMutableBytes { outPtr in
                data.withUnsafeBytes { inPtr in
                    clientKey.withUnsafeBytes { keyPtr in
                        iv.withUnsafeBytes { ivPtr in
                            CCCrypt(
                                CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                0,
                                keyPtr.baseAddress!, clientKey.count,
                                ivPtr.baseAddress!,
                                inPtr.baseAddress!, data.count,
                                outPtr.baseAddress!, data.count,
                                &numBytesEncrypted
                            )
                        }
                    }
                }
            }

            guard status == kCCSuccess else {
                throw TLSError.handshakeFailed("AES-CBC encryption failed")
            }

            let recordPayloadLen = blockSize + numBytesEncrypted
            var record = Data(capacity: 5 + recordPayloadLen)
            record.append(contentType)
            record.append(UInt8(version >> 8))
            record.append(UInt8(version & 0xFF))
            record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
            record.append(UInt8(recordPayloadLen & 0xFF))
            record.append(iv)
            record.append(encrypted.prefix(numBytesEncrypted))
            return record
        }
    }

    private func receiveTLS12ServerFinished(
        buffer: Data,
        keys: TLS12HandshakeKeys,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if let finishedResult = parseTLS12ServerCCSAndFinished(buffer: buffer, keys: keys) {
            switch finishedResult {
            case .success(let remainingData):
                self.buildTLS12Connection(keys: keys, remainingBuffer: remainingData, completion: completion)
            case .failure(let error):
                completion(.failure(error))
            }
            return
        }

        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive() { [weak self] moreData, isComplete, error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let moreData, !moreData.isEmpty else {
                completion(.failure(TLSError.handshakeFailed("Connection closed before server Finished")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(moreData)
            self.receiveTLS12ServerFinished(buffer: newBuffer, keys: keys, completion: completion)
        }
    }

    /// Returns remaining post-handshake bytes on success, or nil if the record is incomplete.
    private func parseTLS12ServerCCSAndFinished(
        buffer: Data,
        keys: TLS12HandshakeKeys
    ) -> Result<Data?, Error>? {
        var offset = 0
        var foundCCS = false
        var serverSeqNum: UInt64 = 0

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { return nil }

            if contentType == TLSContentType.changeCipherSpec {
                foundCCS = true
            } else if contentType == TLSContentType.handshake && !foundCCS {
                // Plaintext handshake before CCS (e.g. NewSessionTicket) must enter the transcript — the server's Finished hash includes it.
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                tls12Transcript?.append(recordBody)
            } else if contentType == TLSContentType.handshake && foundCCS {
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))

                do {
                    let seqNum = serverSeqNum
                    serverSeqNum += 1
                    let decrypted = try decryptTLS12HandshakeRecord(
                        ciphertext: recordBody,
                        contentType: TLSContentType.handshake,
                        seqNum: seqNum,
                        serverKey: keys.serverKey,
                        serverIV: keys.serverIV,
                        serverMACKey: keys.serverMACKey
                    )

                    guard decrypted.count >= 16, decrypted[0] == TLSHandshakeType.finished else {
                        return .failure(TLSError.handshakeFailed("Invalid server Finished"))
                    }

                    let verifyData = decrypted.subdata(in: 4..<16)

                    guard let ms = masterSecret, let transcript = tls12Transcript else {
                        return .failure(TLSError.handshakeFailed("Missing state for Finished verification"))
                    }

                    let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
                    let transcriptHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
                    let expectedVerifyData = TLS12KeyDerivation.finishedPayload(
                        masterSecret: ms, label: "server finished",
                        handshakeHash: transcriptHash, useSHA384: useSHA384
                    )

                    guard verifyData.count == expectedVerifyData.count,
                          constantTimeEqual(verifyData, expectedVerifyData) else {
                        return .failure(TLSError.handshakeFailed("Server Finished verification failed"))
                    }

                    offset += 5 + recordLen
                    let remaining = offset < buffer.count ? Data(buffer[offset...]) : nil
                    return .success(remaining)
                } catch {
                    return .failure(error)
                }
            }

            offset += 5 + recordLen
        }

        return nil
    }

    private func decryptTLS12HandshakeRecord(
        ciphertext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        serverKey: Data,
        serverIV: Data,
        serverMACKey: Data
    ) throws -> Data {
        let isAEAD = TLSCipherSuite.isAEAD(tls12CipherSuite)
        let isChaCha = TLSCipherSuite.isChaCha20(tls12CipherSuite)
        let version = negotiatedVersion

        if isAEAD {
            let key = SymmetricKey(data: serverKey)
            let explicitNonceLen = isChaCha ? 0 : 8

            guard ciphertext.count >= explicitNonceLen + 16 else {
                throw TLSError.handshakeFailed("Ciphertext too short")
            }

            let explicitNonce = isChaCha ? Data() : Data(ciphertext.prefix(explicitNonceLen))
            let payload = Data(ciphertext.suffix(from: ciphertext.startIndex + explicitNonceLen))

            let nonce: Data
            if isChaCha {
                var n = serverIV
                n.withUnsafeMutableBytes { pointer in
                    let p = pointer.bindMemory(to: UInt8.self)
                    let base = p.count - 8
                    for i in 0..<8 { p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
                }
                nonce = n
            } else {
                var n = serverIV
                n.append(explicitNonce)
                nonce = n
            }

            let plaintextLen = payload.count - 16
            var aad = Data(capacity: 13)
            for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
            aad.append(contentType)
            aad.append(UInt8(version >> 8))
            aad.append(UInt8(version & 0xFF))
            aad.append(UInt8((plaintextLen >> 8) & 0xFF))
            aad.append(UInt8(plaintextLen & 0xFF))

            let ct = Data(payload.prefix(payload.count - 16))
            let tag = Data(payload.suffix(16))

            if isChaCha {
                let nonceObj = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
                return Data(try ChaChaPoly.open(sealedBox, using: key, authenticating: aad))
            } else {
                let nonceObj = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
                return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
            }
        } else {
            let blockSize = 16
            guard ciphertext.count >= blockSize * 2 else {
                throw TLSError.handshakeFailed("CBC ciphertext too short")
            }

            let iv = Data(ciphertext.prefix(blockSize))
            let encrypted = Data(ciphertext.suffix(from: ciphertext.startIndex + blockSize))

            var decrypted = Data(count: encrypted.count)
            var numBytesDecrypted = 0
            let status = decrypted.withUnsafeMutableBytes { outPtr in
                encrypted.withUnsafeBytes { inPtr in
                    serverKey.withUnsafeBytes { keyPtr in
                        iv.withUnsafeBytes { ivPtr in
                            CCCrypt(
                                CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                0,
                                keyPtr.baseAddress!, serverKey.count,
                                ivPtr.baseAddress!,
                                inPtr.baseAddress!, encrypted.count,
                                outPtr.baseAddress!, encrypted.count,
                                &numBytesDecrypted
                            )
                        }
                    }
                }
            }

            guard status == kCCSuccess else {
                throw TLSError.handshakeFailed("CBC decryption failed")
            }

            decrypted = decrypted.prefix(numBytesDecrypted)

            let paddingByte = Int(decrypted.last ?? 0)
            let paddingLen = paddingByte + 1

            var paddingGood: UInt8 = 0
            if paddingLen > decrypted.count {
                paddingGood = 1
            } else {
                for i in (decrypted.count - paddingLen)..<decrypted.count {
                    paddingGood |= decrypted[i] ^ UInt8(paddingByte)
                }
            }

            guard paddingGood == 0 else {
                throw TLSError.handshakeFailed("Invalid CBC padding")
            }
            decrypted = decrypted.prefix(decrypted.count - paddingLen)

            let macSize = TLSCipherSuite.macLength(tls12CipherSuite)
            guard decrypted.count >= macSize else {
                throw TLSError.handshakeFailed("Decrypted data too short for MAC")
            }

            let payload = Data(decrypted.prefix(decrypted.count - macSize))
            let receivedMAC = Data(decrypted.suffix(macSize))

            let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
            let useSHA256: Bool
            switch tls12CipherSuite {
            case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                useSHA256 = true
            default:
                useSHA256 = false
            }

            let expectedMAC = TLS12KeyDerivation.tls10MAC(
                macKey: serverMACKey, seqNum: seqNum,
                contentType: contentType, protocolVersion: negotiatedVersion,
                payload: payload, useSHA384: useSHA384, useSHA256: useSHA256
            )

            guard receivedMAC.count == expectedMAC.count,
                  constantTimeEqual(receivedMAC, expectedMAC) else {
                throw TLSError.handshakeFailed("MAC verification failed")
            }

            return payload
        }
    }

    private func buildTLS12Connection(
        keys: TLS12HandshakeKeys,
        remainingBuffer: Data?,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        let tlsConnection = TLSRecordConnection(
            tls12ClientKey: keys.clientKey,
            clientIV: keys.clientIV,
            serverKey: keys.serverKey,
            serverIV: keys.serverIV,
            clientMACKey: keys.clientMACKey,
            serverMACKey: keys.serverMACKey,
            cipherSuite: tls12CipherSuite,
            protocolVersion: negotiatedVersion,
            initialClientSeqNum: 1,
            initialServerSeqNum: 1
        )
        tlsConnection.connection = self.connection
        tlsConnection.negotiatedALPN = self.negotiatedALPN
        self.connection = nil

        if let remaining = remainingBuffer, !remaining.isEmpty {
            tlsConnection.prependToReceiveBuffer(remaining)
        }

        clearHandshakeState()
        completion(.success(tlsConnection))
    }
}
