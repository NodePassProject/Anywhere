//
//  TLSServer+TLS12.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit
import Security

extension TLSServer {

    // MARK: - TLS 1.2 ECDHE Key

    enum TLS12ECDHEKey {
        case x25519(Curve25519.KeyAgreement.PrivateKey)
        case p256(P256.KeyAgreement.PrivateKey)
        case p384(P384.KeyAgreement.PrivateKey)

        var namedCurve: UInt16 {
            switch self {
            case .x25519: return TLSNamedGroup.x25519
            case .p256: return TLSNamedGroup.secp256
            case .p384: return TLSNamedGroup.secp384
            }
        }

        var publicKey: Data {
            switch self {
            case .x25519(let key):
                return key.publicKey.rawRepresentation
            case .p256(let key):
                return key.publicKey.x963Representation
            case .p384(let key):
                return key.publicKey.x963Representation
            }
        }

        static func generate(namedCurve: UInt16) -> TLS12ECDHEKey? {
            switch namedCurve {
            case TLSNamedGroup.x25519:
                return .x25519(Curve25519.KeyAgreement.PrivateKey())
            case TLSNamedGroup.secp256:
                return .p256(P256.KeyAgreement.PrivateKey())
            case TLSNamedGroup.secp384:
                return .p384(P384.KeyAgreement.PrivateKey())
            default:
                return nil
            }
        }

        func sharedSecret(with clientPublicKey: Data) throws -> Data {
            switch self {
            case .x25519(let key):
                let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientPublicKey)
                let shared = try key.sharedSecretFromKeyAgreement(with: publicKey)
                return shared.withUnsafeBytes { Data($0) }
            case .p256(let key):
                let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: clientPublicKey)
                let shared = try key.sharedSecretFromKeyAgreement(with: publicKey)
                return shared.withUnsafeBytes { Data($0) }
            case .p384(let key):
                let publicKey = try P384.KeyAgreement.PublicKey(x963Representation: clientPublicKey)
                let shared = try key.sharedSecretFromKeyAgreement(with: publicKey)
                return shared.withUnsafeBytes { Data($0) }
            }
        }
    }

    // MARK: - TLS 1.2 Handshake

    func processClientHelloTLS12(parsed: TLSClientHelloParsed) throws {
        negotiatedTLSVersion = 0x0303
        sni = parsed.serverName

        guard parsed.compressionMethods.contains(0) else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "null compression required")
            return
        }

        guard let suite = preferredCipherSuites12.first(where: { parsed.cipherSuites.contains($0) }) else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "no shared TLS 1.2 cipher")
            return
        }
        chosenCipherSuite = suite

        // Absent signature_algorithms extension is allowed; defaults to server preference.
        if !parsed.signatureAlgorithms.isEmpty && !parsed.signatureAlgorithms.contains(TLSSignatureScheme.ecdsa_secp256r1_sha256) {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "ecdsa_secp256r1_sha256 required (TLS 1.2)")
            return
        }

        var serverRandom = Data(count: 32)
        _ = serverRandom.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, 32, pointer.baseAddress!)
        }
        let preferredGroups: [UInt16] = [TLSNamedGroup.x25519, TLSNamedGroup.secp256, TLSNamedGroup.secp384]
        let candidateGroups = parsed.supportedGroups.isEmpty
            ? preferredGroups
            : preferredGroups.filter { parsed.supportedGroups.contains($0) }
        guard let namedCurve = candidateGroups.first,
              let serverPriv = TLS12ECDHEKey.generate(namedCurve: namedCurve) else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "no shared TLS 1.2 ECDHE group")
            return
        }
        ephemeralKey12 = serverPriv

        handshake12.clientRandom = parsed.random
        handshake12.serverRandom = serverRandom
        handshake12.extendedMasterSecret = parsed.extendedMasterSecret

        handshake12.transcript = parsed.handshakeMessage

        var newSessionID = Data(count: 32)
        _ = newSessionID.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, 32, pointer.baseAddress!)
        }

        let serverHello = TLSServerHelloBuilder.buildServerHello12(
            legacySessionID: newSessionID,
            cipherSuite: suite,
            alpn: negotiatedALPN.isEmpty ? nil : negotiatedALPN,
            extendedMasterSecret: parsed.extendedMasterSecret,
            secureRenegotiation: parsed.secureRenegotiation,
            serverRandom: serverRandom
        )
        handshake12.transcript.append(serverHello)

        let cert = TLSServerHelloBuilder.buildCertificate12(leafCertDER: leafCertDER)
        handshake12.transcript.append(cert)

        let parameters = TLSServerHelloBuilder.serverECDHEParams(
            namedCurve: serverPriv.namedCurve,
            publicKey: serverPriv.publicKey
        )
        var signedContent = Data()
        signedContent.append(parsed.random)
        signedContent.append(serverRandom)
        signedContent.append(parameters)
        let signature = try leafSigningKeyP256.signature(for: signedContent)
        let serverKeyExchange = TLSServerHelloBuilder.buildServerKeyExchange(
            params: parameters,
            signatureAlgorithm: TLSSignatureScheme.ecdsa_secp256r1_sha256,
            signature: signature.derRepresentation
        )
        handshake12.transcript.append(serverKeyExchange)

        let serverHelloDone = TLSServerHelloBuilder.buildServerHelloDone()
        handshake12.transcript.append(serverHelloDone)

        emitPlainHandshakeRecord(serverHello)
        emitPlainHandshakeRecord(cert)
        emitPlainHandshakeRecord(serverKeyExchange)
        emitPlainHandshakeRecord(serverHelloDone)

        state = .sentServerHelloDone12
    }

    func processClientHandshakeMessages12() throws {
        while state == .sentServerHelloDone12, let record = try peekTLSRecord() {
            let contentType = record[record.startIndex]
            let payload = record.subdata(in: (record.startIndex + 5)..<record.endIndex)
            rxBuffer.removeFirst(record.count)

            switch contentType {
            case TLSContentType.handshake:
                if !handshake12.receivedCCS {
                    try handleClientKeyExchange12(payload)
                } else {
                    try handleClientFinished12(payload)
                }
            case TLSContentType.changeCipherSpec:
                handshake12.receivedCCS = true
            case TLSContentType.alert:
                let level = payload.count > 0 ? payload[payload.startIndex] : 0
                let description = payload.count > 1 ? payload[payload.startIndex + 1] : 0
                throw TLSError.handshakeFailed("client TLS 1.2 alert level=\(level) desc=\(description) (\(TLSRecordError.alertName(description)))")
            default:
                throw TLSError.handshakeFailed("unexpected content type \(contentType) during TLS 1.2 handshake")
            }
        }
    }

    private func handleClientKeyExchange12(_ recordBody: Data) throws {
        guard recordBody.count >= 4 else {
            throw TLSError.handshakeFailed("ClientKeyExchange too short")
        }
        let msgType = recordBody[recordBody.startIndex]
        guard msgType == TLSHandshakeType.clientKeyExchange else {
            throw TLSError.handshakeFailed("expected ClientKeyExchange, got \(msgType)")
        }
        let length = (Int(recordBody[recordBody.startIndex + 1]) << 16)
                | (Int(recordBody[recordBody.startIndex + 2]) << 8)
                | Int(recordBody[recordBody.startIndex + 3])
        guard recordBody.count >= 4 + length else {
            throw TLSError.handshakeFailed("ClientKeyExchange truncated")
        }

        let body = recordBody.subdata(in: (recordBody.startIndex + 4)..<(recordBody.startIndex + 4 + length))
        guard body.count >= 1 else {
            throw TLSError.handshakeFailed("ClientKeyExchange empty")
        }
        let pubLen = Int(body[body.startIndex])
        guard body.count >= 1 + pubLen else {
            throw TLSError.handshakeFailed("ClientKeyExchange pubkey truncated")
        }
        let clientPubData = body.subdata(in: (body.startIndex + 1)..<(body.startIndex + 1 + pubLen))

        guard let serverPriv = ephemeralKey12 else {
            throw TLSError.handshakeFailed("missing server ephemeral key")
        }
        let preMaster: Data
        do {
            preMaster = try serverPriv.sharedSecret(with: clientPubData)
        } catch {
            throw TLSError.handshakeFailed("invalid client ECDHE key share")
        }

        let clientKeyExchange = recordBody.subdata(in: recordBody.startIndex..<(recordBody.startIndex + 4 + length))
        handshake12.transcript.append(clientKeyExchange)

        let useSHA384 = TLSCipherSuite.usesSHA384(chosenCipherSuite)
        let masterSecret: Data
        if handshake12.extendedMasterSecret {
            let sessionHash = TLS12KeyDerivation.transcriptHash(handshake12.transcript, useSHA384: useSHA384)
            masterSecret = TLS12KeyDerivation.extendedMasterSecret(
                preMasterSecret: preMaster,
                sessionHash: sessionHash,
                useSHA384: useSHA384
            )
        } else {
            masterSecret = TLS12KeyDerivation.masterSecret(
                preMasterSecret: preMaster,
                clientRandom: handshake12.clientRandom!,
                serverRandom: handshake12.serverRandom!,
                useSHA384: useSHA384
            )
        }
        handshake12.masterSecret = masterSecret

        let macLen = TLSCipherSuite.macLength(chosenCipherSuite)
        let keyLen = TLSCipherSuite.keyLength(chosenCipherSuite)
        let ivLen = TLSCipherSuite.ivLength(chosenCipherSuite)
        handshake12.keys = TLS12KeyDerivation.keysFromMasterSecret(
            masterSecret: masterSecret,
            clientRandom: handshake12.clientRandom!,
            serverRandom: handshake12.serverRandom!,
            macLen: macLen,
            keyLen: keyLen,
            ivLen: ivLen,
            useSHA384: useSHA384
        )
    }

    private func handleClientFinished12(_ encryptedRecord: Data) throws {
        guard let keys = handshake12.keys, let ms = handshake12.masterSecret else {
            throw TLSError.handshakeFailed("missing TLS 1.2 keys")
        }

        let plaintext = try decryptTLS12HandshakeRecord(
            ciphertext: encryptedRecord,
            contentType: TLSContentType.handshake,
            seqNum: 0,
            keys: keys
        )

        guard plaintext.count >= 16, plaintext[plaintext.startIndex] == TLSHandshakeType.finished else {
            throw TLSError.handshakeFailed("expected Finished message")
        }
        let received = plaintext.subdata(in: (plaintext.startIndex + 4)..<(plaintext.startIndex + 16))

        let useSHA384 = TLSCipherSuite.usesSHA384(chosenCipherSuite)
        let transcriptHash = TLS12KeyDerivation.transcriptHash(handshake12.transcript, useSHA384: useSHA384)
        let expected = TLS12KeyDerivation.finishedPayload(
            masterSecret: ms,
            label: "client finished",
            handshakeHash: transcriptHash,
            useSHA384: useSHA384
        )
        guard expected.count == received.count else {
            throw TLSError.handshakeFailed("Finished length mismatch")
        }
        var diff: UInt8 = 0
        for i in 0..<expected.count {
            diff |= expected[expected.startIndex + i] ^ received[received.startIndex + i]
        }
        guard diff == 0 else {
            throw TLSError.handshakeFailed("Client Finished verify failed")
        }

        let clientFinished = plaintext.subdata(in: plaintext.startIndex..<(plaintext.startIndex + 16))
        handshake12.transcript.append(clientFinished)

        let serverTranscriptHash = TLS12KeyDerivation.transcriptHash(handshake12.transcript, useSHA384: useSHA384)
        let serverVerify = TLS12KeyDerivation.finishedPayload(
            masterSecret: ms,
            label: "server finished",
            handshakeHash: serverTranscriptHash,
            useSHA384: useSHA384
        )
        let finished = TLSServerHelloBuilder.buildFinished12(verifyData: serverVerify)
        let encryptedFinished = try encryptTLS12HandshakeRecord(
            plaintext: finished,
            contentType: TLSContentType.handshake,
            seqNum: 0,
            keys: keys
        )

        var output = Data()
        output.append(contentsOf: [TLSContentType.changeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01])
        output.append(encryptedFinished)
        delegate?.tlsServer(self, didProduceOutput: output)

        completeHandshake12(keys: keys)
    }

    private func completeHandshake12(keys: TLS12HandshakeKeys) {
        let connection = TLSRecordConnection(
            tls12ClientKey: keys.clientKey,
            clientIV: keys.clientIV,
            serverKey: keys.serverKey,
            serverIV: keys.serverIV,
            clientMACKey: keys.clientMACKey,
            serverMACKey: keys.serverMACKey,
            cipherSuite: chosenCipherSuite,
            protocolVersion: 0x0303,
            initialClientSeqNum: 1,
            initialServerSeqNum: 1,
            direction: .server
        )
        connection.negotiatedALPN = negotiatedALPN

        let trailer = rxBuffer
        rxBuffer = Data()

        state = .established
        delegate?.tlsServer(
            self,
            didCompleteHandshake: connection,
            sni: sni ?? "",
            alpn: negotiatedALPN,
            clientFinishedHandshakeTrailer: trailer
        )
    }

    // MARK: - TLS 1.2 Handshake-time Record Crypto

    private func encryptTLS12HandshakeRecord(
        plaintext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        keys: TLS12HandshakeKeys
    ) throws -> Data {
        let version: UInt16 = 0x0303
        let isChaCha = TLSCipherSuite.isChaCha20(chosenCipherSuite)
        let symKey = SymmetricKey(data: keys.serverKey)

        let nonce: Data
        let explicitNonce: Data
        if isChaCha {
            var n = keys.serverIV
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
            var n = keys.serverIV
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
            let nObj = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.seal(plaintext, using: symKey, nonce: nObj, authenticating: aad)
            ct = Data(sealed.ciphertext)
            tag = Data(sealed.tag)
        } else {
            let nObj = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.seal(plaintext, using: symKey, nonce: nObj, authenticating: aad)
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
    }


    private func decryptTLS12HandshakeRecord(
        ciphertext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        keys: TLS12HandshakeKeys
    ) throws -> Data {
        let version: UInt16 = 0x0303
        let isChaCha = TLSCipherSuite.isChaCha20(chosenCipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8

        guard ciphertext.count >= explicitNonceLen + 16 else {
            throw TLSError.handshakeFailed("TLS 1.2 handshake ciphertext too short")
        }

        let explicitNonce = isChaCha ? Data() : Data(ciphertext.prefix(explicitNonceLen))
        let payload = Data(ciphertext.suffix(from: ciphertext.startIndex + explicitNonceLen))

        let nonce: Data
        if isChaCha {
            var n = keys.clientIV
            n.withUnsafeMutableBytes { pointer in
                let p = pointer.bindMemory(to: UInt8.self)
                let base = p.count - 8
                for i in 0..<8 { p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
            }
            nonce = n
        } else {
            var n = keys.clientIV
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
        let symKey = SymmetricKey(data: keys.clientKey)

        if isChaCha {
            let nObj = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.SealedBox(nonce: nObj, ciphertext: ct, tag: tag)
            return Data(try ChaChaPoly.open(box, using: symKey, authenticating: aad))
        } else {
            let nObj = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: nObj, ciphertext: ct, tag: tag)
            return Data(try AES.GCM.open(box, using: symKey, authenticating: aad))
        }
    }
}
