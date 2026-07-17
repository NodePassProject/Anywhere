//
//  TLSClient+TLS13.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Security
import Compression

nonisolated private let logger = AnywhereLogger(category: "TLSClient")

extension TLSClient {

    // MARK: - TLS 1.3 Handshake

    func handleTLS13Handshake(
        buffer: Data,
        serverKeyShare: Data,
        cipherSuite: UInt16,
        clientHello: Data
    ) async throws -> TLSRecordConnection {
        guard let privateKey = ephemeralPrivateKey else {
            throw TLSError.handshakeFailed("No ephemeral key")
        }

        do {
            let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyShare)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

            let serverHello = extractServerHelloMessage(from: buffer)

            tls13.keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            serverCertificates.removeAll()
            tls13.transcriptBeforeCertVerify = nil
            tls13.certificateVerifySignature = nil
            tls13.certificateVerifyAlgorithm = 0

            // With ECH, the accepted handshake transcript is seeded by the inner
            // ClientHello. Detect acceptance via the confirmation embedded in the
            // ServerHello random; on rejection fall back to the outer hello so
            // the (doomed) handshake still decrypts far enough to read retry configs.
            var effectiveClientHello = clientHello
            if let ech = echContext {
                if echAcceptConfirmed(serverHello: serverHello, ech: ech, kd: tls13.keyDerivation!) {
                    echAccepted = true
                    effectiveClientHello = ech.innerTranscriptMessage
                } else {
                    ech.rejected = true
                }
            }

            var transcript = Data()
            transcript.append(effectiveClientHello)
            transcript.append(serverHello)

            let (handshakeSecret, keys) = tls13.keyDerivation!.deriveHandshakeKeys(sharedSecret: sharedSecretData, transcript: transcript)
            tls13.handshakeSecret = handshakeSecret
            tls13.handshakeKeys = keys
            tls13.handshakeTranscript = transcript
            negotiatedVersion = 0x0304
        } catch {
            throw TLSError.handshakeFailed("Key derivation failed")
        }

        return try await consumeRemainingTLS13Handshake(buffer: buffer)
    }

    // MARK: - ECH Accept Confirmation

    /// Returns true if the ServerHello signals that ECH was accepted.
    ///
    /// The server places an 8-byte confirmation in the last 8 bytes of the
    /// ServerHello random, derived (with the negotiated cipher suite's hash) as:
    ///
    ///     PRK  = HKDF-Extract(salt: 0, IKM: ClientHelloInner.random)
    ///     conf = Hash(innerTranscript || ServerHello with random[24..32] zeroed)
    ///     tag  = HKDF-Expand-Label(PRK, "ech accept confirmation", conf, 8)
    private func echAcceptConfirmed(serverHello: Data, ech: ECHClientContext, kd: TLS13KeyDerivation) -> Bool {
        let serverHelloBytes = [UInt8](serverHello)
        guard serverHelloBytes.count >= 38 else { return false }

        var confInput = ech.innerTranscriptMessage
        confInput.append(contentsOf: serverHelloBytes[0..<30])
        confInput.append(Data(repeating: 0, count: 8))
        confInput.append(contentsOf: serverHelloBytes[38...])
        let confHash = kd.transcriptHash(confInput)

        let prk = kd.extract(inputKeyMaterial: ech.innerRandom, salt: Data()).key
        let expected = kd.expandLabel(secret: prk, label: "ech accept confirmation", context: confHash, length: 8)

        return constantTimeEqual(expected, Data(serverHelloBytes[30..<38]))
    }

    /// Extract the `retry_configs` ECHConfigList from the server's
    /// encrypted_client_hello extension in EncryptedExtensions, if present.
    private func parseECHRetryConfigList(fromEncryptedExtensions body: Data) -> Data? {
        let extensionsBytes = [UInt8](body)
        guard extensionsBytes.count >= 2 else { return nil }
        let extsTotal = Int(extensionsBytes[0]) << 8 | Int(extensionsBytes[1])
        let end = min(2 + extsTotal, extensionsBytes.count)
        var offset = 2
        while offset + 4 <= end {
            let extType = UInt16(extensionsBytes[offset]) << 8 | UInt16(extensionsBytes[offset + 1])
            let extLen = Int(extensionsBytes[offset + 2]) << 8 | Int(extensionsBytes[offset + 3])
            offset += 4
            guard offset + extLen <= end else { return nil }
            if extType == 0xFE0D {
                return Data(extensionsBytes[offset..<(offset + extLen)])
            }
            offset += extLen
        }
        return nil
    }

    // MARK: - TLS 1.3 Encrypted Handshake Processing

    private func consumeRemainingTLS13Handshake(
        buffer initialBuffer: Data,
        startOffset initialOffset: Int = 0
    ) async throws -> TLSRecordConnection {
        var buffer = initialBuffer
        var startOffset = initialOffset

        while true {
        guard let keys = tls13.handshakeKeys, let kd = tls13.keyDerivation else {
            throw TLSError.handshakeFailed("Missing handshake keys")
        }

        var offset = startOffset
        var fullTranscript = tls13.handshakeTranscript ?? Data()
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
                        let hsBody = decrypted.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))

                        switch hsType {
                        case TLSHandshakeType.encryptedExtensions:
                            fullTranscript.append(hsMessage)
                            if let ech = echContext, ech.rejected {
                                // ECH was rejected; the server may offer fresh
                                // configs here. Skip ALPN validation — it reflects
                                // the cover (outer) hello, and we will fail anyway.
                                ech.retryConfigList = parseECHRetryConfigList(fromEncryptedExtensions: hsBody)
                            } else if let alpn = parseALPNFromEncryptedExtensions(hsBody) {
                                guard (configuration.alpn ?? ["h2", "http/1.1"]).contains(alpn) else {
                                    throw TLSError.handshakeFailed("Server selected an ALPN we didn't offer")
                                }
                                self.negotiatedALPN = alpn
                            }

                        case TLSHandshakeType.certificate:
                            fullTranscript.append(hsMessage)
                            parseTLS13CertificateMessage(hsBody)

                        case TLSHandshakeType.certificateVerify:
                            tls13.transcriptBeforeCertVerify = fullTranscript
                            fullTranscript.append(hsMessage)
                            if hsBody.count >= 4 {
                                tls13.certificateVerifyAlgorithm = UInt16(hsBody[0]) << 8 | UInt16(hsBody[1])
                                let sigLen = Int(hsBody[2]) << 8 | Int(hsBody[3])
                                if hsBody.count >= 4 + sigLen {
                                    tls13.certificateVerifySignature = hsBody.subdata(in: 4..<(4 + sigLen))
                                }
                            }

                        case TLSHandshakeType.finished:
                            if let keys = self.tls13.handshakeKeys {
                                let expectedVerifyData = kd.finishedPayload(
                                    trafficSecret: keys.serverTrafficSecret,
                                    transcript: fullTranscript
                                )
                                guard hsBody.count == expectedVerifyData.count,
                                      constantTimeEqual(hsBody, expectedVerifyData) else {
                                    throw TLSError.handshakeFailed("Server Finished verification failed")
                                }
                            }
                            fullTranscript.append(hsMessage)
                            foundServerFinished = true

                        case TLSHandshakeType.compressedCertificate:
                            fullTranscript.append(hsMessage)
                            if let decompressed = decompressCertificate(hsBody) {
                                parseTLS13CertificateMessage(decompressed)
                            } else {
                                logger.warning("[TLS] Failed to decompress CompressedCertificate")
                            }

                        default:
                            fullTranscript.append(hsMessage)
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch {
                    throw TLSError.handshakeFailed("Record decryption failed")
                }
            }

            offset += 5 + recordLen

            if foundServerFinished { break }
        }

        let processedOffset = offset
        tls13.handshakeTranscript = fullTranscript

        let remainingBuffer = offset < buffer.count ? Data(buffer[offset...]) : nil
        self.postHandshakeBuffer = remainingBuffer

        if foundServerFinished {
            // ECH rejected: the handshake terminated against the cover name, not
            // the intended server. Surface the rejection (with any retry configs)
            // rather than validating the wrong certificate.
            if let ech = echContext, ech.rejected {
                throw TLSError.echRejected(retryConfigList: ech.retryConfigList)
            }

            try validateCertificate()

            // CertificateVerify is MANDATORY in a full TLS 1.3 handshake.
            let skipVerification = self.configuration.insecureSkipVerify || CertificatePolicy.allowInsecure
            if !skipVerification {
                if let error = TLS13CertificateVerifier.verify(
                    transcriptBeforeCertVerify: self.tls13.transcriptBeforeCertVerify,
                    algorithm: self.tls13.certificateVerifyAlgorithm,
                    signature: self.tls13.certificateVerifySignature,
                    serverCertificates: self.serverCertificates,
                    keyDerivation: self.tls13.keyDerivation
                ) {
                    throw error
                }
            }

            return try await finishTLS13Handshake(fullTranscript: fullTranscript)
        } else {
            guard let connection else {
                throw TLSError.connectionFailed("Connection cancelled")
            }
            switch try await connection.receive() {
            case .bytes(let moreData):
                buffer.append(moreData)
                startOffset = processedOffset
                continue
            case .end:
                throw TLSError.handshakeFailed("Connection closed before TLS 1.3 handshake completed")
            }
        }
        } // while true
    }

    // MARK: - TLS 1.3 Certificate Parsing

    private func parseTLS13CertificateMessage(_ body: Data) {
        serverCertificates.removeAll()

        guard body.count >= 4 else { return }

        var offset = 0
        let contextLen = Int(body[offset])
        offset += 1 + contextLen

        guard offset + 3 <= body.count else { return }

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

            if let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                serverCertificates.append(cert)
            }

            guard offset + 2 <= listEnd else { break }
            let extLen = Int(body[offset]) << 8 | Int(body[offset + 1])
            offset += 2 + extLen
        }
    }

    // MARK: - TLS 1.3 EncryptedExtensions ALPN

    private func parseALPNFromEncryptedExtensions(_ body: Data) -> String? {
        guard body.count >= 2 else { return nil }
        let extsTotal = Int(body[body.startIndex]) << 8 | Int(body[body.startIndex + 1])
        let extsStart = body.startIndex + 2
        let extsEnd = extsStart + extsTotal
        guard extsEnd <= body.endIndex else { return nil }

        var offset = extsStart
        while offset + 4 <= extsEnd {
            let extType = UInt16(body[offset]) << 8 | UInt16(body[offset + 1])
            let extLen = Int(body[offset + 2]) << 8 | Int(body[offset + 3])
            offset += 4
            guard offset + extLen <= extsEnd else { return nil }

            if extType == TLSExtensionType.applicationLayerProtocolNegotiation {
                guard extLen >= 3 else { return nil }
                let listLen = Int(body[offset]) << 8 | Int(body[offset + 1])
                guard 2 + listLen <= extLen else { return nil }
                let nameLen = Int(body[offset + 2])
                guard 3 + nameLen <= extLen else { return nil }
                let nameStart = offset + 3
                let name = body.subdata(in: nameStart..<(nameStart + nameLen))
                return String(data: name, encoding: .utf8)
            }
            offset += extLen
        }
        return nil
    }

    // MARK: - TLS 1.3 Finish Handshake

    private func finishTLS13Handshake(fullTranscript: Data) async throws -> TLSRecordConnection {
        guard let kd = tls13.keyDerivation, let hs = tls13.handshakeSecret else {
            throw TLSError.handshakeFailed("Missing handshake state")
        }

        let application = kd.deriveApplicationMaterial(
            handshakeSecret: hs,
            fullTranscript: fullTranscript
        )
        tls13.applicationKeys = application.keys

        try await sendTLS13ClientFinished()

        guard let appKeys = self.tls13.applicationKeys else {
            throw TLSError.handshakeFailed("Application keys not available")
        }

        let tlsConnection = TLSRecordConnection(
            clientKey: appKeys.clientKey,
            clientIV: appKeys.clientIV,
            serverKey: appKeys.serverKey,
            serverIV: appKeys.serverIV,
            cipherSuite: self.tls13.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256,
            clientAppSecret: appKeys.clientTrafficSecret,
            serverAppSecret: appKeys.serverTrafficSecret,
            exporterMasterSecret: application.exporterMasterSecret
        )
        tlsConnection.connection = self.connection
        tlsConnection.negotiatedALPN = self.negotiatedALPN
        self.connection = nil

        if let remaining = self.postHandshakeBuffer, !remaining.isEmpty {
            tlsConnection.prependToReceiveBuffer(remaining)
        }

        self.clearHandshakeState()
        return tlsConnection
    }

    private func sendTLS13ClientFinished() async throws {
        guard let keys = tls13.handshakeKeys,
              let transcript = tls13.handshakeTranscript,
              let kd = tls13.keyDerivation else {
            throw TLSError.handshakeFailed("Missing handshake keys")
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
            cipherSuite: tls13.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
        )
        ccsRecord.append(finishedRecord)

        guard let connection else {
            throw TLSError.connectionFailed("Connection cancelled")
        }
        try await connection.send(ccsRecord)
    }

    // MARK: - CompressedCertificate (RFC 8879)

    private func decompressCertificate(_ body: Data) -> Data? {
        guard body.count >= 8 else { return nil }

        let algorithm = UInt16(body[0]) << 8 | UInt16(body[1])
        let uncompressedLength = Int(body[2]) << 16 | Int(body[3]) << 8 | Int(body[4])
        let compressedLength = Int(body[5]) << 16 | Int(body[6]) << 8 | Int(body[7])
        guard 8 + compressedLength <= body.count else { return nil }
        let compressed = body.subdata(in: 8..<(8 + compressedLength))

        guard uncompressedLength > 0 && uncompressedLength <= 1 << 24 else { return nil }

        let compressionAlgorithm: compression_algorithm
        switch algorithm {
        case 0x0001: compressionAlgorithm = COMPRESSION_ZLIB
        case 0x0002: compressionAlgorithm = COMPRESSION_BROTLI
        default:
            logger.warning("[TLS] Unknown certificate compression algorithm: 0x\(String(format: "%04x", algorithm))")
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
            logger.warning("[TLS] Certificate decompression failed (algorithm: 0x\(String(format: "%04x", algorithm)))")
            return nil
        }
        return Data(decompressed.prefix(decodedSize))
    }
}
