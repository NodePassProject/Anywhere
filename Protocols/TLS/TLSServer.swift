//
//  TLSServer.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation
import CryptoKit
import Security

/// Lifecycle callbacks for ``TLSServer``.
protocol TLSServerDelegate: AnyObject {
    /// One or more bytes of handshake-layer output (alerts or records) are
    /// ready to be flushed to the client.
    func tlsServer(_ server: TLSServer, didProduceOutput data: Data)

    /// Handshake completed successfully. The delegate should detach the
    /// returned ``TLSRecordConnection`` and route it onto the inner
    /// MITM pipeline.
    /// - Parameter alpn: The ALPN value advertised in EncryptedExtensions
    ///   (always `http/1.1` in v1 — included so the caller doesn't need to
    ///   re-derive it).
    /// - Parameter sni: Server name extracted from the ClientHello.
    /// - Parameter clientFinishedHandshakeTrailer: Bytes received in the
    ///   same chunk as the client Finished but belonging to the
    ///   application layer. ``MITMSession`` should
    ///   ``TLSRecordConnection/prependToReceiveBuffer`` these.
    func tlsServer(
        _ server: TLSServer,
        didCompleteHandshake record: TLSRecordConnection,
        sni: String,
        alpn: String,
        clientFinishedHandshakeTrailer: Data
    )

    /// Handshake failed. The output buffer (if any alert was already
    /// produced) is delivered first via ``didProduceOutput``; this is the
    /// terminal callback.
    func tlsServer(_ server: TLSServer, didFail error: TLSError)
}

/// TLS 1.3 server orchestrator.
final class TLSServer {

    // MARK: - State

    private enum State {
        case waitingClientHello
        case waitingClientHelloAfterHRR
        case sentServerHello
        case waitingClientFinished
        case established
        case failed
    }

    weak var delegate: TLSServerDelegate?

    private let leafCert: SecCertificate
    private let leafCertDER: Data
    private let leafPrivateKey: SecKey
    private let leafSigningKeyP256: P256.Signing.PrivateKey
    private let preferredCipherSuites: [UInt16]

    private var state: State = .waitingClientHello

    /// Buffer of bytes received from the client. We expect exactly one
    /// ClientHello to arrive (possibly across multiple chunks), then one
    /// or more encrypted records carrying the client Finished.
    private var rxBuffer = Data()

    /// Captured SNI from the (last) ClientHello.
    private var sni: String?

    /// Server-side ephemeral X25519 private key.
    private var ephemeralKey: Curve25519.KeyAgreement.PrivateKey?

    /// Selected cipher suite once the (final) ClientHello is processed.
    private var chosenCipherSuite: UInt16 = 0

    /// Echoed legacy_session_id from the ClientHello.
    private var sessionID: Data = Data()

    /// Running TLS 1.3 server handshake state.
    private var handshake = TLS13ServerHandshakeState()

    /// First ClientHello bytes (handshake-layer, no record header). Kept
    /// across the HRR boundary so we can restart the transcript with
    /// the synthetic message_hash record.
    private var firstClientHelloBytes: Data?

    // MARK: - Init

    /// - Parameters:
    ///   - leafCert: The leaf cert to present (v1: a single cert, no chain).
    ///   - leafPrivateKeyP256: P-256 signing key matching the leaf.
    ///     Held as ``P256.Signing.PrivateKey`` (CryptoKit) — the same
    ///     bytes that ``X509Builder`` embedded in the cert.
    ///   - preferredCipherSuites: Ordered list of cipher suites the server
    ///     prefers; pick first match in the client's list.
    init(
        leafCert: SecCertificate,
        leafCertDER: Data,
        leafPrivateKey: SecKey,
        leafSigningKeyP256: P256.Signing.PrivateKey,
        preferredCipherSuites: [UInt16] = [
            TLSCipherSuite.TLS_AES_128_GCM_SHA256,
            TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            TLSCipherSuite.TLS_AES_256_GCM_SHA384,
        ]
    ) {
        self.leafCert = leafCert
        self.leafCertDER = leafCertDER
        self.leafPrivateKey = leafPrivateKey
        self.leafSigningKeyP256 = leafSigningKeyP256
        self.preferredCipherSuites = preferredCipherSuites
    }

    // MARK: - Input

    /// Feed inbound bytes from the client. Called repeatedly as bytes
    /// arrive — internally drives the state machine.
    func feed(_ data: Data) {
        guard state != .failed, state != .established else { return }
        rxBuffer.append(data)
        do {
            try runStateMachine()
        } catch let error as TLSError {
            failHandshake(error)
        } catch {
            failHandshake(.handshakeFailed(error.localizedDescription))
        }
    }

    // MARK: - State Machine

    private func runStateMachine() throws {
        switch state {
        case .waitingClientHello, .waitingClientHelloAfterHRR:
            try processClientHello()
        case .sentServerHello, .waitingClientFinished:
            try processClientFinished()
        case .established, .failed:
            return
        }
    }

    private func processClientHello() throws {
        guard let record = try peekTLSRecord() else { return }
        // ClientHello must be a Handshake record (0x16).
        guard record[record.startIndex] == 0x16 else {
            throw TLSError.handshakeFailed("Expected handshake record")
        }
        // Consume.
        rxBuffer.removeFirst(record.count)

        let parsed = try TLSClientHelloParser.parse(record)

        // Hard requirements.
        guard parsed.supportedVersions.contains(0x0304) else {
            sendAlertAndFail(level: 2, description: 70, message: "TLS 1.3 not offered")  // protocol_version
            return
        }
        guard !parsed.alpnProtocols.isEmpty, parsed.alpnProtocols.contains("http/1.1") else {
            sendAlertAndFail(level: 2, description: 120, message: "http/1.1 ALPN required") // no_application_protocol
            return
        }
        guard parsed.signatureAlgorithms.contains(0x0403) else {
            sendAlertAndFail(level: 2, description: 40, message: "ecdsa_secp256r1_sha256 required") // handshake_failure
            return
        }

        // Pick cipher suite.
        guard let suite = preferredCipherSuites.first(where: { parsed.cipherSuites.contains($0) }) else {
            sendAlertAndFail(level: 2, description: 40, message: "no shared cipher")
            return
        }
        chosenCipherSuite = suite

        // X25519 key share check.
        if let clientKeyShare = parsed.keyShares[0x001D] {
            try sendServerHello(
                parsed: parsed,
                clientKeyShare: clientKeyShare,
                cipherSuite: suite
            )
        } else {
            // First time? Send HRR. Second time? Hard-fail.
            if state == .waitingClientHelloAfterHRR {
                sendAlertAndFail(level: 2, description: 40, message: "client did not honor HRR")
                return
            }
            sendHelloRetryRequest(parsed: parsed, cipherSuite: suite)
        }
    }

    private func sendHelloRetryRequest(parsed: TLSClientHelloParsed, cipherSuite: UInt16) {
        // RFC 8446 §4.4.1: HRR transcript synthesis. The first ClientHello
        // is replaced in the transcript by a synthetic
        // `message_hash` record holding HASH(ClientHello1).
        firstClientHelloBytes = parsed.handshakeMessage
        sessionID = parsed.legacySessionID

        let kd = TLS13KeyDerivation(cipherSuite: cipherSuite)
        let firstHash = kd.transcriptHash(parsed.handshakeMessage)
        let synthetic = synthesizeMessageHashRecord(hash: firstHash)

        // Restart transcript: synthetic || HRR.
        handshake.transcript = synthetic

        let hrr = TLSServerHelloBuilder.buildHelloRetryRequest(
            legacySessionID: parsed.legacySessionID,
            cipherSuite: cipherSuite,
            requestedGroup: 0x001D
        )
        handshake.transcript.append(hrr)
        handshake.keyDerivation = kd

        emitPlainHandshakeRecord(hrr)
        // Per RFC 8446 §5.1: implementations may send a CCS for compatibility.
        emitChangeCipherSpec()
        state = .waitingClientHelloAfterHRR
    }

    private func sendServerHello(
        parsed: TLSClientHelloParsed,
        clientKeyShare: Data,
        cipherSuite: UInt16
    ) throws {
        sni = parsed.serverName
        sessionID = parsed.legacySessionID

        let kd: TLS13KeyDerivation
        if let existing = handshake.keyDerivation {
            kd = existing
        } else {
            kd = TLS13KeyDerivation(cipherSuite: cipherSuite)
            handshake.keyDerivation = kd
        }

        // Generate ephemeral key.
        let serverPriv = Curve25519.KeyAgreement.PrivateKey()
        ephemeralKey = serverPriv

        // Update transcript with this ClientHello.
        if state == .waitingClientHello {
            // Fresh handshake (no HRR): transcript starts empty here.
            handshake.transcript = parsed.handshakeMessage
        } else {
            handshake.transcript.append(parsed.handshakeMessage)
        }

        // Build and append ServerHello.
        let serverHello = TLSServerHelloBuilder.buildServerHello(
            legacySessionID: parsed.legacySessionID,
            cipherSuite: cipherSuite,
            x25519PublicKey: serverPriv.publicKey.rawRepresentation
        )
        handshake.transcript.append(serverHello)

        // Send ServerHello plain.
        emitPlainHandshakeRecord(serverHello)
        // Compatibility CCS.
        emitChangeCipherSpec()

        // Derive handshake keys.
        guard let clientPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientKeyShare) else {
            throw TLSError.handshakeFailed("invalid client X25519 key share")
        }
        let shared = try serverPriv.sharedSecretFromKeyAgreement(with: clientPub)
        let sharedData = shared.withUnsafeBytes { Data($0) }

        let (hsSecret, keys) = kd.deriveHandshakeKeys(sharedSecret: sharedData, transcript: handshake.transcript)
        handshake.handshakeSecret = hsSecret
        handshake.handshakeKeys = keys

        // Build and emit encrypted handshake messages.
        try emitServerEncryptedHandshake(keys: keys, kd: kd)

        state = .sentServerHello
    }

    /// Emits EncryptedExtensions, Certificate, CertificateVerify, and Finished
    /// in one TLS 1.3 application_data record using the server handshake keys.
    private func emitServerEncryptedHandshake(keys: TLSHandshakeKeys, kd: TLS13KeyDerivation) throws {
        let alpn = "http/1.1"
        let ee = TLSServerHelloBuilder.buildEncryptedExtensions(alpn: alpn)
        appendToTranscript(ee)

        let cert = TLSServerHelloBuilder.buildCertificate(leafCertDER: leafCertDER)
        appendToTranscript(cert)

        // Sign transcript hash up to and including Certificate.
        let transcriptHash = kd.transcriptHash(handshake.transcript)
        let cvContext = TLSServerHelloBuilder.certificateVerifyContext(transcriptHash: transcriptHash)
        let signature = try leafSigningKeyP256.signature(for: cvContext)

        let cv = TLSServerHelloBuilder.buildCertificateVerify(
            signatureAlgorithm: 0x0403,
            signature: signature.derRepresentation
        )
        appendToTranscript(cv)

        // Server Finished verify_data uses the server_handshake_traffic_secret.
        let serverFinishedVerify = kd.computeServerFinishedVerifyData(
            serverTrafficSecret: keys.serverTrafficSecret,
            transcript: handshake.transcript
        )
        let fin = TLSServerHelloBuilder.buildFinished(verifyData: serverFinishedVerify)
        appendToTranscript(fin)

        // Pack EE/Cert/CV/Fin into one application_data record (TLS 1.3 allows
        // coalescing handshake messages within a record). Using a single
        // record minimises the number of AEAD ops the client has to do.
        var combined = Data()
        combined.append(ee)
        combined.append(cert)
        combined.append(cv)
        combined.append(fin)

        let encrypted = try encryptHandshakeRecord(content: combined, contentType: 0x16, keys: keys, kd: kd)
        delegate?.tlsServer(self, didProduceOutput: encrypted)

        state = .waitingClientFinished
    }

    // MARK: - Client Finished

    private func processClientFinished() throws {
        // We expect at least one encrypted record.
        guard let record = try peekTLSRecord() else { return }
        rxBuffer.removeFirst(record.count)

        let contentType = record[record.startIndex]
        // Skip the legacy CCS (0x14) some clients send between handshakes.
        if contentType == 0x14 {
            try processClientFinished()
            return
        }
        guard contentType == 0x17 else {
            throw TLSError.handshakeFailed("expected encrypted handshake (got \(contentType))")
        }

        guard let keys = handshake.handshakeKeys, let kd = handshake.keyDerivation,
              let hsSecret = handshake.handshakeSecret else {
            throw TLSError.handshakeFailed("missing handshake keys")
        }

        let header = record.subdata(in: record.startIndex..<(record.startIndex + 5))
        let ciphertext = record.subdata(in: (record.startIndex + 5)..<record.endIndex)

        let seqNum = handshake.clientHandshakeSeqNum
        handshake.clientHandshakeSeqNum &+= 1

        // ``TLSRecordCrypto.decryptRecord`` already strips trailing zeros
        // and the inner content-type byte. v1 only expects a handshake
        // record here, so the missing inner-type check is acceptable.
        let plaintext = try TLSRecordCrypto.decryptRecord(
            ciphertext: ciphertext,
            key: SymmetricKey(data: keys.clientKey),
            iv: keys.clientIV,
            seqNum: seqNum,
            recordHeader: header,
            cipherSuite: chosenCipherSuite
        )

        try parseClientHandshakeMessages(plaintext, keys: keys, kd: kd, hsSecret: hsSecret)
    }

    /// Walks every handshake message in the decrypted plaintext. Looks for
    /// Finished, ignores any optional Certificate (we don't request client
    /// auth in v1).
    private func parseClientHandshakeMessages(
        _ buf: Data,
        keys: TLSHandshakeKeys,
        kd: TLS13KeyDerivation,
        hsSecret: Data
    ) throws {
        var offset = buf.startIndex
        while offset + 4 <= buf.endIndex {
            let msgType = buf[offset]
            let len = (Int(buf[offset + 1]) << 16)
                    | (Int(buf[offset + 2]) << 8)
                    | Int(buf[offset + 3])
            let total = 4 + len
            guard offset + total <= buf.endIndex else { return }

            let message = buf[offset..<(offset + total)]
            switch msgType {
            case 0x14: // Finished
                let received = Data(message.suffix(len))

                // Compute expected against transcript at this point.
                let expected = kd.computeFinishedVerifyData(
                    clientTrafficSecret: keys.clientTrafficSecret,
                    transcript: handshake.transcript
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

                // RFC 8446 §7.1: application_traffic_secret_0 (both
                // directions) is derived from the transcript through
                // server Finished — NOT including the client Finished we
                // just verified. Derive first, then append.
                let appKeys = kd.deriveApplicationKeys(
                    handshakeSecret: hsSecret,
                    fullTranscript: handshake.transcript
                )
                handshake.applicationKeys = appKeys
                handshake.transcript.append(message)

                completeHandshake(applicationKeys: appKeys)
                return

            case 0x0B, 0x0F:
                // Certificate (0x0B) and CertificateVerify (0x0F) — ignored
                // (client auth not requested).
                handshake.transcript.append(message)
                offset += total

            default:
                handshake.transcript.append(message)
                offset += total
            }
        }
    }

    private func completeHandshake(applicationKeys: TLSApplicationKeys) {
        let record = TLSRecordConnection(
            clientKey: applicationKeys.clientKey,
            clientIV: applicationKeys.clientIV,
            serverKey: applicationKeys.serverKey,
            serverIV: applicationKeys.serverIV,
            cipherSuite: chosenCipherSuite,
            direction: .server
        )
        // Anything left in rxBuffer is application-layer data that the
        // client started sending right after Finished. Hand it to the
        // record connection's receive buffer.
        let trailer = rxBuffer
        rxBuffer = Data()

        state = .established
        delegate?.tlsServer(
            self,
            didCompleteHandshake: record,
            sni: sni ?? "",
            alpn: "http/1.1",
            clientFinishedHandshakeTrailer: trailer
        )
    }

    // MARK: - Output Helpers

    /// Wraps a handshake-layer payload in a plain (unencrypted) TLS record
    /// and forwards it to the delegate.
    private func emitPlainHandshakeRecord(_ payload: Data) {
        var record = Data(capacity: 5 + payload.count)
        record.append(0x16)                                           // type = handshake
        record.append(0x03); record.append(0x03)                      // legacy version = TLS 1.2
        record.append(UInt8((payload.count >> 8) & 0xFF))
        record.append(UInt8(payload.count & 0xFF))
        record.append(payload)
        delegate?.tlsServer(self, didProduceOutput: record)
    }

    private func emitChangeCipherSpec() {
        let ccs = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        delegate?.tlsServer(self, didProduceOutput: ccs)
    }

    /// Builds a TLS 1.3 application_data record with the given inner
    /// content type, encrypting under the server handshake-traffic key.
    private func encryptHandshakeRecord(
        content: Data,
        contentType: UInt8,
        keys: TLSHandshakeKeys,
        kd: TLS13KeyDerivation
    ) throws -> Data {
        var inner = content
        inner.append(contentType)
        let encryptedLen = inner.count + 16
        var nonce = keys.serverIV
        let seqNum = handshake.serverHandshakeSeqNum
        handshake.serverHandshakeSeqNum &+= 1
        for i in 0..<8 {
            nonce[nonce.count - 8 + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)
        }
        let aad = Data([
            0x17, 0x03, 0x03,
            UInt8((encryptedLen >> 8) & 0xFF),
            UInt8(encryptedLen & 0xFF),
        ])
        let symmetricKey = SymmetricKey(data: keys.serverKey)

        let (ct, tag) = try seal(plaintext: inner, nonce: nonce, aad: aad, key: symmetricKey)
        var record = Data(capacity: 5 + encryptedLen)
        record.append(aad)
        record.append(ct)
        record.append(tag)
        return record
    }

    private func seal(plaintext: Data, nonce: Data, aad: Data, key: SymmetricKey) throws -> (Data, Data) {
        if TLSCipherSuite.isChaCha20(chosenCipherSuite) {
            let n = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: n, authenticating: aad)
            return (Data(box.ciphertext), Data(box.tag))
        }
        let n = try AES.GCM.Nonce(data: nonce)
        let box = try AES.GCM.seal(plaintext, using: key, nonce: n, authenticating: aad)
        return (Data(box.ciphertext), Data(box.tag))
    }

    private func appendToTranscript(_ message: Data) {
        handshake.transcript.append(message)
    }

    /// Builds the synthetic message_hash handshake record per
    /// RFC 8446 §4.4.1.
    private func synthesizeMessageHashRecord(hash: Data) -> Data {
        var out = Data()
        out.append(0xFE)                                              // message_hash
        // Length (3 bytes) = hash.count
        out.append(0x00)
        out.append(UInt8((hash.count >> 8) & 0xFF))
        out.append(UInt8(hash.count & 0xFF))
        out.append(hash)
        return out
    }

    // MARK: - Failure

    private func failHandshake(_ error: TLSError) {
        state = .failed
        delegate?.tlsServer(self, didFail: error)
    }

    private func sendAlertAndFail(level: UInt8, description: UInt8, message: String) {
        let alert = TLSServerHelloBuilder.alert(level: level, description: description)
        var record = Data(capacity: 5 + alert.count)
        record.append(0x15)                                           // alert
        record.append(0x03); record.append(0x03)
        record.append(UInt8((alert.count >> 8) & 0xFF))
        record.append(UInt8(alert.count & 0xFF))
        record.append(alert)
        delegate?.tlsServer(self, didProduceOutput: record)
        failHandshake(.handshakeFailed(message))
    }

    // MARK: - Record Framing

    /// Returns the next complete TLS record from ``rxBuffer`` (including
    /// header), or `nil` if more bytes are needed.
    private func peekTLSRecord() throws -> Data? {
        guard rxBuffer.count >= 5 else { return nil }
        let len = (Int(rxBuffer[rxBuffer.startIndex + 3]) << 8)
                | Int(rxBuffer[rxBuffer.startIndex + 4])
        guard len <= 16384 + 256 else {
            throw TLSError.handshakeFailed("record length \(len) out of bounds")
        }
        let total = 5 + len
        guard rxBuffer.count >= total else { return nil }
        return rxBuffer.subdata(in: rxBuffer.startIndex..<(rxBuffer.startIndex + total))
    }
}
