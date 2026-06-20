//
//  TLSServer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security

protocol TLSServerDelegate: AnyObject {
    func tlsServer(_ server: TLSServer, didProduceOutput data: Data)

    /// Handshake completed; `clientFinishedHandshakeTrailer` holds application bytes that arrived
    /// with the client Finished — prepend them to the record connection's receive buffer.
    func tlsServer(
        _ server: TLSServer,
        didCompleteHandshake record: TLSRecordConnection,
        sni: String,
        alpn: String,
        clientFinishedHandshakeTrailer: Data
    )

    /// Handshake failed. Any alert bytes are delivered via ``didProduceOutput`` first; this is terminal.
    func tlsServer(_ server: TLSServer, didFail error: TLSError)
}

nonisolated final class TLSServer {

    // MARK: - State

    enum State {
        case waitingClientHello
        case waitingClientHelloAfterHRR
        case sentServerHello
        case waitingClientFinished
        case sentServerHelloDone12
        case established
        case failed
    }

    weak var delegate: TLSServerDelegate?

    private let leafCert: SecCertificate
    let leafCertDER: Data
    private let leafPrivateKey: SecKey
    let leafSigningKeyP256: P256.Signing.PrivateKey
    private let preferredCipherSuites: [UInt16]
    let preferredCipherSuites12: [UInt16]
    private let acceptableTLSVersions: Set<UInt16>

    private let acceptableALPNs: [String]

    /// Negotiated ALPN — locked in on the first ClientHello; HRR cannot change it.
    var negotiatedALPN: String = ""

    var state: State = .waitingClientHello

    var rxBuffer = Data()

    /// Decrypted client handshake messages not yet fully parsed; a message may
    /// span more than one record.
    private var clientHandshakeMessages = Data()

    var sni: String?
    private var ephemeralKey: Curve25519.KeyAgreement.PrivateKey?
    var ephemeralKey12: TLS12ECDHEKey?
    var chosenCipherSuite: UInt16 = 0
    var negotiatedTLSVersion: UInt16 = 0
    private var sessionID: Data = Data()
    private var handshake = TLS13ServerHandshakeState()
    var handshake12 = TLS12ServerHandshakeState()
    /// First ClientHello bytes, kept across HRR for the synthetic message_hash transcript record.
    private var firstClientHelloBytes: Data?

    // MARK: - Init

    /// - Parameters:
    ///   - leafCert: The leaf cert to present (single cert, no chain).
    ///   - acceptableALPNs: Preference order; fails with `no_application_protocol`
    ///     if the client's offer has no overlap.
    ///   - preferredCipherSuites12: Defaults match the ECDSA-P256 leaf.
    init(
        leafCert: SecCertificate,
        leafCertDER: Data,
        leafPrivateKey: SecKey,
        leafSigningKeyP256: P256.Signing.PrivateKey,
        acceptableALPNs: [String] = ["http/1.1"],
        acceptableTLSVersions: Set<UInt16> = [0x0304],
        preferredCipherSuites: [UInt16] = [
            TLSCipherSuite.TLS_AES_128_GCM_SHA256,
            TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            TLSCipherSuite.TLS_AES_256_GCM_SHA384,
        ],
        preferredCipherSuites12: [UInt16] = [
            TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ]
    ) {
        self.leafCert = leafCert
        self.leafCertDER = leafCertDER
        self.leafPrivateKey = leafPrivateKey
        self.leafSigningKeyP256 = leafSigningKeyP256
        self.acceptableALPNs = acceptableALPNs
        self.acceptableTLSVersions = acceptableTLSVersions
        self.preferredCipherSuites = preferredCipherSuites
        self.preferredCipherSuites12 = preferredCipherSuites12
    }

    // MARK: - Input

    /// Feed inbound bytes from the client; drives the handshake state machine.
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
        case .sentServerHelloDone12:
            try processClientHandshakeMessages12()
        case .established, .failed:
            return
        }
    }

    private func processClientHello() throws {
        // A ClientHello may legally be split across several TLS records (RFC 8446 §5.1), so
        // reassemble the whole handshake message before parsing.
        guard let handshakeMessage = try peekReassembledClientHello() else { return }

        let parsed = try TLSClientHelloParser.parseHandshakeBody(handshakeMessage)

        if !parsed.alpnProtocols.isEmpty {
            guard let alpn = acceptableALPNs.first(where: { parsed.alpnProtocols.contains($0) }) else {
                sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.noApplicationProtocol, message: "no overlapping ALPN")
                return
            }
            if negotiatedALPN.isEmpty {
                negotiatedALPN = alpn
            }
        }

        // supported_versions is required to indicate TLS 1.3.
        let clientWantsTLS13 = parsed.supportedVersions.contains(0x0304)
        let canDoTLS13 = acceptableTLSVersions.contains(0x0304) && clientWantsTLS13
        let clientWantsTLS12 = parsed.supportedVersions.isEmpty
            ? parsed.legacyVersion == 0x0303
            : parsed.supportedVersions.contains(0x0303)
        let canDoTLS12 = acceptableTLSVersions.contains(0x0303) && clientWantsTLS12

        if canDoTLS13 {
            try processClientHelloTLS13(parsed: parsed)
        } else if canDoTLS12 {
            try processClientHelloTLS12(parsed: parsed)
        } else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.protocolVersion, message: "no acceptable TLS version")
        }
    }

    private func processClientHelloTLS13(parsed: TLSClientHelloParsed) throws {
        negotiatedTLSVersion = 0x0304

        // TLS 1.3 requires legacy_version == 0x0303 and legacy_compression_methods == {0}.
        guard parsed.legacyVersion == 0x0303, parsed.compressionMethods == [0] else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.illegalParameter, message: "bad legacy version/compression")
            return
        }

        guard parsed.signatureAlgorithms.contains(TLSSignatureScheme.ecdsa_secp256r1_sha256) else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "ecdsa_secp256r1_sha256 required")
            return
        }

        guard let suite = preferredCipherSuites.first(where: { parsed.cipherSuites.contains($0) }) else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "no shared cipher")
            return
        }
        chosenCipherSuite = suite

        guard parsed.supportedGroups.contains(TLSNamedGroup.x25519) else {
            sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "no shared group")
            return
        }

        if let clientKeyShare = parsed.keyShares[TLSNamedGroup.x25519] {
            try sendServerHello(
                parsed: parsed,
                clientKeyShare: clientKeyShare,
                cipherSuite: suite
            )
        } else {
            if state == .waitingClientHelloAfterHRR {
                sendAlertAndFail(level: TLSAlertLevel.fatal, description: TLSAlertDescription.handshakeFailure, message: "client did not honor HRR")
                return
            }
            sendHelloRetryRequest(parsed: parsed, cipherSuite: suite)
        }
    }

    private func sendHelloRetryRequest(parsed: TLSClientHelloParsed, cipherSuite: UInt16) {
        firstClientHelloBytes = parsed.handshakeMessage
        sessionID = parsed.legacySessionID

        let kd = TLS13KeyDerivation(cipherSuite: cipherSuite)
        let firstHash = kd.transcriptHash(parsed.handshakeMessage)
        let synthetic = synthesizeMessageHashRecord(hash: firstHash)

        handshake.transcript = synthetic

        let hrr = TLSServerHelloBuilder.buildHelloRetryRequest(
            legacySessionID: parsed.legacySessionID,
            cipherSuite: cipherSuite,
            requestedGroup: TLSNamedGroup.x25519
        )
        handshake.transcript.append(hrr)
        handshake.keyDerivation = kd

        emitPlainHandshakeRecord(hrr)
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

        let serverPriv = Curve25519.KeyAgreement.PrivateKey()
        ephemeralKey = serverPriv

        if state == .waitingClientHello {
            handshake.transcript = parsed.handshakeMessage
        } else {
            handshake.transcript.append(parsed.handshakeMessage)
        }

        let serverHello = TLSServerHelloBuilder.buildServerHello(
            legacySessionID: parsed.legacySessionID,
            cipherSuite: cipherSuite,
            x25519PublicKey: serverPriv.publicKey.rawRepresentation
        )
        handshake.transcript.append(serverHello)

        emitPlainHandshakeRecord(serverHello)
        emitChangeCipherSpec()

        guard let clientPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientKeyShare) else {
            throw TLSError.handshakeFailed("invalid client X25519 key share")
        }
        let shared = try serverPriv.sharedSecretFromKeyAgreement(with: clientPub)
        let sharedData = shared.withUnsafeBytes { Data($0) }

        let (hsSecret, keys) = kd.deriveHandshakeKeys(sharedSecret: sharedData, transcript: handshake.transcript)
        handshake.handshakeSecret = hsSecret
        handshake.handshakeKeys = keys

        try emitServerEncryptedHandshake(keys: keys, kd: kd)

        state = .sentServerHello
    }

    private func emitServerEncryptedHandshake(keys: TLS13HandshakeKeys, kd: TLS13KeyDerivation) throws {
        let ee = TLSServerHelloBuilder.buildEncryptedExtensions(alpn: negotiatedALPN.isEmpty ? nil : negotiatedALPN)
        appendToTranscript(ee)

        let cert = TLSServerHelloBuilder.buildCertificate(leafCertDER: leafCertDER)
        appendToTranscript(cert)

        let transcriptHash = kd.transcriptHash(handshake.transcript)
        let cvContext = TLSServerHelloBuilder.certificateVerifyContext(transcriptHash: transcriptHash)
        let signature = try leafSigningKeyP256.signature(for: cvContext)

        let cv = TLSServerHelloBuilder.buildCertificateVerify(
            signatureAlgorithm: TLSSignatureScheme.ecdsa_secp256r1_sha256,
            signature: signature.derRepresentation
        )
        appendToTranscript(cv)

        let serverFinishedVerify = kd.serverFinishedPayload(
            serverTrafficSecret: keys.serverTrafficSecret,
            transcript: handshake.transcript
        )
        let fin = TLSServerHelloBuilder.buildFinished(verifyData: serverFinishedVerify)
        appendToTranscript(fin)

        var combined = Data()
        combined.append(ee)
        combined.append(cert)
        combined.append(cv)
        combined.append(fin)

        let encrypted = try encryptHandshakeRecord(content: combined, contentType: TLSContentType.handshake, keys: keys, kd: kd)
        delegate?.tlsServer(self, didProduceOutput: encrypted)

        state = .waitingClientFinished
    }

    // MARK: - Client Finished

    private func processClientFinished() throws {
        guard let record = try peekTLSRecord() else { return }
        rxBuffer.removeFirst(record.count)

        let contentType = record[record.startIndex]
        if contentType == TLSContentType.changeCipherSpec {
            try processClientFinished()
            return
        }
        guard contentType == TLSContentType.applicationData else {
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

        let plaintext = try TLSRecordCrypto.decryptRecord(
            ciphertext: ciphertext,
            key: SymmetricKey(data: keys.clientKey),
            iv: keys.clientIV,
            seqNum: seqNum,
            recordHeader: header,
            cipherSuite: chosenCipherSuite
        )

        clientHandshakeMessages.append(plaintext)
        try parseClientHandshakeMessages(keys: keys, kd: kd, hsSecret: hsSecret)
    }

    private func parseClientHandshakeMessages(
        keys: TLS13HandshakeKeys,
        kd: TLS13KeyDerivation,
        hsSecret: Data
    ) throws {
        let buffer = clientHandshakeMessages
        var offset = buffer.startIndex
        defer {
            clientHandshakeMessages = Data(buffer[offset...])
        }
        while offset + 4 <= buffer.endIndex {
            let msgType = buffer[offset]
            let length = (Int(buffer[offset + 1]) << 16)
                    | (Int(buffer[offset + 2]) << 8)
                    | Int(buffer[offset + 3])
            // Length field is uint24; cap below 0xFFFF (not RFC-mandated) to bound allocations.
            guard length <= 0xFFFF else {
                throw TLSError.handshakeFailed("handshake message too large")
            }
            let total = 4 + length
            guard offset + total <= buffer.endIndex else { return }

            let message = buffer[offset..<(offset + total)]
            switch msgType {
            case TLSHandshakeType.finished:
                let received = Data(message.suffix(length))

                let expected = kd.clientFinishedPayload(
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

                // The application traffic secrets derive from the transcript through
                // the server Finished, excluding the client Finished.
                let appKeys = kd.deriveApplicationKeys(
                    handshakeSecret: hsSecret,
                    fullTranscript: handshake.transcript
                )
                handshake.applicationKeys = appKeys
                handshake.transcript.append(message)
                offset += total

                completeHandshake(applicationKeys: appKeys)
                return

            default:
                handshake.transcript.append(message)
                offset += total
            }
        }
    }

    private func completeHandshake(applicationKeys: TLS13ApplicationKeys) {
        let record = TLSRecordConnection(
            clientKey: applicationKeys.clientKey,
            clientIV: applicationKeys.clientIV,
            serverKey: applicationKeys.serverKey,
            serverIV: applicationKeys.serverIV,
            cipherSuite: chosenCipherSuite,
            clientAppSecret: applicationKeys.clientTrafficSecret,
            serverAppSecret: applicationKeys.serverTrafficSecret,
            direction: .server
        )
        record.negotiatedALPN = negotiatedALPN
        let trailer = rxBuffer
        rxBuffer = Data()

        state = .established
        delegate?.tlsServer(
            self,
            didCompleteHandshake: record,
            sni: sni ?? "",
            alpn: negotiatedALPN,
            clientFinishedHandshakeTrailer: trailer
        )
    }

    // MARK: - Output Helpers

    func emitPlainHandshakeRecord(_ payload: Data) {
        var record = Data(capacity: 5 + payload.count)
        record.append(TLSContentType.handshake)
        record.append(0x03); record.append(0x03)
        record.append(UInt8((payload.count >> 8) & 0xFF))
        record.append(UInt8(payload.count & 0xFF))
        record.append(payload)
        delegate?.tlsServer(self, didProduceOutput: record)
    }

    private func emitChangeCipherSpec() {
        let ccs = Data([TLSContentType.changeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01])
        delegate?.tlsServer(self, didProduceOutput: ccs)
    }

    private func encryptHandshakeRecord(
        content: Data,
        contentType: UInt8,
        keys: TLS13HandshakeKeys,
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
            TLSContentType.applicationData, 0x03, 0x03,
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

    private func synthesizeMessageHashRecord(hash: Data) -> Data {
        var out = Data()
        out.append(TLSHandshakeType.messageHash)
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

    func sendAlertAndFail(level: UInt8, description: UInt8, message: String) {
        let alert = TLSServerHelloBuilder.alert(level: level, description: description)
        var record = Data(capacity: 5 + alert.count)
        record.append(TLSContentType.alert)
        record.append(0x03); record.append(0x03)
        record.append(UInt8((alert.count >> 8) & 0xFF))
        record.append(UInt8(alert.count & 0xFF))
        record.append(alert)
        delegate?.tlsServer(self, didProduceOutput: record)
        failHandshake(.handshakeFailed(message))
    }

    // MARK: - Record Framing

    func peekTLSRecord() throws -> Data? {
        guard rxBuffer.count >= 5 else { return nil }
        let length = (Int(rxBuffer[rxBuffer.startIndex + 3]) << 8)
                | Int(rxBuffer[rxBuffer.startIndex + 4])
        guard length <= 16384 + 256 else {
            throw TLSError.handshakeFailed("record length \(length) out of bounds")
        }
        let total = 5 + length
        guard rxBuffer.count >= total else { return nil }
        return rxBuffer.subdata(in: rxBuffer.startIndex..<(rxBuffer.startIndex + total))
    }

    /// Upper bound on a reassembled ClientHello; larger is treated as bogus rather than buffered.
    private static let maxClientHelloBytes = 64 * 1024

    /// Reassembles a (possibly record-fragmented) ClientHello from the head of `rxBuffer`, returning
    /// the bare handshake-message bytes (msg-type + 3-byte length + body). Consumes only the records
    /// it uses; returns nil (leaving `rxBuffer` intact) when more records are needed.
    private func peekReassembledClientHello() throws -> Data? {
        var payload = Data()
        var offset = 0                  // bytes scanned from rxBuffer.startIndex
        var messageLength: Int?         // 4 + bodyLen, once the handshake header is in hand
        let available = rxBuffer.count
        let base = rxBuffer.startIndex
        while true {
            guard available - offset >= 5 else { return nil }
            let h = rxBuffer.index(base, offsetBy: offset)
            guard rxBuffer[h] == TLSContentType.handshake else {
                throw TLSError.handshakeFailed("Expected handshake record")
            }
            let length = (Int(rxBuffer[rxBuffer.index(h, offsetBy: 3)]) << 8)
                    | Int(rxBuffer[rxBuffer.index(h, offsetBy: 4)])
            // Reject zero-length records: they never advance `messageLength`, so the per-message cap
            // never fires and a flood of them would grow rxBuffer without bound.
            guard length > 0, length <= 16384 + 256 else {
                throw TLSError.handshakeFailed("record length \(length) out of bounds")
            }
            let recordTotal = 5 + length
            guard available - offset >= recordTotal else { return nil }
            let payloadStart = rxBuffer.index(h, offsetBy: 5)
            let payloadEnd = rxBuffer.index(payloadStart, offsetBy: length)
            payload.append(rxBuffer.subdata(in: payloadStart..<payloadEnd))
            offset += recordTotal
            if messageLength == nil, payload.count >= 4 {
                let b = payload.startIndex
                guard payload[b] == TLSHandshakeType.clientHello else {
                    throw TLSError.handshakeFailed("Expected ClientHello")
                }
                let bodyLen = (Int(payload[payload.index(b, offsetBy: 1)]) << 16)
                            | (Int(payload[payload.index(b, offsetBy: 2)]) << 8)
                            | Int(payload[payload.index(b, offsetBy: 3)])
                let total = 4 + bodyLen
                guard total <= Self.maxClientHelloBytes else {
                    throw TLSError.handshakeFailed("ClientHello too large (\(total) B)")
                }
                messageLength = total
            }
            if let total = messageLength, payload.count >= total {
                rxBuffer.removeFirst(offset)
                let start = payload.startIndex
                return payload.subdata(in: start..<payload.index(start, offsetBy: total))
            }
        }
    }

}
