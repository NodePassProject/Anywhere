//
//  TLSServer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security

/// Lifecycle callbacks for ``TLSServer``.
protocol TLSServerDelegate: AnyObject {
    /// One or more bytes of handshake-layer output are ready to be flushed to the client.
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

/// Server-side TLS 1.2/1.3 handshake driver; the version is selected per-handshake.
nonisolated final class TLSServer {

    // MARK: - State

    private enum State {
        case waitingClientHello
        case waitingClientHelloAfterHRR
        case sentServerHello        // TLS 1.3
        case waitingClientFinished
        // TLS 1.2: sent ServerHello/Cert/SKE/SHD; awaiting CKE + CCS + Finished
        case sentServerHelloDone12
        case established
        case failed
    }

    private enum TLS12ECDHEKey {
        case x25519(Curve25519.KeyAgreement.PrivateKey)
        case p256(P256.KeyAgreement.PrivateKey)
        case p384(P384.KeyAgreement.PrivateKey)

        var namedCurve: UInt16 {
            switch self {
            case .x25519: return 0x001D
            case .p256: return 0x0017
            case .p384: return 0x0018
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
            case 0x001D:
                return .x25519(Curve25519.KeyAgreement.PrivateKey())
            case 0x0017:
                return .p256(P256.KeyAgreement.PrivateKey())
            case 0x0018:
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

    weak var delegate: TLSServerDelegate?

    private let leafCert: SecCertificate
    private let leafCertDER: Data
    private let leafPrivateKey: SecKey
    private let leafSigningKeyP256: P256.Signing.PrivateKey
    private let preferredCipherSuites: [UInt16]
    private let preferredCipherSuites12: [UInt16]
    private let acceptableTLSVersions: Set<UInt16>

    /// ALPN protocols willing to negotiate, in preference order.
    private let acceptableALPNs: [String]

    /// Negotiated ALPN — locked in on the first ClientHello; HRR cannot change it.
    private var negotiatedALPN: String = ""

    private var state: State = .waitingClientHello

    private var rxBuffer = Data()

    private var sni: String?
    private var ephemeralKey: Curve25519.KeyAgreement.PrivateKey?
    private var ephemeralKey12: TLS12ECDHEKey?
    private var chosenCipherSuite: UInt16 = 0
    /// 0x0303 = TLS 1.2, 0x0304 = TLS 1.3.
    private var negotiatedTLSVersion: UInt16 = 0
    private var sessionID: Data = Data()
    private var handshake = TLS13ServerHandshakeState()
    private var handshake12 = TLS12ServerHandshakeState()
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
        guard let record = try peekTLSRecord() else { return }
        guard record[record.startIndex] == 0x16 else {
            throw TLSError.handshakeFailed("Expected handshake record")
        }
        rxBuffer.removeFirst(record.count)

        let parsed = try TLSClientHelloParser.parse(record)

        // RFC 7301 §3.2: no client ALPN offer → proceed without echoing the
        // extension; only fail when an offered list has no overlap.
        if !parsed.alpnProtocols.isEmpty {
            guard let alpn = acceptableALPNs.first(where: { parsed.alpnProtocols.contains($0) }) else {
                sendAlertAndFail(level: 2, description: 120, message: "no overlapping ALPN") // no_application_protocol
                return
            }
            if negotiatedALPN.isEmpty {
                negotiatedALPN = alpn
            }
        }

        // RFC 8446 §4.2.1: supported_versions takes precedence over legacy_version.
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
            sendAlertAndFail(level: 2, description: 70, message: "no acceptable TLS version")  // protocol_version
        }
    }

    private func processClientHelloTLS13(parsed: TLSClientHelloParsed) throws {
        negotiatedTLSVersion = 0x0304

        guard parsed.signatureAlgorithms.contains(0x0403) else {
            sendAlertAndFail(level: 2, description: 40, message: "ecdsa_secp256r1_sha256 required") // handshake_failure
            return
        }

        guard let suite = preferredCipherSuites.first(where: { parsed.cipherSuites.contains($0) }) else {
            sendAlertAndFail(level: 2, description: 40, message: "no shared cipher")
            return
        }
        chosenCipherSuite = suite

        if let clientKeyShare = parsed.keyShares[0x001D] {
            try sendServerHello(
                parsed: parsed,
                clientKeyShare: clientKeyShare,
                cipherSuite: suite
            )
        } else {
            if state == .waitingClientHelloAfterHRR {
                sendAlertAndFail(level: 2, description: 40, message: "client did not honor HRR")
                return
            }
            sendHelloRetryRequest(parsed: parsed, cipherSuite: suite)
        }
    }

    private func sendHelloRetryRequest(parsed: TLSClientHelloParsed, cipherSuite: UInt16) {
        // RFC 8446 §4.4.1: the first ClientHello is replaced in the transcript
        // by a synthetic message_hash record holding HASH(ClientHello1).
        firstClientHelloBytes = parsed.handshakeMessage
        sessionID = parsed.legacySessionID

        let kd = TLS13KeyDerivation(cipherSuite: cipherSuite)
        let firstHash = kd.transcriptHash(parsed.handshakeMessage)
        let synthetic = synthesizeMessageHashRecord(hash: firstHash)

        handshake.transcript = synthetic

        let hrr = TLSServerHelloBuilder.buildHelloRetryRequest(
            legacySessionID: parsed.legacySessionID,
            cipherSuite: cipherSuite,
            requestedGroup: 0x001D
        )
        handshake.transcript.append(hrr)
        handshake.keyDerivation = kd

        emitPlainHandshakeRecord(hrr)
        // RFC 8446 §5.1: a compatibility CCS may be sent.
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

    /// Emits EE + Certificate + CertificateVerify + Finished in one encrypted record.
    private func emitServerEncryptedHandshake(keys: TLSHandshakeKeys, kd: TLS13KeyDerivation) throws {
        let ee = TLSServerHelloBuilder.buildEncryptedExtensions(alpn: negotiatedALPN.isEmpty ? nil : negotiatedALPN)
        appendToTranscript(ee)

        let cert = TLSServerHelloBuilder.buildCertificate(leafCertDER: leafCertDER)
        appendToTranscript(cert)

        let transcriptHash = kd.transcriptHash(handshake.transcript)
        let cvContext = TLSServerHelloBuilder.certificateVerifyContext(transcriptHash: transcriptHash)
        let signature = try leafSigningKeyP256.signature(for: cvContext)

        let cv = TLSServerHelloBuilder.buildCertificateVerify(
            signatureAlgorithm: 0x0403,
            signature: signature.derRepresentation
        )
        appendToTranscript(cv)

        let serverFinishedVerify = kd.computeServerFinishedVerifyData(
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

        let encrypted = try encryptHandshakeRecord(content: combined, contentType: 0x16, keys: keys, kd: kd)
        delegate?.tlsServer(self, didProduceOutput: encrypted)

        state = .waitingClientFinished
    }

    // MARK: - Client Finished

    private func processClientFinished() throws {
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

        // decryptRecord strips padding and the inner content-type byte;
        // only a handshake record is expected here, so its type isn't checked.
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

    /// Walks decrypted handshake messages; verifies Finished, ignores Certificate/CertificateVerify
    /// (client auth not requested).
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

                // RFC 8446 §7.1: application traffic secrets derive from the transcript
                // through server Finished, excluding client Finished — derive, then append.
                let appKeys = kd.deriveApplicationKeys(
                    handshakeSecret: hsSecret,
                    fullTranscript: handshake.transcript
                )
                handshake.applicationKeys = appKeys
                handshake.transcript.append(message)

                completeHandshake(applicationKeys: appKeys)
                return

            case 0x0B, 0x0F: // Certificate / CertificateVerify — ignored (no client auth)
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
        record.negotiatedALPN = negotiatedALPN
        // Any bytes remaining in rxBuffer are application data sent immediately after Finished.
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

    /// Synthetic message_hash record (RFC 8446 §4.4.1) used in HRR transcripts.
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

    /// Returns the next complete TLS record from `rxBuffer`, or `nil` if more bytes are needed.
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

    // MARK: - TLS 1.2 Handshake

    private func processClientHelloTLS12(parsed: TLSClientHelloParsed) throws {
        negotiatedTLSVersion = 0x0303
        sni = parsed.serverName

        guard let suite = preferredCipherSuites12.first(where: { parsed.cipherSuites.contains($0) }) else {
            sendAlertAndFail(level: 2, description: 40, message: "no shared TLS 1.2 cipher")
            return
        }
        chosenCipherSuite = suite

        // SKE signing requires ecdsa_secp256r1_sha256 (matches the ECDSA-P256 leaf);
        // an absent signature_algorithms list defaults to including it.
        if !parsed.signatureAlgorithms.isEmpty && !parsed.signatureAlgorithms.contains(0x0403) {
            sendAlertAndFail(level: 2, description: 40, message: "ecdsa_secp256r1_sha256 required (TLS 1.2)")
            return
        }

        var serverRandom = Data(count: 32)
        _ = serverRandom.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        let preferredGroups: [UInt16] = [0x001D, 0x0017, 0x0018]
        let candidateGroups = parsed.supportedGroups.isEmpty
            ? preferredGroups
            : preferredGroups.filter { parsed.supportedGroups.contains($0) }
        guard let namedCurve = candidateGroups.first,
              let serverPriv = TLS12ECDHEKey.generate(namedCurve: namedCurve) else {
            sendAlertAndFail(level: 2, description: 40, message: "no shared TLS 1.2 ECDHE group")
            return
        }
        ephemeralKey12 = serverPriv

        handshake12.clientRandom = parsed.random
        handshake12.serverRandom = serverRandom
        handshake12.extendedMasterSecret = parsed.extendedMasterSecret

        handshake12.transcript = parsed.handshakeMessage

        // RFC 5246 §7.4.1.3: a fresh session_id (not echoing the client's) forces a full handshake.
        var newSessionID = Data(count: 32)
        _ = newSessionID.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
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

        let params = TLSServerHelloBuilder.serverECDHEParams(
            namedCurve: serverPriv.namedCurve,
            publicKey: serverPriv.publicKey
        )
        var signedContent = Data()
        signedContent.append(parsed.random)
        signedContent.append(serverRandom)
        signedContent.append(params)
        let signature = try leafSigningKeyP256.signature(for: signedContent)
        let ske = TLSServerHelloBuilder.buildServerKeyExchange(
            params: params,
            signatureAlgorithm: 0x0403,
            signature: signature.derRepresentation
        )
        handshake12.transcript.append(ske)

        let shd = TLSServerHelloBuilder.buildServerHelloDone()
        handshake12.transcript.append(shd)

        emitPlainHandshakeRecord(serverHello)
        emitPlainHandshakeRecord(cert)
        emitPlainHandshakeRecord(ske)
        emitPlainHandshakeRecord(shd)

        state = .sentServerHelloDone12
    }

    private func processClientHandshakeMessages12() throws {
        while state == .sentServerHelloDone12, let record = try peekTLSRecord() {
            let contentType = record[record.startIndex]
            let payload = record.subdata(in: (record.startIndex + 5)..<record.endIndex)
            rxBuffer.removeFirst(record.count)

            switch contentType {
            case 0x16: // Handshake
                if !handshake12.receivedCCS {
                    try handleClientKeyExchange12(payload)
                } else {
                    try handleClientFinished12(payload)
                }
            case 0x14: // ChangeCipherSpec
                handshake12.receivedCCS = true
            case 0x15: // Alert
                let level = payload.count > 0 ? payload[payload.startIndex] : 0
                let desc = payload.count > 1 ? payload[payload.startIndex + 1] : 0
                throw TLSError.handshakeFailed("client TLS 1.2 alert level=\(level) desc=\(desc) (\(alertDescriptionName(desc)))")
            default:
                throw TLSError.handshakeFailed("unexpected content type \(contentType) during TLS 1.2 handshake")
            }
        }
    }

    private func handleClientKeyExchange12(_ recordBody: Data) throws {
        // Handshake message header: type(1) + length(3).
        guard recordBody.count >= 4 else {
            throw TLSError.handshakeFailed("ClientKeyExchange too short")
        }
        let msgType = recordBody[recordBody.startIndex]
        guard msgType == 0x10 else {
            throw TLSError.handshakeFailed("expected ClientKeyExchange, got \(msgType)")
        }
        let len = (Int(recordBody[recordBody.startIndex + 1]) << 16)
                | (Int(recordBody[recordBody.startIndex + 2]) << 8)
                | Int(recordBody[recordBody.startIndex + 3])
        guard recordBody.count >= 4 + len else {
            throw TLSError.handshakeFailed("ClientKeyExchange truncated")
        }

        let body = recordBody.subdata(in: (recordBody.startIndex + 4)..<(recordBody.startIndex + 4 + len))
        // ECDHE CKE body: opaque public_key<1..255> (length-prefixed).
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

        let cke = recordBody.subdata(in: recordBody.startIndex..<(recordBody.startIndex + 4 + len))
        handshake12.transcript.append(cke)

        let useSHA384 = TLSCipherSuite.usesSHA384(chosenCipherSuite)
        let ms: Data
        if handshake12.extendedMasterSecret {
            let sessionHash = TLS12KeyDerivation.transcriptHash(handshake12.transcript, useSHA384: useSHA384)
            ms = TLS12KeyDerivation.extendedMasterSecret(
                preMasterSecret: preMaster,
                sessionHash: sessionHash,
                useSHA384: useSHA384
            )
        } else {
            ms = TLS12KeyDerivation.masterSecret(
                preMasterSecret: preMaster,
                clientRandom: handshake12.clientRandom!,
                serverRandom: handshake12.serverRandom!,
                useSHA384: useSHA384
            )
        }
        handshake12.masterSecret = ms

        let macLen = TLSCipherSuite.macLength(chosenCipherSuite)
        let keyLen = TLSCipherSuite.keyLength(chosenCipherSuite)
        let ivLen = TLSCipherSuite.ivLength(chosenCipherSuite)
        handshake12.keys = TLS12KeyDerivation.keysFromMasterSecret(
            masterSecret: ms,
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
            contentType: 0x16,
            seqNum: 0,
            keys: keys
        )

        guard plaintext.count >= 16, plaintext[plaintext.startIndex] == 0x14 else {
            throw TLSError.handshakeFailed("expected Finished message")
        }
        let received = plaintext.subdata(in: (plaintext.startIndex + 4)..<(plaintext.startIndex + 16))

        let useSHA384 = TLSCipherSuite.usesSHA384(chosenCipherSuite)
        let transcriptHash = TLS12KeyDerivation.transcriptHash(handshake12.transcript, useSHA384: useSHA384)
        let expected = TLS12KeyDerivation.computeFinishedVerifyData(
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

        // Append Client Finished to transcript before computing server verify_data.
        let cf = plaintext.subdata(in: plaintext.startIndex..<(plaintext.startIndex + 16))
        handshake12.transcript.append(cf)

        let serverTranscriptHash = TLS12KeyDerivation.transcriptHash(handshake12.transcript, useSHA384: useSHA384)
        let serverVerify = TLS12KeyDerivation.computeFinishedVerifyData(
            masterSecret: ms,
            label: "server finished",
            handshakeHash: serverTranscriptHash,
            useSHA384: useSHA384
        )
        let finished = TLSServerHelloBuilder.buildFinished12(verifyData: serverVerify)
        let encryptedFinished = try encryptTLS12HandshakeRecord(
            plaintext: finished,
            contentType: 0x16,
            seqNum: 0,
            keys: keys
        )

        var output = Data()
        output.append(contentsOf: [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]) // CCS
        output.append(encryptedFinished)
        delegate?.tlsServer(self, didProduceOutput: output)

        completeHandshake12(keys: keys)
    }

    private func completeHandshake12(keys: TLS12Keys) {
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
    // One-shot encrypt/decrypt for the Finished exchange, before the long-lived
    // TLSRecordConnection exists.

    private func encryptTLS12HandshakeRecord(
        plaintext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        keys: TLS12Keys
    ) throws -> Data {
        let version: UInt16 = 0x0303
        let isChaCha = TLSCipherSuite.isChaCha20(chosenCipherSuite)
        let symKey = SymmetricKey(data: keys.serverKey)

        let nonce: Data
        let explicitNonce: Data
        if isChaCha {
            var n = keys.serverIV
            n.withUnsafeMutableBytes { ptr in
                let p = ptr.bindMemory(to: UInt8.self)
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

    private func alertDescriptionName(_ desc: UInt8) -> String {
        switch desc {
        case 0: return "close_notify"
        case 10: return "unexpected_message"
        case 20: return "bad_record_mac"
        case 22: return "record_overflow"
        case 40: return "handshake_failure"
        case 42: return "bad_certificate"
        case 43: return "unsupported_certificate"
        case 44: return "certificate_revoked"
        case 45: return "certificate_expired"
        case 46: return "certificate_unknown"
        case 47: return "illegal_parameter"
        case 48: return "unknown_ca"
        case 49: return "access_denied"
        case 50: return "decode_error"
        case 51: return "decrypt_error"
        case 70: return "protocol_version"
        case 71: return "insufficient_security"
        case 80: return "internal_error"
        case 86: return "inappropriate_fallback"
        case 90: return "user_canceled"
        case 109: return "missing_extension"
        case 110: return "unsupported_extension"
        case 112: return "unrecognized_name"
        case 113: return "bad_certificate_status_response"
        case 116: return "certificate_required"
        case 120: return "no_application_protocol"
        default:  return "unknown"
        }
    }

    private func decryptTLS12HandshakeRecord(
        ciphertext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        keys: TLS12Keys
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
            n.withUnsafeMutableBytes { ptr in
                let p = ptr.bindMemory(to: UInt8.self)
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
