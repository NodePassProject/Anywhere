//
//  QUICTLSHandler.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization
import CryptoKit
import Security
import AnywhereQUIC

nonisolated private let logger = AnywhereLogger(category: "QUICTLSHandler")

// MARK: - Session Ticket Cache

nonisolated struct QUICSessionTicket {
    let ticket: Data
    let nonce: Data
    let psk: Data
    let cipherSuite: UInt16
    let issued: CFAbsoluteTime
    let lifetime: UInt32
    let ticketAgeAdd: UInt32
    let issuedInsecure: Bool
}

extension QUICSessionTicket {
    nonisolated static let maxLifetime = UInt32(604800)
}

nonisolated enum QUICSessionTicketCache {
    private static let cache = Mutex<[String: QUICSessionTicket]>([:])
    private static let maxEntries = 64

    private static func key(serverName: String, alpn: [String]) -> String {
        "\(serverName)\u{0}\(alpn.joined(separator: ","))"
    }

    static func lookup(serverName: String, alpn: [String]) -> QUICSessionTicket? {
        let k = key(serverName: serverName, alpn: alpn)
        return cache.withLock { $0[k] }
    }

    static func store(_ ticket: QUICSessionTicket, serverName: String, alpn: [String]) {
        let k = key(serverName: serverName, alpn: alpn)
        cache.withLock { cache in
            cache[k] = ticket
            guard cache.count > maxEntries else { return }
            let now = CFAbsoluteTimeGetCurrent()
            cache = cache.filter { now - $0.value.issued < Double($0.value.lifetime) }
            while cache.count > maxEntries,
                  let oldest = cache.min(by: { $0.value.issued < $1.value.issued })?.key {
                cache.removeValue(forKey: oldest)
            }
        }
    }

    static func invalidate(serverName: String, alpn: [String]) {
        let k = key(serverName: serverName, alpn: alpn)
        cache.withLock { _ = $0.removeValue(forKey: k) }
    }
}

nonisolated enum QUICTLSResult {
    case success
    case needMoreData
    case error
}

nonisolated final class QUICTLSHandler: QUICTLSProvider {

    // MARK: - State

    enum Phase: PhaseTransitionable {
        case initial
        case clientHelloSent
        case serverHelloReceived
        case completed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.initial, .clientHelloSent),
                 (.clientHelloSent, .serverHelloReceived),
                 (.serverHelloReceived, .completed):
                return true
            default:
                return false
            }
        }
    }

    // MARK: - Properties

    private let serverName: String
    private let alpn: [String]
    private var phase: Phase = .initial

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        Phase.transition(&phase, to: new)
    }

    private var builtClientHello: Data?

    private var keyDerivation: TLS13KeyDerivation?
    private var handshakeSecret: Data?
    private var clientHandshakeTrafficSecret: Data?
    private var serverHandshakeTrafficSecret: Data?
    private var exporterMasterSecret: Data?

    private var privateKeyP256: P256.KeyAgreement.PrivateKey?
    private var privateKeyX25519: Curve25519.KeyAgreement.PrivateKey?
    private var clientRandom = Data(count: 32)
    
    private var transcript = Data()

    private(set) var cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256
    
    private var actions: [QUICHandshakeAction] = []

    private var cryptoBuffer = Data()
    private var cryptoBufferLevel: QUICEncryptionLevel?

    private var serverCertificates: [SecCertificate] = []
    private var serverCertificateData: [Data] = []
    private var isAwaitingPeerVerification = false
    private var transcriptBeforeCertVerify: Data?
    private var transcriptBeforeServerFinished: Data?
    private var certificateVerifyAlgorithm: UInt16 = 0
    private var certificateVerifySignature: Data?

    private var resumptionMasterSecret: Data?
    private var activePSK: Data?
    private var offeredPSKCipherSuite: UInt16?
    private var pskAccepted = false
    private var pskBinderLength: Int = 0
    private var offeredTicketInsecure = false
    private var authenticatedInsecurely = false

    private(set) var peerQUICTransportParameters: Data?

    private(set) var negotiatedALPN: String?

    private(set) var handshakeError: Error?

    // MARK: - Initialization

    init(serverName: String, alpn: [String]) {
        self.serverName = serverName
        self.alpn = alpn

        privateKeyP256 = P256.KeyAgreement.PrivateKey()
        privateKeyX25519 = Curve25519.KeyAgreement.PrivateKey()

        _ = clientRandom.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
        }
    }

    func exportKeyingMaterial(label: String, context: Data, length: Int) throws -> Data {
        guard phase == .completed, let keyDerivation, let exporterMasterSecret, length > 0 else {
            throw AnywhereError.quic(.connectionFailed(detail: "TLS exporter unavailable"))
        }
        return keyDerivation.exportKeyingMaterial(
            exporterMasterSecret: exporterMasterSecret,
            label: label,
            context: context,
            length: length
        )
    }

    // MARK: - Build ClientHello

    func buildClientHello(transportParams: Data) -> Data? {
        if phase == .clientHelloSent, let cached = builtClientHello {
            return cached
        }
        guard phase == .initial else { return nil }
        guard let privateKeyP256, let privateKeyX25519 else { return nil }

        serverCertificates.removeAll()
        transcriptBeforeCertVerify = nil
        certificateVerifySignature = nil
        certificateVerifyAlgorithm = 0
        handshakeError = nil

        let p256Public = privateKeyP256.publicKey.x963Representation
        let x25519Public = privateKeyX25519.publicKey.rawRepresentation

        let keyShares: [(group: UInt16, keyData: Data)] = [
            (TLSNamedGroup.x25519, x25519Public),
            (TLSNamedGroup.secp256, p256Public),
        ]

        var pskExtData: Data?
        var candidatePSK: Data?
        var candidateCipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256

        let cachedTicket = QUICSessionTicketCache.lookup(serverName: serverName, alpn: alpn)

        if let ticket = cachedTicket,
           CFAbsoluteTimeGetCurrent() - ticket.issued < Double(ticket.lifetime),
           !ticket.issuedInsecure || CertificatePolicy.allowInsecure {
            let (extData, binderLen) = buildPSKExtension(ticket: ticket)
            pskExtData = extData
            pskBinderLength = binderLen
            candidatePSK = ticket.psk
            candidateCipherSuite = ticket.cipherSuite
            offeredTicketInsecure = ticket.issuedInsecure
        }

        var clientHello = TLSClientHelloBuilder.buildQUICClientHello(
            random: clientRandom,
            serverName: serverName,
            alpn: alpn,
            keyShares: keyShares,
            quicTransportParams: transportParams,
            pskExtension: pskExtData
        )

        if let psk = candidatePSK, pskBinderLength > 0 {
            patchPSKBinder(clientHello: &clientHello, binderLen: pskBinderLength,
                           psk: psk, cipherSuite: candidateCipherSuite)
            activePSK = psk
            offeredPSKCipherSuite = candidateCipherSuite
        }

        transcript.append(clientHello)
        builtClientHello = clientHello
        transition(to: .clientHelloSent)

        return clientHello
    }

    // MARK: - Failure Reporting

    private func fail(_ reason: String, error: Error? = nil) -> QUICTLSResult {
        if handshakeError == nil {
            handshakeError = error ?? AnywhereError.tls(.handshakeFailed(detail: reason))
        }
        return .error
    }

    // MARK: - Process Crypto Data
    
    func startHandshake(localTransportParameters: Data) throws -> [QUICHandshakeAction] {
        guard let hello = buildClientHello(transportParams: localTransportParameters) else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Unable to build QUIC ClientHello"))
        }
        return [.sendCryptoData(hello, level: .initial)]
    }

    func receiveCryptoData(_ data: Data, at level: QUICEncryptionLevel) throws -> [QUICHandshakeAction] {
        actions.removeAll(keepingCapacity: true)
        if case .error = processCryptoData(data, level: level) {
            actions.removeAll(keepingCapacity: true)
            throw handshakeError ?? AnywhereError.tls(.handshakeFailed(detail: "QUIC TLS handshake failed"))
        }
        let result = actions
        actions.removeAll(keepingCapacity: true)
        return result
    }

    private func processCryptoData(_ data: Data, level: QUICEncryptionLevel) -> QUICTLSResult {
        if !cryptoBuffer.isEmpty, let bufferedLevel = cryptoBufferLevel, bufferedLevel != level {
            return fail("handshake message split across encryption levels (\(bufferedLevel) → \(level))")
        }
        cryptoBufferLevel = level
        cryptoBuffer.append(data)

        while cryptoBuffer.count >= 4 {
            guard !isAwaitingPeerVerification else {
                return fail("handshake data after server Finished at level \(level)")
            }
            let startIndex = cryptoBuffer.startIndex
            let msgType = cryptoBuffer[startIndex]
            let msgLen = (Int(cryptoBuffer[startIndex + 1]) << 16)
            | (Int(cryptoBuffer[startIndex + 2]) << 8)
            |  Int(cryptoBuffer[startIndex + 3])
            
            guard msgLen <= 0xFFFF else {
                return fail("handshake message too long (type \(msgType), \(msgLen) B, level \(level))")
            }
            if let expected = QUICTLSHandler.expectedLevel(for: msgType), level != expected {
                return fail("handshake message type \(msgType) at level \(level), expected \(expected)")
            }
            let totalLen = 4 + msgLen

            guard cryptoBuffer.count >= totalLen else {
                return .needMoreData
            }

            let message = Data(cryptoBuffer[startIndex..<(startIndex + totalLen)])
            cryptoBuffer = Data(cryptoBuffer.dropFirst(totalLen))

            if msgType == TLSHandshakeType.certificateVerify {
                transcriptBeforeCertVerify = transcript
            } else if msgType == TLSHandshakeType.finished {
                transcriptBeforeServerFinished = transcript
            }

            transcript.append(message)

            let body = message.count > 4 ? Data(message[4...]) : Data()
            let result = processHandshakeMessage(msgType: msgType, body: body,
                                                  fullMessage: message, level: level)
            if case .error = result {
                return result
            }
        }

        return .success
    }
    
    private static func expectedLevel(for msgType: UInt8) -> QUICEncryptionLevel? {
        switch msgType {
        case TLSHandshakeType.serverHello:
            return .initial
        case TLSHandshakeType.encryptedExtensions, TLSHandshakeType.certificate,
             TLSHandshakeType.certificateRequest, TLSHandshakeType.certificateVerify,
             TLSHandshakeType.finished:
            return .handshake
        case TLSHandshakeType.newSessionTicket:
            return .application
        default:
            return nil
        }
    }

    // MARK: - Process Individual Messages

    private func processHandshakeMessage(
        msgType: UInt8,
        body: Data,
        fullMessage: Data,
        level: QUICEncryptionLevel
    ) -> QUICTLSResult {
        switch msgType {
        case TLSHandshakeType.serverHello:         return processServerHello(body)
        case TLSHandshakeType.encryptedExtensions: return processEncryptedExtensions(body)
        case TLSHandshakeType.certificate:         return processCertificate(body)
        case TLSHandshakeType.certificateVerify:   return processCertificateVerify(body)
        case TLSHandshakeType.finished:            return processServerFinished(body)
        case TLSHandshakeType.newSessionTicket:    return processNewSessionTicket(body)
        default:
            logger.warning("[QUIC-TLS] Unknown message type: \(msgType)")
            return .success
        }
    }

    // MARK: - ServerHello

    private func processServerHello(_ body: Data) -> QUICTLSResult {
        guard phase == .clientHelloSent else {
            return fail("ServerHello in phase \(phase)")
        }
        guard body.count >= 35 else {
            return fail("ServerHello truncated (\(body.count) B)")
        }

        // ServerHello rules: HRR forbidden; echoed empty legacy session ID;
        // legacy version TLS 1.2; compression zero; negotiated version TLS 1.3.
        let legacyVersion = (UInt16(body[0]) << 8) | UInt16(body[1])
        guard legacyVersion == 0x0303 else {
            return fail(String(format: "ServerHello legacy version 0x%04x (expected 0x0303)", legacyVersion))
        }

        let serverRandom = Data(body[2..<34])
        if serverRandom == TLSRandom.helloRetryRequest {
            return fail("server sent HelloRetryRequest (unsupported)", error: AnywhereError.tls(.helloRetryRequest))
        }

        var offset = 34
        let sessionIdLen = Int(body[offset])
        guard sessionIdLen == 0 else {
            return fail("ServerHello echoed non-empty legacy session ID (\(sessionIdLen) B)")
        }
        offset += 1 + sessionIdLen

        guard offset + 2 <= body.count else {
            return fail("ServerHello truncated at cipher suite")
        }
        cipherSuite = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
        offset += 2

        switch cipherSuite {
        case TLSCipherSuite.TLS_AES_128_GCM_SHA256,
             TLSCipherSuite.TLS_AES_256_GCM_SHA384,
             TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            break
        default:
            return fail(String(format: "server selected unsupported cipher suite 0x%04x", cipherSuite))
        }

        guard offset < body.count, body[offset] == 0 else {
            return fail("ServerHello non-zero compression method")
        }
        offset += 1

        guard offset + 2 <= body.count else {
            return fail("ServerHello truncated at extensions length")
        }
        let extLen = (Int(body[offset]) << 8) | Int(body[offset + 1])
        offset += 2

        var serverKeyShareGroup: UInt16 = 0
        var serverPublicKey: Data?
        var supportedVersionsSeen = false
        var negotiatedVersion: UInt16 = 0
        var observedExtensionTypes = Set<UInt16>()
        let extEnd = offset + extLen
        while offset + 4 <= extEnd && offset + 4 <= body.count {
            let extType = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
            let extDataLen = (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
            offset += 4

            guard offset + extDataLen <= extEnd, offset + extDataLen <= body.count else {
                return fail(String(format: "ServerHello extension 0x%04x overruns message", extType))
            }

            let (inserted, _) = observedExtensionTypes.insert(extType)
            if !inserted {
                return fail(String(format: "duplicate ServerHello extension 0x%04x", extType))
            }

            if extType == TLSExtensionType.keyShare {
                if extDataLen >= 4 {
                    serverKeyShareGroup = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
                    let keyExchangeLen = (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
                    if 4 + keyExchangeLen <= extDataLen {
                        serverPublicKey = Data(body[(offset + 4)..<(offset + 4 + keyExchangeLen)])
                    }
                }
            } else if extType == TLSExtensionType.supportedVersions {
                if extDataLen >= 2 {
                    negotiatedVersion = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
                    supportedVersionsSeen = true
                }
            } else if extType == TLSExtensionType.preSharedKey {
                guard activePSK != nil, extDataLen >= 2,
                      (UInt16(body[offset]) << 8) | UInt16(body[offset + 1]) == 0 else {
                    return fail("invalid pre_shared_key extension in ServerHello")
                }
                pskAccepted = true
            }
            offset += extDataLen
        }

        guard supportedVersionsSeen, negotiatedVersion == 0x0304 else {
            return fail(supportedVersionsSeen
                ? String(format: "server negotiated 0x%04x, not TLS 1.3", negotiatedVersion)
                : "ServerHello missing supported_versions extension")
        }

        if pskAccepted {
            guard cipherSuite == offeredPSKCipherSuite else {
                return fail(String(format: "PSK accepted but cipher suite 0x%04x differs from ticket suite 0x%04x", cipherSuite, offeredPSKCipherSuite ?? 0))
            }
        }

        guard let serverPublicKey else {
            return fail("ServerHello missing key_share extension")
        }

        do {
            let sharedSecretData: Data
            switch serverKeyShareGroup {
            case TLSNamedGroup.x25519:
                guard let priv = privateKeyX25519 else {
                    return fail("internal: X25519 private key unavailable")
                }
                let serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKey)
                let shared = try priv.sharedSecretFromKeyAgreement(with: serverKey)
                sharedSecretData = shared.withUnsafeBytes { Data($0) }
            case TLSNamedGroup.secp256:
                guard let priv = privateKeyP256 else {
                    return fail("internal: P-256 private key unavailable")
                }
                let serverKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKey)
                let shared = try priv.sharedSecretFromKeyAgreement(with: serverKey)
                sharedSecretData = shared.withUnsafeBytes { Data($0) }
            default:
                return fail(String(format: "server chose unsupported key-share group 0x%04x", serverKeyShareGroup))
            }

            keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            if !pskAccepted { activePSK = nil }

            let (hsSecret, hsKeys) = keyDerivation!.deriveHandshakeKeys(
                sharedSecret: sharedSecretData, transcript: transcript,
                psk: activePSK
            )
            handshakeSecret = hsSecret
            clientHandshakeTrafficSecret = hsKeys.clientTrafficSecret
            serverHandshakeTrafficSecret = hsKeys.serverTrafficSecret

            actions.append(.installHandshakeKeys(
                cipherSuite: QUICCipherSuite(rawValue: cipherSuite)!,
                readSecret: hsKeys.serverTrafficSecret,
                writeSecret: hsKeys.clientTrafficSecret
            ))

            transition(to: .serverHelloReceived)
        } catch {
            return fail(String(format: "key agreement failed (group 0x%04x): %@", serverKeyShareGroup, String(describing: error)))
        }

        return .success
    }

    // MARK: - EncryptedExtensions

    private func processEncryptedExtensions(_ body: Data) -> QUICTLSResult {
        guard body.count >= 2 else { return .success }
        let extLen = (Int(body[0]) << 8) | Int(body[1])
        var offset = 2
        var observedExtensionTypes = Set<UInt16>()
        let extEnd = offset + extLen

        while offset + 4 <= extEnd && offset + 4 <= body.count {
            let extType = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
            let extDataLen = (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
            offset += 4

            guard offset + extDataLen <= extEnd, offset + extDataLen <= body.count else {
                return fail(String(format: "EncryptedExtensions extension 0x%04x overruns message", extType))
            }

            let (inserted, _) = observedExtensionTypes.insert(extType)
            if !inserted {
                return fail(String(format: "duplicate EncryptedExtensions extension 0x%04x", extType))
            }

            if extType == TLSExtensionType.quicTransportParameters {
                let parameters = Data(body[offset..<(offset + extDataLen)])
                peerQUICTransportParameters = parameters

                actions.append(.setRemoteTransportParameters(parameters))
            } else if extType == TLSExtensionType.applicationLayerProtocolNegotiation {
                if extDataLen >= 3 {
                    let listLen = (Int(body[offset]) << 8) | Int(body[offset + 1])
                    if listLen >= 1, 2 + listLen <= extDataLen {
                        let nameLen = Int(body[offset + 2])
                        if nameLen >= 1, 3 + nameLen <= extDataLen {
                            let nameStart = offset + 3
                            let nameData = Data(body[nameStart..<(nameStart + nameLen)])
                            negotiatedALPN = String(data: nameData, encoding: .utf8)
                        }
                    }
                }
            }
            offset += extDataLen
        }

        if !alpn.isEmpty {
            guard let picked = negotiatedALPN, alpn.contains(picked) else {
                return fail("ALPN mismatch: offered \(alpn), server selected \(negotiatedALPN ?? "nothing")")
            }
        }

        return .success
    }

    // MARK: - Server Finished

    private func processServerFinished(_ body: Data) -> QUICTLSResult {
        guard phase == .serverHelloReceived else {
            return fail("Finished in phase \(phase)")
        }
        guard let keyDerivation, handshakeSecret != nil, clientHandshakeTrafficSecret != nil else {
            return fail("internal: handshake secrets unavailable at server Finished")
        }

        let allowInsecure = CertificatePolicy.allowInsecure
        authenticatedInsecurely = pskAccepted ? offeredTicketInsecure : allowInsecure

        if !pskAccepted, !allowInsecure {
            if let error = TLS13CertificateVerifier.verify(
                transcriptBeforeCertVerify: transcriptBeforeCertVerify,
                algorithm: certificateVerifyAlgorithm,
                signature: certificateVerifySignature,
                serverCertificates: serverCertificates,
                keyDerivation: keyDerivation
            ) {
                logger.warning("[QUIC-TLS] CertificateVerify rejected: \(error.localizedDescription)")
                handshakeError = error
                return .error
            }
        }

        guard let serverHTS = serverHandshakeTrafficSecret,
              let preFinishedTranscript = transcriptBeforeServerFinished else {
            return fail("internal: transcript unavailable at server Finished")
        }
        let expectedServerFinished = keyDerivation.serverFinishedPayload(
            serverTrafficSecret: serverHTS, transcript: preFinishedTranscript
        )
        guard body == expectedServerFinished else {
            return fail("server Finished verification failed (transcript mismatch)")
        }

        guard pskAccepted || allowInsecure else {
            isAwaitingPeerVerification = true
            actions.append(.verifyPeer(certificates: serverCertificateData))
            return .success
        }
        return completeServerFinished()
    }

    func completePeerVerification(error: (any Error)?) throws -> [QUICHandshakeAction] {
        guard isAwaitingPeerVerification else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Unexpected peer verification result"))
        }
        isAwaitingPeerVerification = false
        if let error {
            logger.warning("[QUIC-TLS] Certificate validation failed: \(error.localizedDescription)")
            handshakeError = error
            throw error
        }
        actions.removeAll(keepingCapacity: true)
        if case .error = completeServerFinished() {
            actions.removeAll(keepingCapacity: true)
            throw handshakeError ?? AnywhereError.tls(.handshakeFailed(detail: "QUIC TLS handshake failed"))
        }
        let result = actions
        actions.removeAll(keepingCapacity: true)
        return result
    }

    private func completeServerFinished() -> QUICTLSResult {
        guard let keyDerivation, let handshakeSecret, let clientHTS = clientHandshakeTrafficSecret else {
            return fail("internal: handshake secrets unavailable at server Finished")
        }

        let application = keyDerivation.deriveApplicationMaterial(
            handshakeSecret: handshakeSecret, fullTranscript: transcript
        )
        exporterMasterSecret = application.exporterMasterSecret
        actions.append(.installApplicationKeys(
            cipherSuite: QUICCipherSuite(rawValue: cipherSuite)!,
            readSecret: application.keys.serverTrafficSecret,
            writeSecret: application.keys.clientTrafficSecret
        ))

        let verifyData = keyDerivation.finishedPayload(
            trafficSecret: clientHTS, transcript: transcript
        )
        let finishedMessage = buildFinishedMessage(verifyData: verifyData)

        actions.append(.sendCryptoData(finishedMessage, level: .handshake))
        actions.append(.handshakeComplete)
        transition(to: .completed)

        transcript.append(finishedMessage)
        let hsKey = SymmetricKey(data: handshakeSecret)
        let derivedHS = keyDerivation.deriveSecret(secret: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = keyDerivation.extract(
            inputKeyMaterial: Data(repeating: 0, count: keyDerivation.hashLength), salt: derivedHS
        )
        resumptionMasterSecret = keyDerivation.deriveSecret(
            secret: masterKey, label: "res master", messages: transcript
        )

        return .success
    }

    // MARK: - Session Tickets

    private func processNewSessionTicket(_ body: Data) -> QUICTLSResult {
        guard body.count >= 11 else { return .success }

        var offset = 0
        let rawLifetime = UInt32(body[0]) << 24 | UInt32(body[1]) << 16
                        | UInt32(body[2]) << 8  | UInt32(body[3])
        let lifetime = min(rawLifetime, QUICSessionTicket.maxLifetime)
        offset += 4

        let ticketAgeAdd = UInt32(body[offset]) << 24 | UInt32(body[offset + 1]) << 16
                   | UInt32(body[offset + 2]) << 8  | UInt32(body[offset + 3])
        offset += 4

        let nonceLen = Int(body[offset])
        offset += 1
        guard offset + nonceLen <= body.count else { return .success }
        let nonce = Data(body[offset..<(offset + nonceLen)])
        offset += nonceLen

        guard offset + 2 <= body.count else { return .success }
        let ticketLen = Int(body[offset]) << 8 | Int(body[offset + 1])
        offset += 2
        guard offset + ticketLen <= body.count else { return .success }
        let ticket = Data(body[offset..<(offset + ticketLen)])

        guard let kd = keyDerivation, let rms = resumptionMasterSecret else { return .success }
        let psk = kd.expandLabel(
            secret: SymmetricKey(data: rms),
            label: "resumption",
            context: nonce,
            length: kd.hashLength
        )

        let cached = QUICSessionTicket(
            ticket: ticket, nonce: nonce, psk: psk,
            cipherSuite: cipherSuite, issued: CFAbsoluteTimeGetCurrent(),
            lifetime: lifetime, ticketAgeAdd: ticketAgeAdd,
            issuedInsecure: authenticatedInsecurely
        )
        QUICSessionTicketCache.store(cached, serverName: serverName, alpn: alpn)

        return .success
    }

    // MARK: - PSK Extension Building
    
    private func buildPSKExtension(ticket: QUICSessionTicket) -> (extensionData: Data, binderLen: Int) {
        let ageMs = max(0, (CFAbsoluteTimeGetCurrent() - ticket.issued) * 1000)
        let ticketAgeMs = UInt32(min(ageMs, Double(UInt32.max)))
        let obfuscatedAge = ticketAgeMs &+ ticket.ticketAgeAdd

        var identities = Data()
        identities.append(UInt8(ticket.ticket.count >> 8))
        identities.append(UInt8(ticket.ticket.count & 0xFF))
        identities.append(ticket.ticket)
        identities.append(UInt8((obfuscatedAge >> 24) & 0xFF))
        identities.append(UInt8((obfuscatedAge >> 16) & 0xFF))
        identities.append(UInt8((obfuscatedAge >> 8) & 0xFF))
        identities.append(UInt8(obfuscatedAge & 0xFF))

        let kd = TLS13KeyDerivation(cipherSuite: ticket.cipherSuite)
        let binderLen = kd.hashLength

        var binders = Data()
        binders.append(UInt8(binderLen))
        binders.append(Data(repeating: 0, count: binderLen))

        var payload = Data()
        payload.append(UInt8(identities.count >> 8))
        payload.append(UInt8(identities.count & 0xFF))
        payload.append(identities)
        payload.append(UInt8(binders.count >> 8))
        payload.append(UInt8(binders.count & 0xFF))
        payload.append(binders)

        var ext = Data()
        ext.append(UInt8(TLSExtensionType.preSharedKey >> 8))
        ext.append(UInt8(TLSExtensionType.preSharedKey & 0xFF))
        ext.append(UInt8(payload.count >> 8))
        ext.append(UInt8(payload.count & 0xFF))
        ext.append(payload)

        return (ext, binderLen)
    }
    
    private func patchPSKBinder(clientHello: inout Data, binderLen: Int, psk: Data, cipherSuite ticketCipherSuite: UInt16) {
        let kd = TLS13KeyDerivation(cipherSuite: ticketCipherSuite)

        let (_, earlyKey) = kd.extract(inputKeyMaterial: psk, salt: Data())
        let binderKeySecret = kd.deriveSecret(secret: earlyKey, label: "res binder", messages: Data())
        let finishedKey = kd.expandLabel(
            secret: SymmetricKey(data: binderKeySecret),
            label: "finished",
            context: Data(),
            length: kd.hashLength
        )
        
        let truncatedSuffix = binderLen + 3
        guard clientHello.count >= truncatedSuffix else { return }
        let partial = Data(clientHello[0..<(clientHello.count - truncatedSuffix)])

        let transcriptHash = kd.transcriptHash(partial)

        let symKey = SymmetricKey(data: finishedKey)
        let binder: Data
        if ticketCipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            binder = Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: symKey))
        } else {
            binder = Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: symKey))
        }

        clientHello.replaceSubrange((clientHello.count - binderLen)..<clientHello.count, with: binder)
    }

    // MARK: - Certificate

    private func processCertificate(_ body: Data) -> QUICTLSResult {
        parseTLS13CertificateMessage(body)
        return .success
    }

    private func parseTLS13CertificateMessage(_ body: Data) {
        serverCertificates.removeAll()
        serverCertificateData.removeAll()
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

            let certData = Data(body[offset..<(offset + certLen)])
            offset += certLen

            if let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                serverCertificates.append(cert)
                serverCertificateData.append(certData)
            }

            guard offset + 2 <= listEnd else { break }
            let extLen = Int(body[offset]) << 8 | Int(body[offset + 1])
            offset += 2 + extLen
        }
    }

    // MARK: - CertificateVerify

    private func processCertificateVerify(_ body: Data) -> QUICTLSResult {
        guard body.count >= 4 else {
            return fail("CertificateVerify truncated (\(body.count) B)")
        }
        certificateVerifyAlgorithm = UInt16(body[0]) << 8 | UInt16(body[1])
        
        guard TLSClientHelloBuilder.quicSignatureAlgorithms.contains(certificateVerifyAlgorithm) else {
            return fail(String(format: "CertificateVerify uses signature algorithm 0x%04x", certificateVerifyAlgorithm))
        }

        let sigLen = Int(body[2]) << 8 | Int(body[3])
        guard body.count >= 4 + sigLen else {
            return fail("CertificateVerify signature truncated (\(sigLen) B declared, \(body.count - 4) B present)")
        }
        certificateVerifySignature = Data(body[4..<(4 + sigLen)])
        return .success
    }

    // MARK: - Certificate Validation

    static func verifyPeer(certificates: [Data], serverName: String) async -> Error? {
        let chain = certificates.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        switch await CertificatePolicy.verify(chain: chain, serverName: serverName) {
        case .trusted:
            return nil
        case .rejected(let reason):
            return AnywhereError.tls(.certificateValidationFailed(detail: reason))
        }
    }

    // MARK: - Helpers

    private func buildFinishedMessage(verifyData: Data) -> Data {
        var message = Data()
        message.append(TLSHandshakeType.finished)
        let length = verifyData.count
        message.append(UInt8((length >> 16) & 0xFF))
        message.append(UInt8((length >> 8) & 0xFF))
        message.append(UInt8(length & 0xFF))
        message.append(verifyData)
        return message
    }
}
