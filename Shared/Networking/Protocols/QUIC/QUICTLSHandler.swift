//
//  QUICTLSHandler.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "QUICTLSHandler")

// MARK: - Session Ticket Cache

/// A TLS session ticket.
///
/// This structure encodes all the information needed to resume a session.
struct QUICSessionTicket {
    let ticket: Data
    let nonce: Data
    let psk: Data
    let cipherSuite: UInt16
    let issued: CFAbsoluteTime
    let lifetime: UInt32
    let ticketAgeAdd: UInt32
}

extension QUICSessionTicket {
    /// The maximum cache lifetime allowed by RFC 8446.
    static let maxLifetime = UInt32(604800)
}

enum QUICSessionTicketCache {
    private static let lock = UnfairLock()
    private static var cache: [String: QUICSessionTicket] = [:]
    private static let maxEntries = 64

    private static func key(serverName: String, alpn: [String]) -> String {
        "\(serverName)\u{0}\(alpn.joined(separator: ","))"
    }

    static func lookup(serverName: String, alpn: [String]) -> QUICSessionTicket? {
        let k = key(serverName: serverName, alpn: alpn)
        lock.lock(); defer { lock.unlock() }
        return cache[k]
    }

    static func store(_ ticket: QUICSessionTicket, serverName: String, alpn: [String]) {
        let k = key(serverName: serverName, alpn: alpn)
        lock.lock(); defer { lock.unlock() }
        cache[k] = ticket
        guard cache.count > maxEntries else { return }
        let now = CFAbsoluteTimeGetCurrent()
        cache = cache.filter { now - $0.value.issued < Double($0.value.lifetime) }
        while cache.count > maxEntries,
              let oldest = cache.min(by: { $0.value.issued < $1.value.issued })?.key {
            cache.removeValue(forKey: oldest)
        }
    }

    static func invalidate(serverName: String, alpn: [String]) {
        let k = key(serverName: serverName, alpn: alpn)
        lock.lock(); defer { lock.unlock() }
        cache.removeValue(forKey: k)
    }
}

enum QUICTLSResult {
    case success
    case needMoreData
    case error(Int32)
}

nonisolated class QUICTLSHandler {

    // MARK: - State

    enum HandshakeState {
        case initial
        case clientHelloSent
        case serverHelloReceived
        case handshakeKeysInstalled
        case serverFinishedReceived
        case completed
    }

    // MARK: - Properties

    private let serverName: String
    private let alpn: [String]
    private var state: HandshakeState = .initial

    // Key derivation
    private var keyDerivation: TLS13KeyDerivation?
    private var handshakeSecret: Data?
    private var clientHandshakeTrafficSecret: Data?
    private var serverHandshakeTrafficSecret: Data?

    // ECDHE
    private var privateKeyP256: P256.KeyAgreement.PrivateKey?
    private var privateKeyX25519: Curve25519.KeyAgreement.PrivateKey?
    private var clientRandom = Data(count: 32)

    // Transcript (concatenation of all handshake messages)
    private var transcript = Data()

    private(set) var cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256

    // Accumulator for partial TLS messages
    private var cryptoBuffer = Data()

    // Certificate validation state
    private var serverCertificates: [SecCertificate] = []
    private var transcriptBeforeCertVerify: Data?
    private var transcriptBeforeServerFinished: Data?
    private var certificateVerifyAlgorithm: UInt16 = 0
    private var certificateVerifySignature: Data?

    // Session resumption
    private var resumptionMasterSecret: Data?
    private var activePSK: Data?
    private var offeredPSKCipherSuite: UInt16?
    private var pskAccepted = false
    private var pskBinderLength: Int = 0

    /// The value of the QUIC transport parameters set by the peer, if any.
    private(set) var peerQUICTransportParameters: Data?

    /// The value of the ALPN sent by the peer, if any.
    private(set) var negotiatedALPN: String?

    // MARK: - Initialization

    init(serverName: String, alpn: [String]) {
        self.serverName = serverName
        self.alpn = alpn

        privateKeyP256 = P256.KeyAgreement.PrivateKey()
        privateKeyX25519 = Curve25519.KeyAgreement.PrivateKey()

        _ = clientRandom.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, 32, buf.baseAddress!)
        }
    }

    // MARK: - Build ClientHello

    func buildClientHello(transportParams: Data) -> Data? {
        guard let privateKeyP256, let privateKeyX25519 else { return nil }

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
           CFAbsoluteTimeGetCurrent() - ticket.issued < Double(ticket.lifetime) {
            let (extData, binderLen) = buildPSKExtension(ticket: ticket)
            pskExtData = extData
            pskBinderLength = binderLen
            candidatePSK = ticket.psk
            candidateCipherSuite = ticket.cipherSuite
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
        state = .clientHelloSent

        return clientHello
    }

    // MARK: - Process Crypto Data

    /// Processes TLS handshake data received in a QUIC CRYPTO frame. Any bytes
    /// that don't form a complete message remain buffered for the next call.
    func processCryptoData(_ data: Data, level: ngtcp2_encryption_level,
                           conn: OpaquePointer) -> QUICTLSResult {
        cryptoBuffer.append(data)

        while cryptoBuffer.count >= 4 {
            let si = cryptoBuffer.startIndex
            let msgType = cryptoBuffer[si]
            let msgLen = (Int(cryptoBuffer[si + 1]) << 16)
                       | (Int(cryptoBuffer[si + 2]) << 8)
                       |  Int(cryptoBuffer[si + 3])

            // NOTE: this length limit is not RFC specified. The length field is a uint24, so can be larger.
            // Guard against erroneous handshake length values causing large memory allocations.
            guard msgLen <= 0xFFFF else {
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }
            let totalLen = 4 + msgLen

            guard cryptoBuffer.count >= totalLen else {
                return .needMoreData
            }

            let message = Data(cryptoBuffer[si..<(si + totalLen)])
            cryptoBuffer = Data(cryptoBuffer.dropFirst(totalLen))

            if msgType == TLSHandshakeType.certificateVerify {
                transcriptBeforeCertVerify = transcript
            } else if msgType == TLSHandshakeType.finished {
                // The server Finished verify_data covers the transcript up to but not
                // including the Finished itself.
                transcriptBeforeServerFinished = transcript
            }

            transcript.append(message)

            let body = message.count > 4 ? Data(message[4...]) : Data()
            let result = processHandshakeMessage(msgType: msgType, body: body,
                                                  fullMessage: message, level: level, conn: conn)
            if case .error = result {
                return result
            }
        }

        return .success
    }

    // MARK: - Process Individual Messages

    private func processHandshakeMessage(msgType: UInt8, body: Data, fullMessage: Data,
                                          level: ngtcp2_encryption_level,
                                          conn: OpaquePointer) -> QUICTLSResult {
        switch msgType {
        case TLSHandshakeType.serverHello:         return processServerHello(body, conn: conn)
        case TLSHandshakeType.encryptedExtensions: return processEncryptedExtensions(body, conn: conn)
        case TLSHandshakeType.certificate:         return processCertificate(body)
        case TLSHandshakeType.certificateVerify:   return processCertificateVerify(body)
        case TLSHandshakeType.finished:            return processServerFinished(body, conn: conn)
        case TLSHandshakeType.newSessionTicket:    return processNewSessionTicket(body)
        default:
            logger.warning("[QUIC-TLS] Unknown message type: \(msgType)")
            return .success
        }
    }

    // MARK: - ServerHello

    private func processServerHello(_ body: Data, conn: OpaquePointer) -> QUICTLSResult {
        guard body.count >= 35 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        // Let's validate this ServerHello. The rules:
        //
        // - helloRetryRequest is forbidden
        // - the server must have echoed our (empty) legacy session ID
        // - the legacy version number must be TLSv1.2
        // - the chosen compression option must be zero
        // - the supported version must be TLSV1.3
        let legacyVersion = (UInt16(body[0]) << 8) | UInt16(body[1])
        guard legacyVersion == 0x0303 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        let serverRandom = Data(body[2..<34])
        if serverRandom == TLSRandom.helloRetryRequest {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        var offset = 34
        let sessionIdLen = Int(body[offset])
        guard sessionIdLen == 0 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        offset += 1 + sessionIdLen

        guard offset + 2 <= body.count else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        cipherSuite = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
        offset += 2

        switch cipherSuite {
        case TLSCipherSuite.TLS_AES_128_GCM_SHA256,
             TLSCipherSuite.TLS_AES_256_GCM_SHA384,
             TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            break
        default:
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        guard offset < body.count, body[offset] == 0 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        offset += 1

        guard offset + 2 <= body.count else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
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
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }

            let (inserted, _) = observedExtensionTypes.insert(extType)
            if !inserted {
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
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
                    return .error(NGTCP2_ERR_CALLBACK_FAILURE)
                }
                pskAccepted = true
            }
            offset += extDataLen
        }

        guard supportedVersionsSeen, negotiatedVersion == 0x0304 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        if pskAccepted {
            guard cipherSuite == offeredPSKCipherSuite else {
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }
        }

        guard let serverPublicKey else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        do {
            let sharedSecretData: Data
            switch serverKeyShareGroup {
            case TLSNamedGroup.x25519:
                guard let priv = privateKeyX25519 else {
                    return .error(NGTCP2_ERR_CALLBACK_FAILURE)
                }
                let serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKey)
                let shared = try priv.sharedSecretFromKeyAgreement(with: serverKey)
                sharedSecretData = shared.withUnsafeBytes { Data($0) }
            case TLSNamedGroup.secp256:
                guard let priv = privateKeyP256 else {
                    return .error(NGTCP2_ERR_CALLBACK_FAILURE)
                }
                let serverKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKey)
                let shared = try priv.sharedSecretFromKeyAgreement(with: serverKey)
                sharedSecretData = shared.withUnsafeBytes { Data($0) }
            default:
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }

            keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            ngtcp2_conn_set_tls_native_handle(conn,
                UnsafeMutableRawPointer(bitPattern: UInt(cipherSuite)))

            if !pskAccepted { activePSK = nil }

            let (hsSecret, hsKeys) = keyDerivation!.deriveHandshakeKeys(
                sharedSecret: sharedSecretData, transcript: transcript,
                psk: activePSK
            )
            handshakeSecret = hsSecret
            clientHandshakeTrafficSecret = hsKeys.clientTrafficSecret
            serverHandshakeTrafficSecret = hsKeys.serverTrafficSecret

            installHandshakeKeys(conn: conn, keys: hsKeys)

            state = .serverHelloReceived

        } catch {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        return .success
    }

    // MARK: - EncryptedExtensions

    private func processEncryptedExtensions(_ body: Data, conn: OpaquePointer) -> QUICTLSResult {
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
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }

            let (inserted, _) = observedExtensionTypes.insert(extType)
            if !inserted {
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }

            if extType == TLSExtensionType.quicTransportParameters {
                let params = Data(body[offset..<(offset + extDataLen)])
                peerQUICTransportParameters = params

                _ = params.withUnsafeBytes { buf -> Int32 in
                    guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return -1
                    }
                    return ngtcp2_conn_decode_and_set_remote_transport_params(
                        conn, ptr, params.count
                    )
                }
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
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }
        }

        return .success
    }

    // MARK: - Server Finished

    private func processServerFinished(_ body: Data, conn: OpaquePointer) -> QUICTLSResult {
        guard let keyDerivation, let handshakeSecret, let clientHTS = clientHandshakeTrafficSecret else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        // If we're resuming we jump straight to Finished: a resumed handshake carries no
        // Certificate/CertificateVerify, the server is authenticated by the PSK.
        if !pskAccepted {
            if let error = validateCertificate() {
                logger.warning("[QUIC-TLS] Certificate validation failed: \(error.localizedDescription)")
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }

            if !serverCertificates.isEmpty,
               let cvTranscript = transcriptBeforeCertVerify,
               let signature = certificateVerifySignature {
                if let error = verifyCertificateVerify(
                    transcript: cvTranscript,
                    algorithm: certificateVerifyAlgorithm,
                    signature: signature
                ) {
                    logger.warning("[QUIC-TLS] CertificateVerify failed: \(error.localizedDescription)")
                    return .error(NGTCP2_ERR_CALLBACK_FAILURE)
                }
            }
        }

        guard let serverHTS = serverHandshakeTrafficSecret,
              let preFinishedTranscript = transcriptBeforeServerFinished else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        let expectedServerFinished = keyDerivation.serverFinishedPayload(
            serverTrafficSecret: serverHTS, transcript: preFinishedTranscript
        )
        guard body == expectedServerFinished else {
            logger.warning("[QUIC-TLS] Server Finished verification failed")
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        let appKeys = keyDerivation.deriveApplicationKeys(
            handshakeSecret: handshakeSecret, fullTranscript: transcript
        )
        installApplicationKeys(conn: conn, keys: appKeys)

        let verifyData = keyDerivation.finishedPayload(
            trafficSecret: clientHTS, transcript: transcript
        )
        let finishedMessage = buildFinishedMessage(verifyData: verifyData)

        let rv = finishedMessage.withUnsafeBytes { buf -> Int32 in
            guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return NGTCP2_ERR_CALLBACK_FAILURE
            }
            return ngtcp2_conn_submit_crypto_data(
                conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, ptr, finishedMessage.count
            )
        }

        if rv != 0 {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        ngtcp2_conn_tls_handshake_completed(conn)
        state = .completed

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

    // MARK: - Key Installation

    private func installHandshakeKeys(conn: OpaquePointer, keys: TLSHandshakeKeys) {
        let aead = ngtcp2_crypto_aead()
        let md = ngtcp2_crypto_md()

        var ctx = ngtcp2_crypto_ctx()
        ngtcp2_crypto_ctx_tls(&ctx, UnsafeMutableRawPointer(bitPattern: UInt(cipherSuite)))
        ngtcp2_conn_set_crypto_ctx(conn, &ctx)

        let kd = keyDerivation!
        let clientKey = kd.expandLabel(
            secret: SymmetricKey(data: keys.clientTrafficSecret),
            label: "quic key", context: Data(), length: kd.keyLength)
        let clientIV = kd.expandLabel(
            secret: SymmetricKey(data: keys.clientTrafficSecret),
            label: "quic iv", context: Data(), length: 12)
        let clientHP = kd.expandLabel(
            secret: SymmetricKey(data: keys.clientTrafficSecret),
            label: "quic hp", context: Data(), length: kd.keyLength)

        let serverKey = kd.expandLabel(
            secret: SymmetricKey(data: keys.serverTrafficSecret),
            label: "quic key", context: Data(), length: kd.keyLength)
        let serverIV = kd.expandLabel(
            secret: SymmetricKey(data: keys.serverTrafficSecret),
            label: "quic iv", context: Data(), length: 12)
        let serverHP = kd.expandLabel(
            secret: SymmetricKey(data: keys.serverTrafficSecret),
            label: "quic hp", context: Data(), length: kd.keyLength)

        var rxAeadCtx = ngtcp2_crypto_aead_ctx()
        var txAeadCtx = ngtcp2_crypto_aead_ctx()
        var rxHPCtx = ngtcp2_crypto_cipher_ctx()
        var txHPCtx = ngtcp2_crypto_cipher_ctx()

        serverKey.withUnsafeBytes { keyBuf in
            ngtcp2_crypto_aead_ctx_decrypt_init(&rxAeadCtx, &ctx.aead,
                keyBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12)
        }
        clientKey.withUnsafeBytes { keyBuf in
            ngtcp2_crypto_aead_ctx_encrypt_init(&txAeadCtx, &ctx.aead,
                keyBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12)
        }
        serverHP.withUnsafeBytes { keyBuf in
            ngtcp2_crypto_cipher_ctx_encrypt_init(&rxHPCtx, &ctx.hp,
                keyBuf.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }
        clientHP.withUnsafeBytes { keyBuf in
            ngtcp2_crypto_cipher_ctx_encrypt_init(&txHPCtx, &ctx.hp,
                keyBuf.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }

        serverIV.withUnsafeBytes { ivBuf in
            ngtcp2_conn_install_rx_handshake_key(conn, &rxAeadCtx,
                ivBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12, &rxHPCtx)
        }
        clientIV.withUnsafeBytes { ivBuf in
            ngtcp2_conn_install_tx_handshake_key(conn, &txAeadCtx,
                ivBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12, &txHPCtx)
        }
    }

    private func installApplicationKeys(conn: OpaquePointer, keys: TLSApplicationKeys) {
        let kd = keyDerivation!
        var ctx = ngtcp2_crypto_ctx()
        ngtcp2_crypto_ctx_tls(&ctx, UnsafeMutableRawPointer(bitPattern: UInt(cipherSuite)))

        let hsKey = SymmetricKey(data: handshakeSecret!)
        let derivedHS = kd.deriveSecret(secret: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = kd.extract(inputKeyMaterial: Data(repeating: 0, count: kd.hashLength), salt: derivedHS)

        let serverATS = kd.deriveSecret(secret: masterKey, label: "s ap traffic", messages: transcript)
        let clientATS = kd.deriveSecret(secret: masterKey, label: "c ap traffic", messages: transcript)

        let serverATSKey = SymmetricKey(data: serverATS)
        let rxKey = kd.expandLabel(secret: serverATSKey, label: "quic key", context: Data(), length: kd.keyLength)
        let rxIV = kd.expandLabel(secret: serverATSKey, label: "quic iv", context: Data(), length: 12)
        let rxHP = kd.expandLabel(secret: serverATSKey, label: "quic hp", context: Data(), length: kd.keyLength)

        let clientATSKey = SymmetricKey(data: clientATS)
        let txKey = kd.expandLabel(secret: clientATSKey, label: "quic key", context: Data(), length: kd.keyLength)
        let txIV = kd.expandLabel(secret: clientATSKey, label: "quic iv", context: Data(), length: 12)
        let txHP = kd.expandLabel(secret: clientATSKey, label: "quic hp", context: Data(), length: kd.keyLength)

        var rxAeadCtx = ngtcp2_crypto_aead_ctx()
        var rxHPCtx = ngtcp2_crypto_cipher_ctx()
        var txAeadCtx = ngtcp2_crypto_aead_ctx()
        var txHPCtx = ngtcp2_crypto_cipher_ctx()

        rxKey.withUnsafeBytes { buf in
            ngtcp2_crypto_aead_ctx_decrypt_init(&rxAeadCtx, &ctx.aead,
                buf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12)
        }
        rxHP.withUnsafeBytes { buf in
            ngtcp2_crypto_cipher_ctx_encrypt_init(&rxHPCtx, &ctx.hp,
                buf.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }
        txKey.withUnsafeBytes { buf in
            ngtcp2_crypto_aead_ctx_encrypt_init(&txAeadCtx, &ctx.aead,
                buf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12)
        }
        txHP.withUnsafeBytes { buf in
            ngtcp2_crypto_cipher_ctx_encrypt_init(&txHPCtx, &ctx.hp,
                buf.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }

        serverATS.withUnsafeBytes { secretBuf in
            rxIV.withUnsafeBytes { ivBuf in
                ngtcp2_conn_install_rx_key(conn,
                    secretBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), kd.hashLength,
                    &rxAeadCtx,
                    ivBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12,
                    &rxHPCtx)
            }
        }

        clientATS.withUnsafeBytes { secretBuf in
            txIV.withUnsafeBytes { ivBuf in
                ngtcp2_conn_install_tx_key(conn,
                    secretBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), kd.hashLength,
                    &txAeadCtx,
                    ivBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12,
                    &txHPCtx)
            }
        }
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
            lifetime: lifetime, ticketAgeAdd: ticketAgeAdd
        )
        QUICSessionTicketCache.store(cached, serverName: serverName, alpn: alpn)

        return .success
    }

    // MARK: - PSK Extension Building

    /// Builds a pre_shared_key extension with a fake binder value that is all zeros.
    private func buildPSKExtension(ticket: QUICSessionTicket) -> (extensionData: Data, binderLen: Int) {
        // We need to get the age in milliseconds, and add the obfuscation value modulo 2^32.
        let ticketAgeMs = UInt32((CFAbsoluteTimeGetCurrent() - ticket.issued) * 1000)
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

    /// Computes and patches the PSK binder into a ClientHello that has a zero-filled placeholder.
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

        // We now need to strip trailing data. We know the binder list contains only one binder,
        // which is binderLen in length, plus the 1 byte length of the binder and the
        // 2 byte length of the binder entry field it's a part of. Drop those.
        let truncatedSuffix = binderLen + 3
        guard clientHello.count >= truncatedSuffix else { return }
        let partial = Data(clientHello[0..<(clientHello.count - truncatedSuffix)])

        // Now we can generate the new binder and replace the zero binder with it.
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
            }

            guard offset + 2 <= listEnd else { break }
            let extLen = Int(body[offset]) << 8 | Int(body[offset + 1])
            offset += 2 + extLen
        }
    }

    // MARK: - CertificateVerify

    private func processCertificateVerify(_ body: Data) -> QUICTLSResult {
        guard body.count >= 4 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        certificateVerifyAlgorithm = UInt16(body[0]) << 8 | UInt16(body[1])

        // Verify that the signature algorithm matches the client's offer.
        guard TLSClientHelloBuilder.quicSignatureAlgorithms.contains(certificateVerifyAlgorithm) else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        let sigLen = Int(body[2]) << 8 | Int(body[3])
        guard body.count >= 4 + sigLen else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        certificateVerifySignature = Data(body[4..<(4 + sigLen)])
        return .success
    }

    // MARK: - Certificate Validation

    private func validateCertificate() -> Error? {
        if CertificatePolicy.allowInsecure {
            return nil
        }

        guard !serverCertificates.isEmpty else {
            return TLSError.certificateValidationFailed("No server certificates received")
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, serverName as CFString)

        let status = SecTrustCreateWithCertificates(
            serverCertificates as CFArray,
            policy,
            &trust
        )

        guard status == errSecSuccess, let trust else {
            return TLSError.certificateValidationFailed("Failed to create trust object")
        }

        var cfError: CFError?
        let isValid = SecTrustEvaluateWithError(trust, &cfError)
        if isValid {
            return nil
        }

        if Self.isUserTrusted(chain: serverCertificates, serverName: serverName) {
            return nil
        }

        let message = (cfError as Error?)?.localizedDescription ?? "Certificate evaluation failed"
        return TLSError.certificateValidationFailed(message)
    }

    private func verifyCertificateVerify(
        transcript: Data,
        algorithm: UInt16,
        signature: Data
    ) -> Error? {
        guard let kd = keyDerivation else {
            return TLSError.handshakeFailed("Missing key derivation")
        }

        guard let serverCert = serverCertificates.first else {
            return TLSError.certificateValidationFailed("No server certificate for CertificateVerify")
        }

        guard let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            return TLSError.certificateValidationFailed("Failed to extract public key")
        }

        let transcriptHash = kd.transcriptHash(transcript)

        var content = Data(repeating: 0x20, count: 64)
        content.append("TLS 1.3, server CertificateVerify".data(using: .ascii)!)
        content.append(0x00)
        content.append(transcriptHash)

        let secAlgorithm = Self.secKeyAlgorithm(for: algorithm)

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
                return nil
            }
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            return TLSError.certificateValidationFailed("CertificateVerify failed: \(message)")
        }

        return nil
    }

    private static func secKeyAlgorithm(for tlsAlgorithm: UInt16) -> SecKeyAlgorithm {
        switch tlsAlgorithm {
        case TLSSignatureScheme.ecdsa_secp256r1_sha256: return .ecdsaSignatureMessageX962SHA256
        case TLSSignatureScheme.ecdsa_secp384r1_sha384: return .ecdsaSignatureMessageX962SHA384
        case TLSSignatureScheme.ecdsa_secp521r1_sha512: return .ecdsaSignatureMessageX962SHA512
        case TLSSignatureScheme.ecdsa_sha1:             return .ecdsaSignatureMessageX962SHA1
        case TLSSignatureScheme.rsa_pss_rsae_sha256:    return .rsaSignatureMessagePSSSHA256
        case TLSSignatureScheme.rsa_pss_rsae_sha384:    return .rsaSignatureMessagePSSSHA384
        case TLSSignatureScheme.rsa_pss_rsae_sha512:    return .rsaSignatureMessagePSSSHA512
        case TLSSignatureScheme.rsa_pkcs1_sha256:       return .rsaSignatureMessagePKCS1v15SHA256
        case TLSSignatureScheme.rsa_pkcs1_sha384:       return .rsaSignatureMessagePKCS1v15SHA384
        case TLSSignatureScheme.rsa_pkcs1_sha512:       return .rsaSignatureMessagePKCS1v15SHA512
        case TLSSignatureScheme.rsa_pkcs1_sha1:         return .rsaSignatureMessagePKCS1v15SHA1
        default:                                        return .rsaSignatureMessagePSSSHA256
        }
    }

    /// A user-pinned leaf fingerprint waives **only** the chain-of-trust requirement — not the
    /// hostname or validity period. After matching the pinned SHA-256, the leaf is re-evaluated as
    /// its own trust anchor under the SSL policy for `serverName`, so a cert pinned for host A can't
    /// be accepted for host B and an expired pinned cert is still rejected (the pin is host-scoped).
    private static func isUserTrusted(chain: [SecCertificate], serverName: String) -> Bool {
        guard let leaf = chain.first else { return false }
        let trusted = CertificatePolicy.trustedFingerprints
        guard !trusted.isEmpty else { return false }
        let certData = SecCertificateCopyData(leaf) as Data
        let sha256 = SHA256.hash(data: certData).map { String(format: "%02x", $0) }.joined()
        guard trusted.contains(sha256) else { return false }
        // Re-evaluate with the pinned leaf installed as the sole anchor: this trusts the exact pinned
        // cert while the SSL policy still enforces hostname (SAN/CN) match and notBefore/notAfter.
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, serverName as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess,
              let trust else { return false }
        guard SecTrustSetAnchorCertificates(trust, [leaf] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }

    // MARK: - Helpers

    private func buildFinishedMessage(verifyData: Data) -> Data {
        var msg = Data()
        msg.append(TLSHandshakeType.finished)
        let len = verifyData.count
        msg.append(UInt8((len >> 16) & 0xFF))
        msg.append(UInt8((len >> 8) & 0xFF))
        msg.append(UInt8(len & 0xFF))
        msg.append(verifyData)
        return msg
    }
}
