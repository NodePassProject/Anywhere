//
//  QUICTLSHandler.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "QUIC-TLS")

// MARK: - Session Ticket Cache

/// Cached session ticket for TLS resumption.
struct QUICSessionTicket {
    let ticket: Data
    let nonce: Data
    let psk: Data           // Pre-shared key derived from resumption master secret
    let cipherSuite: UInt16
    let createdAt: Date
    let lifetime: UInt32    // seconds
    let ageAdd: UInt32      // obfuscation factor for ticket age
}

/// Global session ticket cache, keyed by SNI.
private let ticketCacheLock = UnfairLock()
private var sessionTicketCache: [String: QUICSessionTicket] = [:]

/// Result of processing a TLS crypto data message.
enum QUICTLSResult {
    case success
    case needMoreData
    case error(Int32)
}

/// Manages the TLS 1.3 handshake within a QUIC connection.
///
/// Instead of using TLS records, the handshake messages are transported in
/// QUIC CRYPTO frames. This handler:
/// 1. Builds a TLS ClientHello with QUIC transport parameters
/// 2. Processes the server's TLS messages (ServerHello, EncryptedExtensions, etc.)
/// 3. Derives and installs handshake/application keys into ngtcp2
/// 4. Submits the client Finished message
class QUICTLSHandler {

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

    private let sni: String
    private let alpn: [String]
    private var state: HandshakeState = .initial

    // Key derivation
    private var keyDerivation: TLS13KeyDerivation?
    private var handshakeSecret: Data?
    private var clientHandshakeTrafficSecret: Data?

    // ECDHE
    private var privateKey: P256.KeyAgreement.PrivateKey?
    private var clientRandom = Data(count: 32)

    // Transcript (concatenation of all handshake messages)
    private var transcript = Data()

    // Negotiated cipher suite
    private(set) var cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256

    // Accumulator for partial TLS messages
    private var cryptoBuffer = Data()

    // Certificate validation state
    private var serverCertificates: [SecCertificate] = []
    private var transcriptBeforeCertVerify: Data?
    private var certificateVerifyAlgorithm: UInt16 = 0
    private var certificateVerifySignature: Data?

    // Session resumption
    private var resumptionMasterSecret: Data?
    private var activePSK: Data?           // PSK used in this handshake (when server accepts)
    private var pskBinderLength: Int = 0   // Binder length used in ClientHello

    // Server's transport parameters (extracted from EncryptedExtensions)
    private(set) var serverTransportParams: Data?

    // MARK: - Initialization

    init(sni: String, alpn: [String] = ["h3"]) {
        self.sni = sni
        self.alpn = alpn

        // Generate ECDHE key pair
        privateKey = P256.KeyAgreement.PrivateKey()

        // Generate client random
        _ = clientRandom.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, 32, buf.baseAddress!)
        }
    }

    // MARK: - Build ClientHello

    /// Builds a TLS 1.3 ClientHello message with QUIC transport parameters.
    ///
    /// The returned data is the raw TLS Handshake message (type + length + body),
    /// suitable for submission via `ngtcp2_conn_submit_crypto_data`.
    func buildClientHello(transportParams: Data) -> Data? {
        guard let privateKey else { return nil }

        let publicKeyData = privateKey.publicKey.x963Representation

        // Check for a cached session ticket for resumption
        var pskExtData: Data?
        var candidatePSK: Data?

        ticketCacheLock.lock()
        let cachedTicket = sessionTicketCache[sni]
        ticketCacheLock.unlock()

        if let ticket = cachedTicket,
           Date().timeIntervalSince(ticket.createdAt) < Double(ticket.lifetime) {
            let (extData, binderLen) = buildPSKExtension(ticket: ticket)
            pskExtData = extData
            pskBinderLength = binderLen
            candidatePSK = ticket.psk
        }

        // Build ClientHello (PSK extension appended last if present)
        var clientHello = TLSClientHelloBuilder.buildQUICClientHello(
            random: clientRandom,
            sni: sni,
            alpn: alpn,
            publicKey: publicKeyData,
            quicTransportParams: transportParams,
            pskExtension: pskExtData
        )

        // Compute and patch PSK binder if we included a PSK extension
        if let psk = candidatePSK, pskBinderLength > 0 {
            patchPSKBinder(clientHello: &clientHello, binderLen: pskBinderLength, psk: psk)
            activePSK = psk
        }

        // Add to transcript
        transcript.append(clientHello)
        state = .clientHelloSent

        return clientHello
    }

    // MARK: - Process Crypto Data

    /// Processes TLS handshake data received in a QUIC CRYPTO frame.
    func processCryptoData(_ data: Data, level: ngtcp2_encryption_level,
                           conn: OpaquePointer) -> QUICTLSResult {
        cryptoBuffer.append(data)

        // Process all complete TLS messages in the buffer
        while cryptoBuffer.count >= 4 {
            // TLS handshake message: type(1) + length(3) + body
            // Use startIndex-relative access since removeFirst shifts the base.
            let si = cryptoBuffer.startIndex
            let msgType = cryptoBuffer[si]
            let msgLen = (Int(cryptoBuffer[si + 1]) << 16)
                       | (Int(cryptoBuffer[si + 2]) << 8)
                       |  Int(cryptoBuffer[si + 3])
            let totalLen = 4 + msgLen

            guard cryptoBuffer.count >= totalLen else {
                return .needMoreData
            }

            let message = Data(cryptoBuffer[si..<(si + totalLen)])
            cryptoBuffer = Data(cryptoBuffer.dropFirst(totalLen))

            // Save transcript state before CertificateVerify for signature verification
            if msgType == 15 { // CertificateVerify
                transcriptBeforeCertVerify = transcript
            }

            // Add to transcript
            transcript.append(message)

            // body starts after the 4-byte handshake header
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
        case 2:  return processServerHello(body, conn: conn)
        case 8:  return processEncryptedExtensions(body, conn: conn)
        case 11: return processCertificate(body)
        case 15: return processCertificateVerify(body)
        case 20: return processServerFinished(body, conn: conn)
        case 4:  return processNewSessionTicket(body)
        default:
            logger.warning("[QUIC-TLS] Unknown message type: \(msgType)")
            return .success
        }
    }

    // MARK: - ServerHello

    private func processServerHello(_ body: Data, conn: OpaquePointer) -> QUICTLSResult {
        guard body.count >= 34 else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        // Parse server random (bytes 2-33 after version)
        let serverRandom = Data(body[2..<34])

        // Parse session ID length and skip
        var offset = 34
        guard offset < body.count else { return .error(NGTCP2_ERR_CALLBACK_FAILURE) }
        let sessionIdLen = Int(body[offset])
        offset += 1 + sessionIdLen

        // Parse cipher suite
        guard offset + 2 <= body.count else { return .error(NGTCP2_ERR_CALLBACK_FAILURE) }
        cipherSuite = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
        offset += 2

        // Skip compression method
        offset += 1

        // Parse extensions to find key_share
        guard offset + 2 <= body.count else { return .error(NGTCP2_ERR_CALLBACK_FAILURE) }
        let extLen = (Int(body[offset]) << 8) | Int(body[offset + 1])
        offset += 2

        var serverPublicKey: Data?
        var pskAccepted = false
        let extEnd = offset + extLen
        while offset + 4 <= extEnd && offset + 4 <= body.count {
            let extType = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
            let extDataLen = (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
            offset += 4

            if extType == 0x0033 { // key_share
                // key_share extension: named_group(2) + key_exchange_length(2) + key_exchange
                if offset + 4 <= body.count {
                    let keyExchangeLen = (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
                    if offset + 4 + keyExchangeLen <= body.count {
                        serverPublicKey = Data(body[(offset + 4)..<(offset + 4 + keyExchangeLen)])
                    }
                }
            } else if extType == 0x0029 { // pre_shared_key
                // Server accepted PSK: selected_identity (UInt16), must be 0
                if extDataLen >= 2 {
                    let selectedIdentity = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
                    pskAccepted = (selectedIdentity == 0 && activePSK != nil)
                }
            }
            offset += extDataLen
        }

        guard let serverPublicKey, let privateKey else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        // Compute shared secret via ECDHE
        do {
            let serverKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKey)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverKey)
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

            // Initialize key derivation
            keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            // Update ngtcp2's TLS native handle with negotiated cipher suite
            ngtcp2_conn_set_tls_native_handle(conn,
                UnsafeMutableRawPointer(bitPattern: UInt(cipherSuite)))

            // Clear PSK if server didn't accept it
            if !pskAccepted { activePSK = nil }

            // Derive handshake keys (with PSK for resumption, or nil for full handshake)
            let (hsSecret, hsKeys) = keyDerivation!.deriveHandshakeKeys(
                sharedSecret: sharedSecretData, transcript: transcript,
                psk: activePSK
            )
            handshakeSecret = hsSecret
            clientHandshakeTrafficSecret = hsKeys.clientTrafficSecret

            // Install handshake keys in ngtcp2
            installHandshakeKeys(conn: conn, keys: hsKeys)

            state = .serverHelloReceived

        } catch {
            logger.error("[QUIC-TLS] ECDHE failed: \(error)")
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        return .success
    }

    // MARK: - EncryptedExtensions

    private func processEncryptedExtensions(_ body: Data, conn: OpaquePointer) -> QUICTLSResult {
        // Parse extensions to find QUIC transport parameters (0x39)
        guard body.count >= 2 else { return .success }
        let extLen = (Int(body[0]) << 8) | Int(body[1])
        var offset = 2
        let extEnd = offset + extLen

        while offset + 4 <= extEnd && offset + 4 <= body.count {
            let extType = (UInt16(body[offset]) << 8) | UInt16(body[offset + 1])
            let extDataLen = (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
            offset += 4

            if extType == 0x0039 { // quic_transport_parameters
                if offset + extDataLen <= body.count {
                    let params = Data(body[offset..<(offset + extDataLen)])
                    serverTransportParams = params

                    // Set remote transport params on the connection
                    let rv = params.withUnsafeBytes { buf -> Int32 in
                        guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                            return -1
                        }
                        return ngtcp2_conn_decode_and_set_remote_transport_params(
                            conn, ptr, params.count
                        )
                    }
                    if rv != 0 {
                        logger.error("[QUIC-TLS] Failed to set remote transport params: \(rv)")
                    }
                }
            }
            offset += extDataLen
        }

        return .success
    }

    // MARK: - Server Finished

    private func processServerFinished(_ body: Data, conn: OpaquePointer) -> QUICTLSResult {
        guard let keyDerivation, let handshakeSecret, let clientHTS = clientHandshakeTrafficSecret else {
            logger.error("[QUIC-TLS] Missing key derivation state for Finished")
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        // Validate server certificate chain (respects allowInsecure setting)
        if let error = validateCertificate() {
            logger.error("[QUIC-TLS] \(error.localizedDescription)")
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        // Verify CertificateVerify signature against transcript
        if !serverCertificates.isEmpty,
           let cvTranscript = transcriptBeforeCertVerify,
           let signature = certificateVerifySignature {
            if let error = verifyCertificateVerify(
                transcript: cvTranscript,
                algorithm: certificateVerifyAlgorithm,
                signature: signature
            ) {
                logger.error("[QUIC-TLS] \(error.localizedDescription)")
                return .error(NGTCP2_ERR_CALLBACK_FAILURE)
            }
        }

        let appKeys = keyDerivation.deriveApplicationKeys(
            handshakeSecret: handshakeSecret, fullTranscript: transcript
        )
        installApplicationKeys(conn: conn, keys: appKeys)

        let verifyData = keyDerivation.computeFinishedVerifyData(
            trafficSecret: clientHTS, transcript: transcript
        )
        let finishedMessage = buildFinishedMessage(verifyData: verifyData)

        // Submit client Finished on the handshake encryption level
        let rv = finishedMessage.withUnsafeBytes { buf -> Int32 in
            guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return NGTCP2_ERR_CALLBACK_FAILURE
            }
            return ngtcp2_conn_submit_crypto_data(
                conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, ptr, finishedMessage.count
            )
        }

        if rv != 0 {
            logger.error("[QUIC-TLS] Failed to submit client Finished: \(rv)")
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }

        ngtcp2_conn_tls_handshake_completed(conn)
        state = .completed

        // Compute resumption master secret for session ticket processing.
        // Transcript must include client Finished for this derivation.
        transcript.append(finishedMessage)
        let hsKey = SymmetricKey(data: handshakeSecret)
        let derivedHS = keyDerivation.deriveSecret(key: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = keyDerivation.hkdfExtract(
            salt: derivedHS, ikm: Data(repeating: 0, count: keyDerivation.hashLength)
        )
        resumptionMasterSecret = keyDerivation.deriveSecret(
            key: masterKey, label: "res master", messages: transcript
        )

        return .success
    }

    // MARK: - Key Installation

    private func installHandshakeKeys(conn: OpaquePointer, keys: TLSHandshakeKeys) {
        let aead = ngtcp2_crypto_aead()
        let md = ngtcp2_crypto_md()

        // Set crypto context based on cipher suite
        var ctx = ngtcp2_crypto_ctx()
        ngtcp2_crypto_ctx_tls(&ctx, UnsafeMutableRawPointer(bitPattern: UInt(cipherSuite)))
        ngtcp2_conn_set_crypto_ctx(conn, &ctx)

        // Derive packet protection keys from traffic secrets
        let kd = keyDerivation!
        let clientKey = kd.hkdfExpandLabel(
            key: SymmetricKey(data: keys.clientTrafficSecret),
            label: "quic key", context: Data(), length: kd.keyLength)
        let clientIV = kd.hkdfExpandLabel(
            key: SymmetricKey(data: keys.clientTrafficSecret),
            label: "quic iv", context: Data(), length: 12)
        let clientHP = kd.hkdfExpandLabel(
            key: SymmetricKey(data: keys.clientTrafficSecret),
            label: "quic hp", context: Data(), length: kd.keyLength)

        let serverKey = kd.hkdfExpandLabel(
            key: SymmetricKey(data: keys.serverTrafficSecret),
            label: "quic key", context: Data(), length: kd.keyLength)
        let serverIV = kd.hkdfExpandLabel(
            key: SymmetricKey(data: keys.serverTrafficSecret),
            label: "quic iv", context: Data(), length: 12)
        let serverHP = kd.hkdfExpandLabel(
            key: SymmetricKey(data: keys.serverTrafficSecret),
            label: "quic hp", context: Data(), length: kd.keyLength)

        // Create AEAD and HP contexts
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

        // Install keys
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

        // Derive proper application traffic secrets via the master secret chain:
        //   derived = Derive-Secret(handshakeSecret, "derived", "")
        //   masterSecret = HKDF-Extract(derived, 0...0)
        //   server_ats = Derive-Secret(masterSecret, "s ap traffic", transcript)
        //   client_ats = Derive-Secret(masterSecret, "c ap traffic", transcript)
        let hsKey = SymmetricKey(data: handshakeSecret!)
        let derivedHS = kd.deriveSecret(key: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = kd.hkdfExtract(salt: derivedHS, ikm: Data(repeating: 0, count: kd.hashLength))

        let serverATS = kd.deriveSecret(key: masterKey, label: "s ap traffic", messages: transcript)
        let clientATS = kd.deriveSecret(key: masterKey, label: "c ap traffic", messages: transcript)

        // Derive QUIC packet protection keys from the traffic secrets
        let serverATSKey = SymmetricKey(data: serverATS)
        let rxKey = kd.hkdfExpandLabel(key: serverATSKey, label: "quic key", context: Data(), length: kd.keyLength)
        let rxIV = kd.hkdfExpandLabel(key: serverATSKey, label: "quic iv", context: Data(), length: 12)
        let rxHP = kd.hkdfExpandLabel(key: serverATSKey, label: "quic hp", context: Data(), length: kd.keyLength)

        let clientATSKey = SymmetricKey(data: clientATS)
        let txKey = kd.hkdfExpandLabel(key: clientATSKey, label: "quic key", context: Data(), length: kd.keyLength)
        let txIV = kd.hkdfExpandLabel(key: clientATSKey, label: "quic iv", context: Data(), length: 12)
        let txHP = kd.hkdfExpandLabel(key: clientATSKey, label: "quic hp", context: Data(), length: kd.keyLength)

        // (keys derived)

        // Create AEAD and HP contexts
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

        // Install rx (server → client) application keys
        serverATS.withUnsafeBytes { secretBuf in
            rxIV.withUnsafeBytes { ivBuf in
                ngtcp2_conn_install_rx_key(conn,
                    secretBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), kd.hashLength,
                    &rxAeadCtx,
                    ivBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 12,
                    &rxHPCtx)
            }
        }

        // Install tx (client → server) application keys
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

    /// Parses a NewSessionTicket message and caches it for future resumption.
    private func processNewSessionTicket(_ body: Data) -> QUICTLSResult {
        guard body.count >= 11 else { return .success }

        var offset = 0
        let lifetime = UInt32(body[0]) << 24 | UInt32(body[1]) << 16
                     | UInt32(body[2]) << 8  | UInt32(body[3])
        offset += 4

        let ageAdd = UInt32(body[offset]) << 24 | UInt32(body[offset + 1]) << 16
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

        // Derive PSK from resumption master secret (RFC 8446 §4.6.1)
        guard let kd = keyDerivation, let rms = resumptionMasterSecret else { return .success }
        let psk = kd.hkdfExpandLabel(
            key: SymmetricKey(data: rms),
            label: "resumption",
            context: nonce,
            length: kd.hashLength
        )

        let cached = QUICSessionTicket(
            ticket: ticket, nonce: nonce, psk: psk,
            cipherSuite: cipherSuite, createdAt: Date(),
            lifetime: lifetime, ageAdd: ageAdd
        )
        ticketCacheLock.lock()
        sessionTicketCache[sni] = cached
        ticketCacheLock.unlock()
        
        return .success
    }

    // MARK: - PSK Extension Building

    /// Builds a pre_shared_key extension (type 0x0029) with a zero-filled binder placeholder.
    private func buildPSKExtension(ticket: QUICSessionTicket) -> (extensionData: Data, binderLen: Int) {
        let ticketAgeMs = UInt32(Date().timeIntervalSince(ticket.createdAt) * 1000)
        let obfuscatedAge = ticketAgeMs &+ ticket.ageAdd

        // PskIdentity: identity_len(2) + identity + obfuscated_ticket_age(4)
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

        // PskBinderEntry: binder_len(1) + binder (zero placeholder)
        var binders = Data()
        binders.append(UInt8(binderLen))
        binders.append(Data(repeating: 0, count: binderLen))

        // OfferedPsks: identities_len(2) + identities + binders_len(2) + binders
        var payload = Data()
        payload.append(UInt8(identities.count >> 8))
        payload.append(UInt8(identities.count & 0xFF))
        payload.append(identities)
        payload.append(UInt8(binders.count >> 8))
        payload.append(UInt8(binders.count & 0xFF))
        payload.append(binders)

        // Extension header: type(2) + length(2) + payload
        var ext = Data()
        ext.append(0x00); ext.append(0x29) // pre_shared_key
        ext.append(UInt8(payload.count >> 8))
        ext.append(UInt8(payload.count & 0xFF))
        ext.append(payload)

        return (ext, binderLen)
    }

    /// Computes and patches the PSK binder into a ClientHello that has a zero-filled placeholder.
    private func patchPSKBinder(clientHello: inout Data, binderLen: Int, psk: Data) {
        let kd = TLS13KeyDerivation(cipherSuite: cipherSuite)

        // Derive binder key: early_secret → "res binder" → finished_key
        let (_, earlyKey) = kd.hkdfExtract(salt: Data(), ikm: psk)
        let binderKeySecret = kd.deriveSecret(key: earlyKey, label: "res binder", messages: Data())
        let finishedKey = kd.hkdfExpandLabel(
            key: SymmetricKey(data: binderKeySecret),
            label: "finished",
            context: Data(),
            length: kd.hashLength
        )

        // Binder = HMAC(finished_key, Hash(partial_ClientHello))
        // partial_ClientHello = everything except the binder value bytes at the end
        let partialLen = clientHello.count - binderLen
        let partial = Data(clientHello[0..<partialLen])
        let transcriptHash = kd.transcriptHash(partial)

        let symKey = SymmetricKey(data: finishedKey)
        let binder: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            binder = Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: symKey))
        } else {
            binder = Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: symKey))
        }

        // Patch binder into ClientHello
        clientHello.replaceSubrange(partialLen..<clientHello.count, with: binder)
    }

    // MARK: - Certificate

    private func processCertificate(_ body: Data) -> QUICTLSResult {
        parseTLS13CertificateMessage(body)
        return .success
    }

    /// Parses a TLS 1.3 Certificate message to extract X.509 certificates.
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

            // Skip per-certificate extensions
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
        let sigLen = Int(body[2]) << 8 | Int(body[3])
        guard body.count >= 4 + sigLen else {
            return .error(NGTCP2_ERR_CALLBACK_FAILURE)
        }
        certificateVerifySignature = Data(body[4..<(4 + sigLen)])
        return .success
    }

    // MARK: - Certificate Validation

    /// Validates the server certificate chain using SecTrust.
    /// Respects `allowInsecure` and user-trusted certificate SHA-256 fingerprints,
    /// matching the behavior of TLSClient for HTTP/2.
    private func validateCertificate() -> Error? {
        if CertificatePolicy.allowInsecure {
            return nil
        }

        guard !serverCertificates.isEmpty else {
            return TLSError.certificateValidationFailed("No server certificates received")
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, sni as CFString)

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

        if let leafCert = serverCertificates.first,
           Self.isUserTrusted(certificate: leafCert) {
            return nil
        }

        let message = (cfError as Error?)?.localizedDescription ?? "Certificate evaluation failed"
        return TLSError.certificateValidationFailed(message)
    }

    /// Verifies the CertificateVerify signature against the handshake transcript.
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

        // RFC 8446 §4.4.3: content = 64×0x20 + context_string + 0x00 + Hash(transcript)
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
            // Respect allowInsecure for signature verification too
            if CertificatePolicy.allowInsecure {
                return nil
            }
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            return TLSError.certificateValidationFailed("CertificateVerify failed: \(message)")
        }

        return nil
    }

    /// Maps TLS signature algorithm identifier to Security.framework algorithm.
    private static func secKeyAlgorithm(for tlsAlgorithm: UInt16) -> SecKeyAlgorithm {
        switch tlsAlgorithm {
        case 0x0403: return .ecdsaSignatureMessageX962SHA256
        case 0x0503: return .ecdsaSignatureMessageX962SHA384
        case 0x0603: return .ecdsaSignatureMessageX962SHA512
        case 0x0804: return .rsaSignatureMessagePSSSHA256
        case 0x0805: return .rsaSignatureMessagePSSSHA384
        case 0x0806: return .rsaSignatureMessagePSSSHA512
        case 0x0401: return .rsaSignatureMessagePKCS1v15SHA256
        case 0x0501: return .rsaSignatureMessagePKCS1v15SHA384
        case 0x0601: return .rsaSignatureMessagePKCS1v15SHA512
        case 0x0201: return .rsaSignatureMessagePKCS1v15SHA1
        default:     return .rsaSignatureMessagePSSSHA256
        }
    }

    /// Checks whether the certificate's SHA-256 fingerprint is in the user's trusted list.
    private static func isUserTrusted(certificate: SecCertificate) -> Bool {
        let trusted = CertificatePolicy.trustedFingerprints
        guard !trusted.isEmpty else { return false }
        let certData = SecCertificateCopyData(certificate) as Data
        let sha256 = SHA256.hash(data: certData).map { String(format: "%02x", $0) }.joined()
        return trusted.contains(sha256)
    }

    // MARK: - Helpers

    private func buildFinishedMessage(verifyData: Data) -> Data {
        var msg = Data()
        msg.append(20) // Finished type
        let len = verifyData.count
        msg.append(UInt8((len >> 16) & 0xFF))
        msg.append(UInt8((len >> 8) & 0xFF))
        msg.append(UInt8(len & 0xFF))
        msg.append(verifyData)
        return msg
    }
}
