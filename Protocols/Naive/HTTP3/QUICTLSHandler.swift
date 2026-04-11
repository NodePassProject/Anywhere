//
//  QUICTLSHandler.swift
//  Anywhere
//
//  Handles TLS 1.3 handshake over QUIC CRYPTO frames.
//  Uses the existing TLSClientHelloBuilder for ClientHello construction
//  and TLS13KeyDerivation for key material derivation.
//

import Foundation
import CryptoKit

private let logger = AnywhereLogger(category: "QUIC-TLS")

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

        // Build ClientHello using the existing builder
        let clientHello = TLSClientHelloBuilder.buildQUICClientHello(
            random: clientRandom,
            sni: sni,
            alpn: alpn,
            publicKey: publicKeyData,
            quicTransportParams: transportParams
        )

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
        case 11: return .success // Certificate
        case 15: return .success // CertificateVerify
        case 20: return processServerFinished(body, conn: conn)
        case 4:  return .success // NewSessionTicket
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

            // Derive handshake keys
            let transcriptForHS = keyDerivation!.transcriptHash(transcript)
            let (hsSecret, hsKeys) = keyDerivation!.deriveHandshakeKeys(
                sharedSecret: sharedSecretData, transcript: transcript
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
