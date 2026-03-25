//
//  TLSClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import CryptoKit
import Security
import Compression
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "TLS")

// MARK: - TLSClient

/// Client for establishing standard TLS 1.3 connections.
///
/// Performs a TLS 1.3 handshake with X.509 certificate validation:
/// - Builds a standard ClientHello with random SessionId.
/// - Validates the server certificate chain via `SecTrust`.
/// - Verifies the CertificateVerify signature against the handshake transcript.
/// - Derives application-layer encryption keys from the TLS 1.3 handshake.
///
/// After a successful handshake, returns a ``TLSRecordConnection`` that wraps
/// the underlying ``NWTransport`` with TLS record encryption/decryption.
class TLSClient {
    private let configuration: TLSConfiguration
    private var connection: (any RawTransport)?

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var storedClientHello: Data?

    // TLS 1.3 session state (cleared after handshake)
    private var keyDerivation: TLS13KeyDerivation?
    private var handshakeSecret: Data?
    private var handshakeKeys: TLSHandshakeKeys?
    private var applicationKeys: TLSApplicationKeys?
    private var handshakeTranscript: Data?
    private var serverHandshakeSeqNum: UInt64 = 0

    // Certificate validation state
    private var serverCertificates: [SecCertificate] = []

    // Buffer for data received after Server Finished (e.g. NewSessionTicket)
    private var postHandshakeBuffer: Data?

    /// RFC 8446 §4.1.3: HelloRetryRequest is signaled by this special random value.
    private static let helloRetryRequestRandom = Data([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ])

    // MARK: Initialization

    /// Creates a new TLS client with the given configuration.
    ///
    /// - Parameter configuration: The TLS configuration (SNI, ALPN, fingerprint).
    init(configuration: TLSConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API

    /// Connects to a server and performs the TLS 1.3 handshake.
    ///
    /// - Parameters:
    ///   - host: The server hostname or IP address.
    ///   - port: The server port number.
    ///   - completion: Called with the established ``TLSRecordConnection`` or an error.
    func connect(
        host: String,
        port: UInt16,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        guard let privateKey = ephemeralPrivateKey else {
            completion(.failure(TLSError.handshakeFailed("No ephemeral key")))
            return
        }

        // Build ClientHello before connecting so it can be sent via TCP Fast Open
        // (included in the SYN packet, saving one round trip).
        let clientHello: Data
        do {
            clientHello = try buildTLSClientHello(privateKey: privateKey)
        } catch {
            logger.error("[TLS] Failed to build ClientHello: \(error.localizedDescription, privacy: .public)")
            completion(.failure(error))
            return
        }
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        let transport = NWTransport()
        self.connection = transport

        transport.connect(host: host, port: port, queue: .global(), initialData: clientHello) { [weak self] error in
            if let error {
                logger.error("[TLS] TCP connection failed: \(error.localizedDescription, privacy: .public)")
                completion(.failure(TLSError.connectionFailed(error.localizedDescription)))
                return
            }

            guard let self else {
                completion(.failure(TLSError.connectionFailed("Client deallocated")))
                return
            }

            // ClientHello already sent via TFO, proceed directly to server response
            self.receiveServerResponse(completion: completion)
        }
    }

    /// Connects over an existing proxy tunnel and performs the TLS 1.3 handshake.
    ///
    /// Used for proxy chaining: the tunnel provides raw TCP I/O to the remote server.
    ///
    /// - Parameters:
    ///   - tunnel: The proxy connection providing a TCP tunnel to the server.
    ///   - completion: Called with the established ``TLSRecordConnection`` or an error.
    func connect(
        overTunnel tunnel: ProxyConnection,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.connection = TunneledTransport(tunnel: tunnel)
        performTLSHandshake(completion: completion)
    }

    /// Cancels the connection and releases all resources.
    func cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = nil
    }

    // MARK: - Handshake

    /// Performs the TLS 1.3 handshake: sends ClientHello, processes ServerHello,
    /// derives encryption keys, validates certificates, and sends Client Finished.
    private func performTLSHandshake(
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let privateKey = ephemeralPrivateKey else {
            logger.error("[TLS] No ephemeral key for handshake")
            completion(.failure(TLSError.handshakeFailed("No ephemeral key")))
            return
        }

        do {
            let clientHello = try buildTLSClientHello(privateKey: privateKey)

            // Store for TLS transcript (without 5-byte TLS record header)
            storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

            guard let connection else {
                completion(.failure(TLSError.connectionFailed("Connection cancelled")))
                return
            }
            connection.send(data: clientHello) { [weak self] error in
                guard let self else { return }

                if let error {
                    logger.error("[TLS] Failed to send ClientHello: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                self.receiveServerResponse(completion: completion)
            }
        } catch {
            logger.error("[TLS] Failed to build ClientHello: \(error.localizedDescription, privacy: .public)")
            completion(.failure(error))
        }
    }

    // MARK: - ClientHello

    /// Builds a standard TLS 1.3 ClientHello with random SessionId.
    ///
    /// - Parameter privateKey: The ephemeral X25519 private key for this connection.
    /// - Returns: A complete TLS record containing the ClientHello.
    private func buildTLSClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        _ = random.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        // Standard TLS: random 32-byte session ID (no Reality metadata)
        var sessionId = Data(count: 32)
        _ = sessionId.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let rawClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: sessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            alpn: configuration.alpn ?? ["h2", "http/1.1"]
        )

        return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: rawClientHello)
    }

    // MARK: - Server Response Processing

    /// Receives and processes the server's TLS response.
    private func receiveServerResponse(
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive(maximumLength: 65536) { [weak self] data, _, error in
            guard let self else { return }

            if let error {
                logger.error("[TLS] Error receiving server response: \(error.localizedDescription, privacy: .public)")
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let data, data.count >= 5 else {
                logger.error("[TLS] No server response or too short")
                completion(.failure(TLSError.handshakeFailed("No server response")))
                return
            }

            let contentType = data[0]

            if contentType == 0x16 { // Handshake
                self.continueReceivingHandshake(buffer: data, completion: completion)
            } else if contentType == 0x15 { // Alert
                let alertLevel = data.count > 5 ? data[5] : 0
                let alertDesc = data.count > 6 ? data[6] : 0
                logger.error("[TLS] TLS Alert: level=\(alertLevel, privacy: .public), desc=\(alertDesc, privacy: .public)")
                completion(.failure(TLSError.handshakeFailed("TLS Alert: level=\(alertLevel), desc=\(alertDesc)")))
            } else {
                logger.error("[TLS] Unexpected content type: 0x\(String(format: "%02x", contentType), privacy: .public)")
                completion(.failure(TLSError.handshakeFailed("Unexpected content type: \(contentType)")))
            }
        }
    }

    /// Continues receiving handshake messages until ServerHello is complete.
    private func continueReceivingHandshake(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Wait until we have a complete TLS record containing ServerHello.
        // The server may split the response across multiple TCP segments,
        // so we must check the record's declared length before parsing.
        if !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                completion(.failure(TLSError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    logger.error("[TLS] Error receiving more data: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                var newBuffer = buffer
                if let moreData {
                    newBuffer.append(moreData)
                }

                self.continueReceivingHandshake(buffer: newBuffer, completion: completion)
            }
            return
        }

        guard let (serverKeyShare, cipherSuite) = parseServerHello(data: buffer),
              let privateKey = ephemeralPrivateKey,
              let clientHello = storedClientHello else {
            logger.error("[TLS] Failed to parse ServerHello or missing keys")
            completion(.failure(TLSError.handshakeFailed("Failed to parse ServerHello")))
            return
        }

        do {
            let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverKeyShare)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

            let serverHello = extractServerHelloMessage(from: buffer)

            keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            var transcript = Data()
            transcript.append(clientHello)
            transcript.append(serverHello)

            let (hs, keys) = keyDerivation!.deriveHandshakeKeys(sharedSecret: sharedSecretData, transcript: transcript)
            handshakeSecret = hs
            handshakeKeys = keys
            handshakeTranscript = transcript

            consumeRemainingHandshake(buffer: buffer, completion: completion)
        } catch {
            logger.error("[TLS] Failed to derive TLS keys: \(error.localizedDescription, privacy: .public)")
            completion(.failure(TLSError.handshakeFailed("Key derivation failed")))
        }
    }

    // MARK: - ServerHello Parsing

    /// Returns `true` when the buffer contains at least one complete TLS Handshake
    /// record whose payload starts with a ServerHello (type 0x02).
    ///
    /// Returns `false` when a record header indicates more bytes than are
    /// currently buffered — the caller should read more data and retry.
    private func bufferContainsCompleteServerHello(_ buffer: Data) -> Bool {
        var offset = 0
        while offset + 5 <= buffer.count {
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            // Incomplete record — need more data from the network
            if offset + 5 + recordLen > buffer.count { return false }

            // Complete Handshake record containing a ServerHello
            if buffer[offset] == 0x16 && offset + 5 < buffer.count && buffer[offset + 5] == 0x02 {
                return true
            }

            offset += 5 + recordLen
        }

        // All records complete but no ServerHello found — let parseServerHello handle the error
        return offset > 0
    }

    /// Extracts the ServerHello handshake message from the buffer (without TLS record header).
    private func extractServerHelloMessage(from buffer: Data) -> Data {
        var offset = 0
        while offset + 5 < buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if contentType == 0x16 {
                let recordStart = offset + 5
                if recordStart < buffer.count && buffer[recordStart] == 0x02 {
                    return buffer.subdata(in: recordStart..<min(recordStart + recordLen, buffer.count))
                }
            }

            offset += 5 + recordLen
        }
        return Data()
    }

    /// Parses the ServerHello to extract the server's X25519 key share and cipher suite.
    ///
    /// Detects HelloRetryRequest (RFC 8446 §4.1.3) and TLS version mismatches.
    ///
    /// - Parameter data: The raw TLS data containing the ServerHello record.
    /// - Returns: A tuple of (keyShare, cipherSuite) or `nil` if parsing fails.
    private func parseServerHello(data: Data) -> (keyShare: Data, cipherSuite: UInt16)? {
        var offset = 0

        while offset + 5 < data.count {
            let contentType = data[offset]
            guard contentType == 0x16 else { break }

            let recordLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            offset += 5

            guard offset + recordLen <= data.count else { break }
            guard data[offset] == 0x02 else {
                offset += recordLen
                continue
            }

            // Skip handshake type (1) + length (3) + version (2)
            let randomOffset = offset + 1 + 3 + 2
            guard randomOffset + 32 <= data.count else { return nil }

            // Check for HelloRetryRequest (RFC 8446 §4.1.3)
            let serverRandom = data.subdata(in: randomOffset..<(randomOffset + 32))
            if serverRandom == Self.helloRetryRequestRandom {
                logger.error("[TLS] Server sent HelloRetryRequest (not supported)")
                return nil
            }

            var shOffset = randomOffset + 32
            guard shOffset < data.count else { return nil }

            // Session ID
            let sessionIdLen = Int(data[shOffset])
            shOffset += 1 + sessionIdLen

            // Cipher suite (2 bytes)
            guard shOffset + 2 <= data.count else { return nil }
            let cipherSuite = UInt16(data[shOffset]) << 8 | UInt16(data[shOffset + 1])

            // Skip cipher suite (2) + compression (1)
            shOffset += 3

            guard shOffset + 2 <= data.count else { return nil }

            // Extensions
            let extLen = Int(data[shOffset]) << 8 | Int(data[shOffset + 1])
            shOffset += 2

            let extEnd = shOffset + extLen
            guard extEnd <= data.count else { return nil }

            // Check supported_versions (0x002B) and key_share (0x0033)
            var foundVersion: UInt16 = 0
            var keyShareData: Data?

            var extOffset = shOffset
            while extOffset + 4 <= extEnd {
                let extType = UInt16(data[extOffset]) << 8 | UInt16(data[extOffset + 1])
                let extDataLen = Int(data[extOffset + 2]) << 8 | Int(data[extOffset + 3])
                extOffset += 4

                switch extType {
                case 0x002B: // supported_versions
                    if extDataLen == 2, extOffset + 2 <= extEnd {
                        foundVersion = UInt16(data[extOffset]) << 8 | UInt16(data[extOffset + 1])
                    }

                case 0x0033: // key_share
                    if extOffset + 4 <= data.count {
                        let group = UInt16(data[extOffset]) << 8 | UInt16(data[extOffset + 1])
                        let keyLen = Int(data[extOffset + 2]) << 8 | Int(data[extOffset + 3])
                        if group == 0x001D && keyLen == 32, extOffset + 4 + 32 <= data.count {
                            keyShareData = data.subdata(in: (extOffset + 4)..<(extOffset + 4 + 32))
                        }
                    }

                default:
                    break
                }

                extOffset += extDataLen
            }

            // TLS 1.3 requires supported_versions extension with 0x0304
            if foundVersion != 0 && foundVersion != 0x0304 {
                logger.error("[TLS] Server selected TLS version 0x\(String(format: "%04x", foundVersion)) (only TLS 1.3 supported)")
                return nil
            }

            // If no supported_versions extension, server is TLS 1.2 or below
            if foundVersion == 0 {
                logger.error("[TLS] Server did not include supported_versions extension (TLS 1.2 or below not supported)")
                return nil
            }

            if let keyShare = keyShareData {
                return (keyShare, cipherSuite)
            }

            break
        }

        return nil
    }

    // MARK: - Encrypted Handshake Processing

    /// Consumes remaining TLS handshake records (encrypted), looking for Server Finished.
    ///
    /// For standard TLS (unlike Reality), also parses Certificate and CertificateVerify messages.
    private func consumeRemainingHandshake(
        buffer: Data,
        startOffset: Int = 0,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let keys = handshakeKeys, let kd = keyDerivation else {
            completion(.failure(TLSError.handshakeFailed("Missing handshake keys")))
            return
        }

        var offset = startOffset
        var fullTranscript = handshakeTranscript ?? Data()
        var foundServerFinished = false

        // Track transcript up to CertificateVerify for signature verification
        var transcriptBeforeCertVerify: Data? = nil
        var certificateVerifySignature: Data? = nil
        var certificateVerifyAlgorithm: UInt16 = 0

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == 0x14 || contentType == 0x16 {
                // ChangeCipherSpec or plaintext handshake — skip
                offset += 5 + recordLen
                continue
            } else if contentType == 0x17 {
                // Encrypted handshake (Application Data wrapper)
                let recordHeader = buffer.subdata(in: offset..<(offset + 5))
                let ciphertext = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))

                do {
                    let seqNum = serverHandshakeSeqNum
                    let decrypted = try TLSRecordCrypto.decryptRecord(
                        ciphertext: ciphertext,
                        key: SymmetricKey(data: keys.serverKey),
                        iv: keys.serverIV,
                        seqNum: seqNum,
                        recordHeader: recordHeader,
                        cipherSuite: kd.cipherSuite
                    )
                    serverHandshakeSeqNum += 1

                    // Parse decrypted handshake messages
                    var hsOffset = 0
                    while hsOffset + 4 <= decrypted.count {
                        let hsType = decrypted[hsOffset]
                        let hsLen = Int(decrypted[hsOffset + 1]) << 16 | Int(decrypted[hsOffset + 2]) << 8 | Int(decrypted[hsOffset + 3])

                        guard hsOffset + 4 + hsLen <= decrypted.count else { break }

                        let hsMessage = decrypted.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                        let hsBody = decrypted.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))

                        switch hsType {
                        case 0x08: // EncryptedExtensions
                            fullTranscript.append(hsMessage)

                        case 0x0B: // Certificate
                            fullTranscript.append(hsMessage)
                            parseCertificateMessage(hsBody)

                        case 0x0F: // CertificateVerify
                            // Save transcript before CertificateVerify for signature verification
                            transcriptBeforeCertVerify = fullTranscript
                            fullTranscript.append(hsMessage)
                            // Parse signature algorithm and signature
                            if hsBody.count >= 4 {
                                certificateVerifyAlgorithm = UInt16(hsBody[0]) << 8 | UInt16(hsBody[1])
                                let sigLen = Int(hsBody[2]) << 8 | Int(hsBody[3])
                                if hsBody.count >= 4 + sigLen {
                                    certificateVerifySignature = hsBody.subdata(in: 4..<(4 + sigLen))
                                }
                            }

                        case 0x14: // Finished
                            // Verify Server Finished BEFORE adding to transcript (RFC 8446 §4.4.4)
                            if let keys = self.handshakeKeys {
                                let expectedVerifyData = kd.computeFinishedVerifyData(
                                    trafficSecret: keys.serverTrafficSecret,
                                    transcript: fullTranscript
                                )
                                guard hsBody == expectedVerifyData else {
                                    logger.error("[TLS] Server Finished verification failed")
                                    completion(.failure(TLSError.handshakeFailed("Server Finished verification failed")))
                                    return
                                }
                            }
                            fullTranscript.append(hsMessage)
                            foundServerFinished = true

                        case 0x19: // CompressedCertificate (RFC 8879)
                            fullTranscript.append(hsMessage)
                            if let decompressed = decompressCertificate(hsBody) {
                                parseCertificateMessage(decompressed)
                            } else {
                                logger.warning("[TLS] Failed to decompress CompressedCertificate")
                            }

                        default:
                            fullTranscript.append(hsMessage)
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch {
                    logger.error("[TLS] Failed to decrypt handshake record: \(error.localizedDescription, privacy: .public)")
                }
            }

            offset += 5 + recordLen

            // Stop processing once Server Finished is found — any subsequent
            // records (e.g. NewSessionTicket) are encrypted with application keys
            // and must be handled by TLSRecordConnection, not the handshake loop.
            if foundServerFinished { break }
        }

        let processedOffset = offset
        handshakeTranscript = fullTranscript

        // Preserve any remaining data after the last processed record.
        // This may include post-handshake messages (NewSessionTicket) that are
        // encrypted with application keys and must be decrypted by TLSRecordConnection.
        let remainingBuffer = offset < buffer.count ? Data(buffer[offset...]) : nil
        self.postHandshakeBuffer = remainingBuffer

        if foundServerFinished {
            validateCertificate { [weak self] result in
                guard let self else { return }

                switch result {
                case .failure(let error):
                    completion(.failure(error))
                    return
                case .success:
                    break
                }

                // Verify CertificateVerify signature (skip when allowInsecure — no certs to verify against)
                if !self.serverCertificates.isEmpty,
                   let transcript = transcriptBeforeCertVerify,
                   let signature = certificateVerifySignature {
                    do {
                        try self.verifyCertificateVerify(
                            transcript: transcript,
                            algorithm: certificateVerifyAlgorithm,
                            signature: signature
                        )
                    } catch {
                        completion(.failure(error))
                        return
                    }
                }

                self.finishHandshake(fullTranscript: fullTranscript, completion: completion)
            }
        } else {
            // Need more handshake data
            guard let connection else {
                completion(.failure(TLSError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, _, error in
                guard let self else { return }

                if let error {
                    logger.warning("[TLS] Error receiving more handshake data: \(error.localizedDescription, privacy: .public)")
                }

                var newBuffer = buffer
                if let moreData {
                    newBuffer.append(moreData)
                }

                self.consumeRemainingHandshake(buffer: newBuffer, startOffset: processedOffset, completion: completion)
            }
        }
    }

    // MARK: - Certificate Parsing

    /// Parses the Certificate handshake message to extract DER-encoded X.509 certificates.
    ///
    /// TLS 1.3 Certificate message format:
    /// - 1 byte: certificate request context length (usually 0)
    /// - N bytes: certificate request context
    /// - 3 bytes: certificate list length
    /// - For each certificate:
    ///   - 3 bytes: certificate data length
    ///   - N bytes: DER-encoded certificate
    ///   - 2 bytes: extensions length
    ///   - N bytes: extensions
    private func parseCertificateMessage(_ body: Data) {
        serverCertificates.removeAll()

        guard body.count >= 4 else { return }

        var offset = 0

        // Certificate request context
        let contextLen = Int(body[offset])
        offset += 1 + contextLen

        guard offset + 3 <= body.count else { return }

        // Certificate list length (3 bytes)
        let listLen = Int(body[offset]) << 16 | Int(body[offset + 1]) << 8 | Int(body[offset + 2])
        offset += 3

        let listEnd = offset + listLen
        guard listEnd <= body.count else { return }

        while offset + 3 <= listEnd {
            // Certificate data length (3 bytes)
            let certLen = Int(body[offset]) << 16 | Int(body[offset + 1]) << 8 | Int(body[offset + 2])
            offset += 3

            guard offset + certLen <= listEnd else { break }

            let certData = body.subdata(in: offset..<(offset + certLen))
            offset += certLen

            if let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                serverCertificates.append(cert)
            }

            // Skip certificate extensions
            guard offset + 2 <= listEnd else { break }
            let extLen = Int(body[offset]) << 8 | Int(body[offset + 1])
            offset += 2 + extLen
        }
    }

    // MARK: - Certificate Validation

    /// Validates the server certificate chain using Apple's Security framework.
    ///
    /// First tries standard system trust evaluation. If that fails, checks
    /// whether the leaf certificate's SHA-256 fingerprint is in the user's
    /// trusted certificate list (stored in App Group UserDefaults).
    private func validateCertificate(completion: @escaping (Result<Void, Error>) -> Void) {
        if let defaults = UserDefaults(suiteName: "group.com.argsment.Anywhere"),
           defaults.bool(forKey: "allowInsecure") {
            completion(.success(()))
            return
        }

        guard !serverCertificates.isEmpty else {
            completion(.failure(TLSError.certificateValidationFailed("No server certificates received")))
            return
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, configuration.serverName as CFString)

        let status = SecTrustCreateWithCertificates(
            serverCertificates as CFArray,
            policy,
            &trust
        )

        guard status == errSecSuccess, let trust else {
            completion(.failure(TLSError.certificateValidationFailed("Failed to create trust object")))
            return
        }

        var cfError: CFError?
        let isValid = SecTrustEvaluateWithError(trust, &cfError)
        if isValid {
            completion(.success(()))
        } else {
            // System trust failed — check user-trusted certificate fingerprints
            if let leafCert = serverCertificates.first,
               Self.isUserTrusted(certificate: leafCert) {
                completion(.success(()))
                return
            }
            let message = (cfError as Error?)?.localizedDescription ?? "Certificate evaluation failed"
            logger.error("[TLS] Certificate validation failed: \(message, privacy: .public)")
            completion(.failure(TLSError.certificateValidationFailed(message)))
        }
    }

    // MARK: - CertificateVerify

    /// Verifies the CertificateVerify signature against the handshake transcript.
    ///
    /// The signature is computed over:
    /// `64 spaces + "TLS 1.3, server CertificateVerify\0" + transcript_hash`
    private func verifyCertificateVerify(
        transcript: Data,
        algorithm: UInt16,
        signature: Data
    ) throws {
        guard let kd = keyDerivation else {
            throw TLSError.handshakeFailed("Missing key derivation")
        }

        guard let serverCert = serverCertificates.first else {
            throw TLSError.certificateValidationFailed("No server certificate for CertificateVerify")
        }

        guard let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.certificateValidationFailed("Failed to extract public key from certificate")
        }

        // Build the content to verify:
        // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
        let transcriptHash = kd.transcriptHash(transcript)

        var content = Data(repeating: 0x20, count: 64) // 64 spaces
        content.append("TLS 1.3, server CertificateVerify".data(using: .ascii)!)
        content.append(0x00)
        content.append(transcriptHash)

        let secAlgorithm = secKeyAlgorithm(for: algorithm)

        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            serverPublicKey,
            secAlgorithm,
            content as CFData,
            signature as CFData,
            &error
        )

        if !isValid {
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            throw TLSError.certificateValidationFailed("CertificateVerify failed: \(message)")
        }
    }

    /// Maps TLS signature algorithm identifier to Security.framework algorithm.
    private func secKeyAlgorithm(for tlsAlgorithm: UInt16) -> SecKeyAlgorithm {
        switch tlsAlgorithm {
        case 0x0403: // ecdsa_secp256r1_sha256
            return .ecdsaSignatureMessageX962SHA256
        case 0x0503: // ecdsa_secp384r1_sha384
            return .ecdsaSignatureMessageX962SHA384
        case 0x0603: // ecdsa_secp521r1_sha512
            return .ecdsaSignatureMessageX962SHA512
        case 0x0804: // rsa_pss_rsae_sha256
            return .rsaSignatureMessagePSSSHA256
        case 0x0805: // rsa_pss_rsae_sha384
            return .rsaSignatureMessagePSSSHA384
        case 0x0806: // rsa_pss_rsae_sha512
            return .rsaSignatureMessagePSSSHA512
        case 0x0401: // rsa_pkcs1_sha256
            return .rsaSignatureMessagePKCS1v15SHA256
        default:
            return .rsaSignatureMessagePSSSHA256
        }
    }

    // MARK: - Finish Handshake

    /// Derives application keys and sends Client Finished to complete the handshake.
    private func finishHandshake(
        fullTranscript: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let kd = keyDerivation, let hs = handshakeSecret else {
            completion(.failure(TLSError.handshakeFailed("Missing handshake state")))
            return
        }

        applicationKeys = kd.deriveApplicationKeys(handshakeSecret: hs, fullTranscript: fullTranscript)

        sendClientFinished { [weak self] error in
            guard let self else { return }

            if let error {
                logger.error("[TLS] Failed to send Client Finished: \(error.localizedDescription, privacy: .public)")
                completion(.failure(TLSError.handshakeFailed("Failed to send Client Finished")))
                return
            }

            guard let appKeys = self.applicationKeys else {
                logger.error("[TLS] Application keys not available")
                completion(.failure(TLSError.handshakeFailed("Application keys not available")))
                return
            }

            let tlsConnection = TLSRecordConnection(
                clientKey: appKeys.clientKey,
                clientIV: appKeys.clientIV,
                serverKey: appKeys.serverKey,
                serverIV: appKeys.serverIV,
                cipherSuite: self.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
            )
            tlsConnection.connection = self.connection
            self.connection = nil

            // Pre-populate with any data received after Server Finished
            // (e.g. NewSessionTicket records) so TLSRecordConnection can
            // decrypt them with the correct application keys.
            if let remaining = self.postHandshakeBuffer, !remaining.isEmpty {
                tlsConnection.prependToReceiveBuffer(remaining)
            }

            self.clearHandshakeState()
            completion(.success(tlsConnection))
        }
    }

    // MARK: - CompressedCertificate (RFC 8879)

    /// Decompresses a CompressedCertificate message body.
    ///
    /// Format: algorithm(2) + uncompressed_length(3) + compressed_data(...)
    /// Returns the inner Certificate message body (without the handshake header).
    private func decompressCertificate(_ body: Data) -> Data? {
        guard body.count >= 5 else { return nil }

        let algorithm = UInt16(body[0]) << 8 | UInt16(body[1])
        let uncompressedLength = Int(body[2]) << 16 | Int(body[3]) << 8 | Int(body[4])
        let compressed = body.subdata(in: 5..<body.count)

        guard uncompressedLength > 0 && uncompressedLength <= 1 << 24 else { return nil }

        switch algorithm {
        case 0x0001: // zlib
            return zlibDecompress(compressed, expectedSize: uncompressedLength)
        case 0x0002: // brotli — not natively available on Apple platforms
            logger.warning("[TLS] Brotli certificate compression not supported")
            return nil
        case 0x0003: // zstd — not natively available on Apple platforms
            logger.warning("[TLS] Zstd certificate compression not supported")
            return nil
        default:
            logger.warning("[TLS] Unknown certificate compression algorithm: 0x\(String(format: "%04x", algorithm))")
            return nil
        }
    }

    /// Decompresses zlib-compressed data using the Apple Compression framework.
    private func zlibDecompress(_ compressed: Data, expectedSize: Int) -> Data? {
        var decompressed = Data(count: expectedSize)
        let decodedSize = decompressed.withUnsafeMutableBytes { destPtr in
            compressed.withUnsafeBytes { srcPtr in
                compression_decode_buffer(
                    destPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    expectedSize,
                    srcPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    compressed.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        guard decodedSize > 0 else {
            logger.warning("[TLS] zlib decompression failed")
            return nil
        }
        return Data(decompressed.prefix(decodedSize))
    }

    // MARK: - Client Finished

    /// Sends the ChangeCipherSpec and encrypted Client Finished messages.
    private func sendClientFinished(completion: @escaping (Error?) -> Void) {
        guard let keys = handshakeKeys,
              let transcript = handshakeTranscript,
              let kd = keyDerivation else {
            completion(TLSError.handshakeFailed("Missing handshake keys"))
            return
        }

        // ChangeCipherSpec record
        var ccsRecord = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

        // Build and encrypt Client Finished
        let verifyData = kd.computeFinishedVerifyData(clientTrafficSecret: keys.clientTrafficSecret, transcript: transcript)

        var finishedMsg = Data()
        finishedMsg.append(0x14) // Handshake type: Finished
        finishedMsg.append(0x00)
        finishedMsg.append(0x00)
        finishedMsg.append(UInt8(verifyData.count))
        finishedMsg.append(verifyData)

        do {
            let finishedRecord = try TLSRecordCrypto.encryptHandshakeRecord(
                plaintext: finishedMsg,
                key: SymmetricKey(data: keys.clientKey),
                iv: keys.clientIV,
                seqNum: 0,
                cipherSuite: keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
            )
            ccsRecord.append(finishedRecord)

            guard let connection else {
                completion(TLSError.connectionFailed("Connection cancelled"))
                return
            }
            connection.send(data: ccsRecord, completion: completion)
        } catch {
            completion(error)
        }
    }

    // MARK: - Helpers

    /// Checks whether the certificate's SHA-256 fingerprint is in the user's trusted list.
    ///
    /// Reads `trustedCertificateSHA256s` from the App Group UserDefaults (shared with
    /// the main app's ``CertificateStore``).
    private static func isUserTrusted(certificate: SecCertificate) -> Bool {
        guard let defaults = UserDefaults(suiteName: "group.com.argsment.Anywhere"),
              let trusted = defaults.stringArray(forKey: "trustedCertificateSHA256s"),
              !trusted.isEmpty else {
            return false
        }
        let certData = SecCertificateCopyData(certificate) as Data
        let sha256 = SHA256.hash(data: certData).map { String(format: "%02x", $0) }.joined()
        return trusted.contains(sha256)
    }

    /// Frees handshake-only state to reduce memory after the connection is established.
    private func clearHandshakeState() {
        ephemeralPrivateKey = nil
        storedClientHello = nil
        keyDerivation = nil
        handshakeSecret = nil
        handshakeKeys = nil
        applicationKeys = nil
        handshakeTranscript = nil
        serverHandshakeSeqNum = 0
        postHandshakeBuffer = nil
        serverCertificates.removeAll()
    }
}
