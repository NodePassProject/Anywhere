//
//  TLSClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Security
import Compression
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "TLS")

// MARK: - ServerHello Result

/// The result of parsing a ServerHello message.
private enum ServerHelloResult {
    /// TLS 1.3: server provided a key_share extension with an X25519 public key.
    case tls13(keyShare: Data, cipherSuite: UInt16)
    /// TLS 1.2 (or below): standard handshake without key_share.
    case tls12(cipherSuite: UInt16, serverRandom: Data, version: UInt16, extendedMasterSecret: Bool)
}

// MARK: - TLSClient

/// Client for establishing standard TLS 1.0–1.3 connections.
///
/// Performs a TLS handshake with X.509 certificate validation:
/// - Builds a ClientHello with browser-fingerprinted extensions.
/// - Detects the negotiated TLS version from the ServerHello.
/// - **TLS 1.3**: Derives HKDF-based keys, validates encrypted Certificate/CertificateVerify/Finished.
/// - **TLS 1.2**: Processes plaintext Certificate/ServerKeyExchange/ServerHelloDone,
///   derives PRF-based keys, exchanges ChangeCipherSpec and Finished.
///
/// After a successful handshake, returns a ``TLSRecordConnection`` that wraps
/// the underlying transport with TLS record encryption/decryption.
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

    // TLS 1.2 session state (cleared after handshake)
    private var clientRandom: Data?
    private var serverRandom: Data?
    private var masterSecret: Data?
    private var tls12CipherSuite: UInt16 = 0
    private var negotiatedVersion: UInt16 = 0
    /// Whether the server echoed the extended_master_secret extension (RFC 7627).
    private var useExtendedMasterSecret = false
    /// ECDHE private key for TLS 1.2 (P-256)
    private var ecdhP256PrivateKey: P256.KeyAgreement.PrivateKey?
    /// ECDHE private key for TLS 1.2 (P-384)
    private var ecdhP384PrivateKey: P384.KeyAgreement.PrivateKey?
    /// Handshake transcript for TLS 1.2 Finished computation
    private var tls12Transcript: Data?

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
    /// - Parameter configuration: The TLS configuration (SNI, ALPN, fingerprint, version constraints).
    init(configuration: TLSConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API

    /// Connects to a server and performs the TLS handshake.
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

    /// Connects over an existing proxy tunnel and performs the TLS handshake.
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

    /// Performs the TLS handshake: sends ClientHello, processes ServerHello,
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

    /// Builds a TLS ClientHello with browser fingerprinting and random SessionId.
    ///
    /// - Parameter privateKey: The ephemeral X25519 private key for this connection.
    /// - Returns: A complete TLS record containing the ClientHello.
    private func buildTLSClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        _ = random.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        clientRandom = random

        // Standard TLS: random 32-byte session ID (no Reality metadata)
        var sessionId = Data(count: 32)
        _ = sessionId.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let rawClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: sessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            alpn: configuration.alpn ?? ["h2", "http/1.1"],
            omitPQKeyShares: true
        )

        return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: rawClientHello)
    }

    // MARK: - Server Response Processing

    /// Receives and processes the server's TLS response.
    ///
    /// Buffers partial reads until at least one complete TLS record header (5 bytes)
    /// is available. The server may deliver data in small chunks, especially when
    /// the connection is tunneled through a proxy chain.
    private func receiveServerResponse(
        buffer: Data = Data(),
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Already have enough data to inspect
        if buffer.count >= 5 {
            let contentType = buffer[0]

            if contentType == 0x16 { // Handshake
                self.continueReceivingHandshake(buffer: buffer, completion: completion)
            } else if contentType == 0x15 { // Alert
                let alertLevel = buffer.count > 5 ? buffer[5] : 0
                let alertDesc = buffer.count > 6 ? buffer[6] : 0
                logger.error("[TLS] TLS Alert: level=\(alertLevel, privacy: .public), desc=\(alertDesc, privacy: .public)")
                completion(.failure(TLSError.handshakeFailed("TLS Alert: level=\(alertLevel), desc=\(alertDesc)")))
            } else {
                logger.error("[TLS] Unexpected content type: 0x\(String(format: "%02x", contentType), privacy: .public)")
                completion(.failure(TLSError.handshakeFailed("Unexpected content type: \(contentType)")))
            }
            return
        }

        // Need more data
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

            guard let data, !data.isEmpty else {
                logger.error("[TLS] No server response (connection closed)")
                completion(.failure(TLSError.handshakeFailed("No server response")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(data)
            self.receiveServerResponse(buffer: newBuffer, completion: completion)
        }
    }

    /// Continues receiving handshake messages until ServerHello is complete.
    private func continueReceivingHandshake(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                completion(.failure(TLSError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, isComplete, error in
                guard let self else { return }

                if let error {
                    logger.error("[TLS] Error receiving more data: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                guard let moreData, !moreData.isEmpty else {
                    // Connection closed (EOF) before ServerHello was received
                    completion(.failure(TLSError.handshakeFailed("Connection closed before ServerHello")))
                    return
                }

                var newBuffer = buffer
                newBuffer.append(moreData)

                self.continueReceivingHandshake(buffer: newBuffer, completion: completion)
            }
            return
        }

        guard let serverHelloResult = parseServerHello(data: buffer),
              let clientHello = storedClientHello else {
            logger.error("[TLS] Failed to parse ServerHello or missing keys")
            completion(.failure(TLSError.handshakeFailed("Failed to parse ServerHello")))
            return
        }

        switch serverHelloResult {
        case .tls13(let serverKeyShare, let cipherSuite):
            handleTLS13Handshake(
                buffer: buffer,
                serverKeyShare: serverKeyShare,
                cipherSuite: cipherSuite,
                clientHello: clientHello,
                completion: completion
            )

        case .tls12(let cipherSuite, let srvRandom, let version, let ems):
            self.serverRandom = srvRandom
            self.tls12CipherSuite = cipherSuite
            self.negotiatedVersion = version
            self.useExtendedMasterSecret = ems
            handleTLS12Handshake(
                buffer: buffer,
                clientHello: clientHello,
                completion: completion
            )
        }
    }

    // MARK: - ServerHello Parsing

    /// Returns `true` when the buffer contains at least one complete TLS Handshake
    /// record whose payload starts with a ServerHello (type 0x02).
    private func bufferContainsCompleteServerHello(_ buffer: Data) -> Bool {
        var offset = 0
        while offset + 5 <= buffer.count {
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if offset + 5 + recordLen > buffer.count { return false }

            if buffer[offset] == 0x16 && offset + 5 < buffer.count && buffer[offset + 5] == 0x02 {
                return true
            }

            offset += 5 + recordLen
        }

        return false
    }

    /// Extracts only the ServerHello handshake message (type 0x02 + length + body)
    /// from the buffer, without the TLS record header.
    ///
    /// Unlike the previous version, this correctly parses the handshake header
    /// to return only the ServerHello — not the entire record payload (which may
    /// contain coalesced Certificate/SKE/SHD messages in the same record).
    private func extractServerHelloMessage(from buffer: Data) -> Data {
        var offset = 0
        while offset + 5 < buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if contentType == 0x16 {
                let recordStart = offset + 5
                let recordEnd = min(recordStart + recordLen, buffer.count)
                // Parse handshake messages within the record to find ServerHello
                var hsOffset = recordStart
                while hsOffset + 4 <= recordEnd {
                    let hsType = buffer[hsOffset]
                    let hsLen = Int(buffer[hsOffset + 1]) << 16 | Int(buffer[hsOffset + 2]) << 8 | Int(buffer[hsOffset + 3])
                    guard hsOffset + 4 + hsLen <= recordEnd else { break }
                    if hsType == 0x02 {
                        // Return only the ServerHello handshake message
                        return buffer.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                    }
                    hsOffset += 4 + hsLen
                }
            }

            offset += 5 + recordLen
        }
        return Data()
    }

    /// Parses the ServerHello to detect the TLS version and extract key parameters.
    ///
    /// - Returns: `.tls13(keyShare, cipherSuite)` if TLS 1.3 was negotiated,
    ///            `.tls12(cipherSuite, serverRandom, version)` if TLS 1.2 or below,
    ///            `nil` if parsing fails.
    private func parseServerHello(data: Data) -> ServerHelloResult? {
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

            // Legacy version from the ServerHello header
            let legacyVersion = UInt16(data[offset + 4]) << 8 | UInt16(data[offset + 5])

            // Server random (32 bytes)
            let srvRandom = data.subdata(in: randomOffset..<(randomOffset + 32))

            // Check for HelloRetryRequest (RFC 8446 §4.1.3)
            if srvRandom == Self.helloRetryRequestRandom {
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
            var hasEMS = false

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

                case 0x0017: // extended_master_secret (RFC 7627)
                    hasEMS = true

                default:
                    break
                }

                extOffset += extDataLen
            }

            // TLS 1.3: supported_versions extension present with 0x0304
            if foundVersion == 0x0304 {
                if let keyShare = keyShareData {
                    return .tls13(keyShare: keyShare, cipherSuite: cipherSuite)
                }
                logger.error("[TLS] TLS 1.3 ServerHello missing key_share")
                return nil
            }

            // TLS 1.2 or below: no supported_versions extension, use legacy version
            let version = foundVersion != 0 ? foundVersion : legacyVersion
            return .tls12(cipherSuite: cipherSuite, serverRandom: srvRandom, version: version, extendedMasterSecret: hasEMS)
        }

        return nil
    }

    // MARK: - TLS 1.3 Handshake

    /// Handles the TLS 1.3 handshake path after ServerHello.
    private func handleTLS13Handshake(
        buffer: Data,
        serverKeyShare: Data,
        cipherSuite: UInt16,
        clientHello: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let privateKey = ephemeralPrivateKey else {
            completion(.failure(TLSError.handshakeFailed("No ephemeral key")))
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
            negotiatedVersion = 0x0304

            consumeRemainingTLS13Handshake(buffer: buffer, completion: completion)
        } catch {
            logger.error("[TLS] Failed to derive TLS 1.3 keys: \(error.localizedDescription, privacy: .public)")
            completion(.failure(TLSError.handshakeFailed("Key derivation failed")))
        }
    }

    // MARK: - TLS 1.3 Encrypted Handshake Processing

    /// Consumes remaining TLS 1.3 handshake records (encrypted), looking for Server Finished.
    private func consumeRemainingTLS13Handshake(
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

        var transcriptBeforeCertVerify: Data? = nil
        var certificateVerifySignature: Data? = nil
        var certificateVerifyAlgorithm: UInt16 = 0

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == 0x14 || contentType == 0x16 {
                offset += 5 + recordLen
                continue
            } else if contentType == 0x17 {
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
                            parseTLS13CertificateMessage(hsBody)

                        case 0x0F: // CertificateVerify
                            transcriptBeforeCertVerify = fullTranscript
                            fullTranscript.append(hsMessage)
                            if hsBody.count >= 4 {
                                certificateVerifyAlgorithm = UInt16(hsBody[0]) << 8 | UInt16(hsBody[1])
                                let sigLen = Int(hsBody[2]) << 8 | Int(hsBody[3])
                                if hsBody.count >= 4 + sigLen {
                                    certificateVerifySignature = hsBody.subdata(in: 4..<(4 + sigLen))
                                }
                            }

                        case 0x14: // Finished
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
                    logger.error("[TLS] Failed to decrypt handshake record: \(error.localizedDescription, privacy: .public)")
                }
            }

            offset += 5 + recordLen

            if foundServerFinished { break }
        }

        let processedOffset = offset
        handshakeTranscript = fullTranscript

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

                self.finishTLS13Handshake(fullTranscript: fullTranscript, completion: completion)
            }
        } else {
            guard let connection else {
                completion(.failure(TLSError.connectionFailed("Connection cancelled")))
                return
            }
            connection.receive(maximumLength: 65536) { [weak self] moreData, isComplete, error in
                guard let self else { return }

                if let error {
                    logger.warning("[TLS] Error receiving more handshake data: \(error.localizedDescription, privacy: .public)")
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                guard let moreData, !moreData.isEmpty else {
                    // Connection closed (EOF) before TLS 1.3 Server Finished
                    completion(.failure(TLSError.handshakeFailed("Connection closed before TLS 1.3 handshake completed")))
                    return
                }

                var newBuffer = buffer
                newBuffer.append(moreData)

                self.consumeRemainingTLS13Handshake(buffer: newBuffer, startOffset: processedOffset, completion: completion)
            }
        }
    }

    // MARK: - TLS 1.3 Certificate Parsing

    /// Parses the TLS 1.3 Certificate handshake message to extract DER-encoded X.509 certificates.
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

    // MARK: - TLS 1.3 Finish Handshake

    /// Derives application keys and sends Client Finished to complete the TLS 1.3 handshake.
    private func finishTLS13Handshake(
        fullTranscript: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let kd = keyDerivation, let hs = handshakeSecret else {
            completion(.failure(TLSError.handshakeFailed("Missing handshake state")))
            return
        }

        applicationKeys = kd.deriveApplicationKeys(handshakeSecret: hs, fullTranscript: fullTranscript)

        sendTLS13ClientFinished { [weak self] error in
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

            if let remaining = self.postHandshakeBuffer, !remaining.isEmpty {
                tlsConnection.prependToReceiveBuffer(remaining)
            }

            self.clearHandshakeState()
            completion(.success(tlsConnection))
        }
    }

    /// Sends the ChangeCipherSpec and encrypted Client Finished messages (TLS 1.3).
    private func sendTLS13ClientFinished(completion: @escaping (Error?) -> Void) {
        guard let keys = handshakeKeys,
              let transcript = handshakeTranscript,
              let kd = keyDerivation else {
            completion(TLSError.handshakeFailed("Missing handshake keys"))
            return
        }

        // ChangeCipherSpec record
        var ccsRecord = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

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

    // MARK: - TLS 1.2 Handshake

    /// Handles the TLS 1.2 handshake path after ServerHello.
    ///
    /// Processes plaintext Certificate, ServerKeyExchange, ServerHelloDone messages,
    /// then sends ClientKeyExchange + ChangeCipherSpec + Finished.
    private func handleTLS12Handshake(
        buffer: Data,
        clientHello: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Start transcript with ClientHello + ServerHello
        let serverHello = extractServerHelloMessage(from: buffer)
        var transcript = Data()
        transcript.append(clientHello)
        transcript.append(serverHello)
        self.tls12Transcript = transcript

        // Collect all plaintext handshake messages following ServerHello
        receiveTLS12HandshakeMessages(buffer: buffer, completion: completion)
    }

    /// Receives TLS 1.2 handshake messages until ServerHelloDone (0x0E) is found.
    private func receiveTLS12HandshakeMessages(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Check if we have all needed messages (ending with ServerHelloDone)
        if let result = parseTLS12HandshakeMessages(buffer: buffer) {
            processTLS12HandshakeResult(result, buffer: buffer, completion: completion)
            return
        }

        // Need more data
        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive(maximumLength: 65536) { [weak self] moreData, isComplete, error in
            guard let self else { return }

            if let error {
                logger.error("[TLS] Error receiving TLS 1.2 handshake: \(error.localizedDescription, privacy: .public)")
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let moreData, !moreData.isEmpty else {
                // Connection closed (EOF) before ServerHelloDone was received
                completion(.failure(TLSError.handshakeFailed("Connection closed before TLS 1.2 handshake completed")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(moreData)
            self.receiveTLS12HandshakeMessages(buffer: newBuffer, completion: completion)
        }
    }

    /// TLS 1.2 handshake message parsing result.
    private struct TLS12HandshakeMessages {
        var certificates: [SecCertificate] = []
        var certificateDERs: [Data] = []
        var serverKeyExchange: Data?
        var serverHelloDoneOffset: Int = 0
        /// All handshake message bytes (for transcript)
        var handshakeBytes: Data = Data()
    }

    /// Parses TLS 1.2 handshake messages from the buffer.
    /// Returns nil if ServerHelloDone not yet received.
    private func parseTLS12HandshakeMessages(buffer: Data) -> TLS12HandshakeMessages? {
        var result = TLS12HandshakeMessages()
        var offset = 0
        var foundServerHelloDone = false
        var pastServerHello = false

        // Skip over TLS records, extracting handshake messages
        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == 0x16 { // Handshake
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                var hsOffset = 0

                while hsOffset + 4 <= recordBody.count {
                    let hsType = recordBody[hsOffset]
                    let hsLen = Int(recordBody[hsOffset + 1]) << 16 | Int(recordBody[hsOffset + 2]) << 8 | Int(recordBody[hsOffset + 3])

                    guard hsOffset + 4 + hsLen <= recordBody.count else { break }

                    let hsMessage = recordBody.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                    let hsBody = recordBody.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))

                    switch hsType {
                    case 0x02: // ServerHello (already parsed, but add to transcript tracking)
                        pastServerHello = true

                    case 0x0B: // Certificate
                        if pastServerHello {
                            result.handshakeBytes.append(hsMessage)
                            parseTLS12CertificateMessage(hsBody, into: &result)
                        }

                    case 0x0C: // ServerKeyExchange
                        result.handshakeBytes.append(hsMessage)
                        result.serverKeyExchange = hsBody

                    case 0x0E: // ServerHelloDone
                        result.handshakeBytes.append(hsMessage)
                        result.serverHelloDoneOffset = offset + 5 + hsOffset + 4 + hsLen
                        foundServerHelloDone = true

                    default:
                        if pastServerHello {
                            result.handshakeBytes.append(hsMessage)
                        }
                    }

                    hsOffset += 4 + hsLen
                }
            }

            offset += 5 + recordLen
        }

        return foundServerHelloDone ? result : nil
    }

    /// Parses TLS 1.2 Certificate message (no request context, unlike TLS 1.3).
    private func parseTLS12CertificateMessage(_ body: Data, into result: inout TLS12HandshakeMessages) {
        guard body.count >= 3 else { return }

        var offset = 0
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

            result.certificateDERs.append(certData)
            if let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                result.certificates.append(cert)
            }
        }
    }

    /// Processes parsed TLS 1.2 handshake messages: validates cert, performs key exchange, sends Finished.
    private func processTLS12HandshakeResult(
        _ messages: TLS12HandshakeMessages,
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        serverCertificates = messages.certificates

        // Add Certificate + ServerKeyExchange + ServerHelloDone to transcript
        tls12Transcript?.append(messages.handshakeBytes)

        // Validate certificate first
        validateCertificate { [weak self] result in
            guard let self else { return }

            switch result {
            case .failure(let error):
                completion(.failure(error))
                return
            case .success:
                break
            }

            // Perform key exchange
            do {
                let preMasterSecret: Data
                let clientKeyExchangeBody: Data

                if TLSCipherSuite.isECDHE(self.tls12CipherSuite) {
                    guard let ske = messages.serverKeyExchange else {
                        completion(.failure(TLSError.handshakeFailed("ECDHE cipher suite but no ServerKeyExchange")))
                        return
                    }
                    // Verify ServerKeyExchange signature
                    try self.verifyServerKeyExchange(ske, certificates: messages.certificates)
                    (preMasterSecret, clientKeyExchangeBody) = try self.processECDHEServerKeyExchange(ske)
                } else {
                    // RSA key exchange
                    (preMasterSecret, clientKeyExchangeBody) = try self.processRSAKeyExchange(certificates: messages.certificates)
                }

                self.completeTLS12Handshake(
                    preMasterSecret: preMasterSecret,
                    clientKeyExchangeBody: clientKeyExchangeBody,
                    remainingBuffer: buffer.count > messages.serverHelloDoneOffset ? Data(buffer[messages.serverHelloDoneOffset...]) : nil,
                    completion: completion
                )
            } catch {
                completion(.failure(error))
            }
        }
    }

    // MARK: - TLS 1.2 ECDHE Key Exchange

    /// Parses ServerKeyExchange for ECDHE and performs ECDH key agreement.
    ///
    /// ServerKeyExchange format:
    /// - curve_type(1) = 0x03 (named_curve)
    /// - named_curve(2)
    /// - public_key_len(1)
    /// - public_key(N)
    /// - [signature follows]
    private func processECDHEServerKeyExchange(_ body: Data) throws -> (preMasterSecret: Data, clientKeyExchange: Data) {
        guard body.count >= 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange too short")
        }

        let curveType = body[0]
        guard curveType == 0x03 else {
            throw TLSError.handshakeFailed("Unsupported curve type: \(curveType)")
        }

        let namedCurve = UInt16(body[1]) << 8 | UInt16(body[2])
        let pubKeyLen = Int(body[3])
        guard body.count >= 4 + pubKeyLen else {
            throw TLSError.handshakeFailed("ServerKeyExchange public key truncated")
        }

        let serverPubKeyData = body.subdata(in: 4..<(4 + pubKeyLen))

        switch namedCurve {
        case 0x001D: // X25519
            let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPubKeyData)
            // Reuse the ephemeral X25519 key we already generated
            guard let privateKey = ephemeralPrivateKey else {
                throw TLSError.handshakeFailed("No ephemeral key")
            }
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            // ClientKeyExchange: length(1) + raw key(32)
            var cke = Data()
            let pubKey = privateKey.publicKey.rawRepresentation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        case 0x0017: // secp256r1 (P-256)
            let serverPubKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPubKeyData)
            let clientKey = P256.KeyAgreement.PrivateKey()
            self.ecdhP256PrivateKey = clientKey
            let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            // ClientKeyExchange: length(1) + uncompressed point (65 bytes)
            var cke = Data()
            let pubKey = clientKey.publicKey.x963Representation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        case 0x0018: // secp384r1 (P-384)
            let serverPubKey = try P384.KeyAgreement.PublicKey(x963Representation: serverPubKeyData)
            let clientKey = P384.KeyAgreement.PrivateKey()
            self.ecdhP384PrivateKey = clientKey
            let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            var cke = Data()
            let pubKey = clientKey.publicKey.x963Representation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        default:
            throw TLSError.handshakeFailed("Unsupported ECDHE curve: 0x\(String(format: "%04x", namedCurve))")
        }
    }

    /// Verifies the ServerKeyExchange signature using the server certificate.
    private func verifyServerKeyExchange(_ body: Data, certificates: [SecCertificate]) throws {
        guard let serverCert = certificates.first else {
            throw TLSError.certificateValidationFailed("No server certificate for ServerKeyExchange verification")
        }

        guard body.count >= 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange too short for signature")
        }

        // Parse: curve_type(1) + named_curve(2) + pubkey_len(1) + pubkey(N)
        let pubKeyLen = Int(body[3])
        let paramsEnd = 4 + pubKeyLen
        guard body.count >= paramsEnd + 4 else { return }  // No signature = no verification needed

        let sigAlgorithm = UInt16(body[paramsEnd]) << 8 | UInt16(body[paramsEnd + 1])
        let sigLen = Int(body[paramsEnd + 2]) << 8 | Int(body[paramsEnd + 3])
        guard body.count >= paramsEnd + 4 + sigLen else {
            throw TLSError.handshakeFailed("ServerKeyExchange signature truncated")
        }

        let signature = body.subdata(in: (paramsEnd + 4)..<(paramsEnd + 4 + sigLen))

        guard let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.certificateValidationFailed("Failed to extract public key")
        }

        // Content to verify: client_random(32) + server_random(32) + server_params
        guard let cRandom = clientRandom, let sRandom = serverRandom else {
            throw TLSError.handshakeFailed("Missing randoms for signature verification")
        }

        var content = cRandom
        content.append(sRandom)
        content.append(body.subdata(in: 0..<paramsEnd))

        let secAlgorithm = secKeyAlgorithm(for: sigAlgorithm)

        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            serverPublicKey,
            secAlgorithm,
            content as CFData,
            signature as CFData,
            &error
        )

        if !isValid {
            // Allow if allowInsecure is set
            if let defaults = UserDefaults(suiteName: "group.com.argsment.Anywhere"),
               defaults.bool(forKey: "allowInsecure") {
                return
            }
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            throw TLSError.certificateValidationFailed("ServerKeyExchange signature failed: \(message)")
        }
    }

    // MARK: - TLS 1.2 RSA Key Exchange

    /// Performs RSA key exchange: encrypts a random pre-master secret with the server's RSA public key.
    private func processRSAKeyExchange(certificates: [SecCertificate]) throws -> (preMasterSecret: Data, clientKeyExchange: Data) {
        guard let serverCert = certificates.first,
              let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.handshakeFailed("No server certificate for RSA key exchange")
        }

        // Pre-master secret: version(2) + random(46)
        // RFC 5246 §7.4.7.1: version must be the latest (newest) version supported
        // by the client, which is always 0x0303 (TLS 1.2) in the ClientHello.
        // Matches utls key_agreement.go: uses clientHello.vers (always VersionTLS12).
        var preMasterSecret = Data(count: 48)
        preMasterSecret[0] = 0x03
        preMasterSecret[1] = 0x03
        _ = preMasterSecret.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 46, ptr.baseAddress! + 2)
        }

        // RSA-PKCS1 encrypt
        var encryptError: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            serverPublicKey,
            .rsaEncryptionPKCS1,
            preMasterSecret as CFData,
            &encryptError
        ) as Data? else {
            let msg = encryptError?.takeRetainedValue().localizedDescription ?? "RSA encryption failed"
            throw TLSError.handshakeFailed("RSA key exchange failed: \(msg)")
        }

        // ClientKeyExchange: length(2) + encrypted_premaster
        var cke = Data()
        cke.append(UInt8((encrypted.count >> 8) & 0xFF))
        cke.append(UInt8(encrypted.count & 0xFF))
        cke.append(encrypted)

        return (preMasterSecret, cke)
    }

    // MARK: - TLS 1.2 Key Derivation & Finish

    /// Completes the TLS 1.2 handshake: derives keys, sends CKE + CCS + Finished,
    /// receives server CCS + Finished.
    private func completeTLS12Handshake(
        preMasterSecret: Data,
        clientKeyExchangeBody: Data,
        remainingBuffer: Data?,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let cRandom = clientRandom, let sRandom = serverRandom else {
            completion(.failure(TLSError.handshakeFailed("Missing randoms")))
            return
        }

        let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)

        // Build ClientKeyExchange handshake message FIRST — needed for EMS session hash
        var ckeMessage = Data()
        ckeMessage.append(0x10) // Handshake type: ClientKeyExchange
        let ckeLen = clientKeyExchangeBody.count
        ckeMessage.append(UInt8((ckeLen >> 16) & 0xFF))
        ckeMessage.append(UInt8((ckeLen >> 8) & 0xFF))
        ckeMessage.append(UInt8(ckeLen & 0xFF))
        ckeMessage.append(clientKeyExchangeBody)

        // Add ClientKeyExchange to transcript
        tls12Transcript?.append(ckeMessage)

        guard let transcript = tls12Transcript else {
            completion(.failure(TLSError.handshakeFailed("Missing transcript")))
            return
        }

        // Derive master secret
        // RFC 7627: If extended_master_secret was negotiated, the seed is the
        // session hash (Hash of all handshake messages up to and including CKE),
        // not clientRandom + serverRandom.
        // Matches utls handshake_client.go lines 810-817.
        let ms: Data
        if useExtendedMasterSecret {
            let sessionHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
            ms = TLS12KeyDerivation.extendedMasterSecret(
                preMasterSecret: preMasterSecret,
                sessionHash: sessionHash,
                useSHA384: useSHA384
            )
        } else {
            ms = TLS12KeyDerivation.masterSecret(
                preMasterSecret: preMasterSecret,
                clientRandom: cRandom,
                serverRandom: sRandom,
                useSHA384: useSHA384
            )
        }
        self.masterSecret = ms

        // Derive key material
        let macLen = TLSCipherSuite.macLength(tls12CipherSuite)
        let keyLen = TLSCipherSuite.keyLength(tls12CipherSuite)
        let ivLen = TLSCipherSuite.ivLength(tls12CipherSuite)

        let keys = TLS12KeyDerivation.keysFromMasterSecret(
            masterSecret: ms,
            clientRandom: cRandom,
            serverRandom: sRandom,
            macLen: macLen,
            keyLen: keyLen,
            ivLen: ivLen,
            useSHA384: useSHA384
        )

        // Compute transcript hash for Client Finished
        let transcriptHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
        let clientVerifyData = TLS12KeyDerivation.computeFinishedVerifyData(
            masterSecret: ms, label: "client finished",
            handshakeHash: transcriptHash, useSHA384: useSHA384
        )

        // Build Finished handshake message
        var finishedMessage = Data()
        finishedMessage.append(0x14) // Handshake type: Finished
        finishedMessage.append(0x00)
        finishedMessage.append(0x00)
        finishedMessage.append(UInt8(clientVerifyData.count))
        finishedMessage.append(clientVerifyData)

        // Build the wire data: ClientKeyExchange record + CCS record + Finished record (encrypted)
        let version = negotiatedVersion
        var wireData = Data()

        // ClientKeyExchange TLS record
        wireData.append(0x16) // Handshake
        wireData.append(UInt8(version >> 8))
        wireData.append(UInt8(version & 0xFF))
        wireData.append(UInt8((ckeMessage.count >> 8) & 0xFF))
        wireData.append(UInt8(ckeMessage.count & 0xFF))
        wireData.append(ckeMessage)

        // ChangeCipherSpec record
        wireData.append(contentsOf: [0x14, UInt8(version >> 8), UInt8(version & 0xFF), 0x00, 0x01, 0x01])

        // Encrypt Finished with the derived keys
        do {
            let encryptedFinished = try encryptTLS12Handshake(
                plaintext: finishedMessage,
                contentType: 0x16,
                seqNum: 0,
                version: version,
                clientKey: keys.clientKey,
                clientIV: keys.clientIV,
                clientMACKey: keys.clientMACKey
            )
            wireData.append(encryptedFinished)
        } catch {
            completion(.failure(TLSError.handshakeFailed("Failed to encrypt Finished: \(error.localizedDescription)")))
            return
        }

        // Add Client Finished to transcript (for server Finished verification)
        tls12Transcript?.append(finishedMessage)

        // Send everything
        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.send(data: wireData) { [weak self] error in
            guard let self else { return }

            if let error {
                logger.error("[TLS] Failed to send TLS 1.2 handshake: \(error.localizedDescription, privacy: .public)")
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            // Now receive server's CCS + Finished
            self.receiveTLS12ServerFinished(
                buffer: remainingBuffer ?? Data(),
                keys: keys,
                completion: completion
            )
        }
    }

    /// Encrypts a TLS 1.2 handshake record using the derived keys.
    private func encryptTLS12Handshake(
        plaintext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        version: UInt16,
        clientKey: Data,
        clientIV: Data,
        clientMACKey: Data
    ) throws -> Data {
        let isAEAD = TLSCipherSuite.isAEAD(tls12CipherSuite)
        let isChaCha = TLSCipherSuite.isChaCha20(tls12CipherSuite)

        if isAEAD {
            let key = SymmetricKey(data: clientKey)
            let nonce: Data
            let explicitNonce: Data

            if isChaCha {
                var n = clientIV
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
                var n = clientIV
                n.append(seqBytes)
                nonce = n
                explicitNonce = seqBytes
            }

            // AAD: seq(8) || type(1) || version(2) || plaintext_length(2)
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
                let nonceObj = try ChaChaPoly.Nonce(data: nonce)
                let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
                ct = Data(sealed.ciphertext)
                tag = Data(sealed.tag)
            } else {
                let nonceObj = try AES.GCM.Nonce(data: nonce)
                let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
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
        } else {
            // CBC mode - delegate to TLS12KeyDerivation for MAC
            let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
            let useSHA256: Bool
            switch tls12CipherSuite {
            case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                useSHA256 = true
            default:
                useSHA256 = false
            }

            let mac = TLS12KeyDerivation.tls10MAC(
                macKey: clientMACKey, seqNum: seqNum,
                contentType: contentType, protocolVersion: version,
                payload: plaintext, useSHA384: useSHA384, useSHA256: useSHA256
            )

            var data = plaintext
            data.append(mac)

            let blockSize = 16
            let paddingLen = blockSize - (data.count % blockSize)
            data.append(contentsOf: [UInt8](repeating: UInt8(paddingLen - 1), count: paddingLen))

            var iv = Data(count: blockSize)
            _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, blockSize, $0.baseAddress!) }

            var encrypted = Data(count: data.count)
            var numBytesEncrypted = 0
            let status = encrypted.withUnsafeMutableBytes { outPtr in
                data.withUnsafeBytes { inPtr in
                    clientKey.withUnsafeBytes { keyPtr in
                        iv.withUnsafeBytes { ivPtr in
                            CCCrypt(
                                CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                0,
                                keyPtr.baseAddress!, clientKey.count,
                                ivPtr.baseAddress!,
                                inPtr.baseAddress!, data.count,
                                outPtr.baseAddress!, data.count,
                                &numBytesEncrypted
                            )
                        }
                    }
                }
            }

            guard status == kCCSuccess else {
                throw TLSError.handshakeFailed("AES-CBC encryption failed")
            }

            let recordPayloadLen = blockSize + numBytesEncrypted
            var record = Data(capacity: 5 + recordPayloadLen)
            record.append(contentType)
            record.append(UInt8(version >> 8))
            record.append(UInt8(version & 0xFF))
            record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
            record.append(UInt8(recordPayloadLen & 0xFF))
            record.append(iv)
            record.append(encrypted.prefix(numBytesEncrypted))
            return record
        }
    }

    /// Receives the server's ChangeCipherSpec and Finished messages.
    private func receiveTLS12ServerFinished(
        buffer: Data,
        keys: TLS12Keys,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Check if we have CCS + Finished in the buffer
        if let finishedResult = parseTLS12ServerCCSAndFinished(buffer: buffer, keys: keys) {
            switch finishedResult {
            case .success(let remainingData):
                self.buildTLS12Connection(keys: keys, remainingBuffer: remainingData, completion: completion)
            case .failure(let error):
                completion(.failure(error))
            }
            return
        }

        // Need more data
        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive(maximumLength: 65536) { [weak self] moreData, isComplete, error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let moreData, !moreData.isEmpty else {
                // Connection closed (EOF) before server Finished was received
                completion(.failure(TLSError.handshakeFailed("Connection closed before server Finished")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(moreData)
            self.receiveTLS12ServerFinished(buffer: newBuffer, keys: keys, completion: completion)
        }
    }

    /// Parses server CCS + encrypted Finished from the buffer.
    /// Returns remaining data after Finished on success, nil if more data needed.
    private func parseTLS12ServerCCSAndFinished(
        buffer: Data,
        keys: TLS12Keys
    ) -> Result<Data?, Error>? {
        var offset = 0
        var foundCCS = false
        var serverSeqNum: UInt64 = 0

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { return nil }

            if contentType == 0x14 { // ChangeCipherSpec
                foundCCS = true
            } else if contentType == 0x16 && !foundCCS {
                // Plaintext handshake record BEFORE CCS (e.g. NewSessionTicket).
                // Must be added to the transcript — the server includes it when
                // computing its Finished verify_data.
                // Matches utls handshake_client.go readSessionTicket() which adds
                // NewSessionTicket to finishedHash.
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                tls12Transcript?.append(recordBody)
            } else if contentType == 0x16 && foundCCS {
                // Encrypted Finished record
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))

                do {
                    let decrypted = try decryptTLS12HandshakeRecord(
                        ciphertext: recordBody,
                        contentType: 0x16,
                        seqNum: serverSeqNum,
                        serverKey: keys.serverKey,
                        serverIV: keys.serverIV,
                        serverMACKey: keys.serverMACKey
                    )

                    // Parse Finished: type(1) + length(3) + verify_data(12)
                    guard decrypted.count >= 16, decrypted[0] == 0x14 else {
                        return .failure(TLSError.handshakeFailed("Invalid server Finished"))
                    }

                    let verifyData = decrypted.subdata(in: 4..<16)

                    // Verify server Finished
                    guard let ms = masterSecret, let transcript = tls12Transcript else {
                        return .failure(TLSError.handshakeFailed("Missing state for Finished verification"))
                    }

                    let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
                    let transcriptHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
                    let expectedVerifyData = TLS12KeyDerivation.computeFinishedVerifyData(
                        masterSecret: ms, label: "server finished",
                        handshakeHash: transcriptHash, useSHA384: useSHA384
                    )

                    guard verifyData == expectedVerifyData else {
                        return .failure(TLSError.handshakeFailed("Server Finished verification failed"))
                    }

                    offset += 5 + recordLen
                    let remaining = offset < buffer.count ? Data(buffer[offset...]) : nil
                    return .success(remaining)
                } catch {
                    return .failure(error)
                }
            }

            // Always advance past the current record
            offset += 5 + recordLen
        }

        return nil
    }

    /// Decrypts a TLS 1.2 handshake record from the server.
    private func decryptTLS12HandshakeRecord(
        ciphertext: Data,
        contentType: UInt8,
        seqNum: UInt64,
        serverKey: Data,
        serverIV: Data,
        serverMACKey: Data
    ) throws -> Data {
        let isAEAD = TLSCipherSuite.isAEAD(tls12CipherSuite)
        let isChaCha = TLSCipherSuite.isChaCha20(tls12CipherSuite)
        let version = negotiatedVersion

        if isAEAD {
            let key = SymmetricKey(data: serverKey)
            let explicitNonceLen = isChaCha ? 0 : 8

            guard ciphertext.count >= explicitNonceLen + 16 else {
                throw TLSError.handshakeFailed("Ciphertext too short")
            }

            let explicitNonce = isChaCha ? Data() : Data(ciphertext.prefix(explicitNonceLen))
            let payload = Data(ciphertext.suffix(from: ciphertext.startIndex + explicitNonceLen))

            let nonce: Data
            if isChaCha {
                var n = serverIV
                n.withUnsafeMutableBytes { ptr in
                    let p = ptr.bindMemory(to: UInt8.self)
                    let base = p.count - 8
                    for i in 0..<8 { p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
                }
                nonce = n
            } else {
                var n = serverIV
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

            if isChaCha {
                let nonceObj = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
                return Data(try ChaChaPoly.open(sealedBox, using: key, authenticating: aad))
            } else {
                let nonceObj = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
                return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
            }
        } else {
            // CBC decryption
            let blockSize = 16
            guard ciphertext.count >= blockSize * 2 else {
                throw TLSError.handshakeFailed("CBC ciphertext too short")
            }

            let iv = Data(ciphertext.prefix(blockSize))
            let encrypted = Data(ciphertext.suffix(from: ciphertext.startIndex + blockSize))

            var decrypted = Data(count: encrypted.count)
            var numBytesDecrypted = 0
            let status = decrypted.withUnsafeMutableBytes { outPtr in
                encrypted.withUnsafeBytes { inPtr in
                    serverKey.withUnsafeBytes { keyPtr in
                        iv.withUnsafeBytes { ivPtr in
                            CCCrypt(
                                CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                0,
                                keyPtr.baseAddress!, serverKey.count,
                                ivPtr.baseAddress!,
                                inPtr.baseAddress!, encrypted.count,
                                outPtr.baseAddress!, encrypted.count,
                                &numBytesDecrypted
                            )
                        }
                    }
                }
            }

            guard status == kCCSuccess else {
                throw TLSError.handshakeFailed("CBC decryption failed")
            }

            decrypted = decrypted.prefix(numBytesDecrypted)

            // Strip and validate padding
            let paddingByte = Int(decrypted.last ?? 0)
            let paddingLen = paddingByte + 1
            guard paddingLen <= decrypted.count else {
                throw TLSError.handshakeFailed("Invalid CBC padding")
            }
            decrypted = decrypted.prefix(decrypted.count - paddingLen)

            // Strip and verify MAC
            let macSize = TLSCipherSuite.macLength(tls12CipherSuite)
            guard decrypted.count >= macSize else {
                throw TLSError.handshakeFailed("Decrypted data too short for MAC")
            }

            let payload = Data(decrypted.prefix(decrypted.count - macSize))
            let receivedMAC = Data(decrypted.suffix(macSize))

            let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
            let useSHA256: Bool
            switch tls12CipherSuite {
            case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                 TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                useSHA256 = true
            default:
                useSHA256 = false
            }

            let expectedMAC = TLS12KeyDerivation.tls10MAC(
                macKey: serverMACKey, seqNum: seqNum,
                contentType: contentType, protocolVersion: negotiatedVersion,
                payload: payload, useSHA384: useSHA384, useSHA256: useSHA256
            )

            guard receivedMAC == expectedMAC else {
                throw TLSError.handshakeFailed("MAC verification failed")
            }

            return payload
        }
    }

    /// Creates the final TLSRecordConnection for TLS 1.2.
    private func buildTLS12Connection(
        keys: TLS12Keys,
        remainingBuffer: Data?,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        // Sequence numbers start at 1 because seqNum=0 was consumed by the
        // Finished messages (first encrypted record after ChangeCipherSpec).
        // Matches utls conn.go: incSeq() is called after each encrypt/decrypt.
        let tlsConnection = TLSRecordConnection(
            tls12ClientKey: keys.clientKey,
            clientIV: keys.clientIV,
            serverKey: keys.serverKey,
            serverIV: keys.serverIV,
            clientMACKey: keys.clientMACKey,
            serverMACKey: keys.serverMACKey,
            cipherSuite: tls12CipherSuite,
            protocolVersion: negotiatedVersion,
            initialClientSeqNum: 1,
            initialServerSeqNum: 1
        )
        tlsConnection.connection = self.connection
        self.connection = nil

        if let remaining = remainingBuffer, !remaining.isEmpty {
            tlsConnection.prependToReceiveBuffer(remaining)
        }

        clearHandshakeState()
        completion(.success(tlsConnection))
    }

    // MARK: - Certificate Validation

    /// Validates the server certificate chain using Apple's Security framework.
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

    // MARK: - CertificateVerify (TLS 1.3)

    /// Verifies the CertificateVerify signature against the handshake transcript.
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

        let transcriptHash = kd.transcriptHash(transcript)

        var content = Data(repeating: 0x20, count: 64)
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
        // ECDSA
        case 0x0403: return .ecdsaSignatureMessageX962SHA256
        case 0x0503: return .ecdsaSignatureMessageX962SHA384
        case 0x0603: return .ecdsaSignatureMessageX962SHA512
        // RSA-PSS
        case 0x0804: return .rsaSignatureMessagePSSSHA256
        case 0x0805: return .rsaSignatureMessagePSSSHA384
        case 0x0806: return .rsaSignatureMessagePSSSHA512
        // RSA-PKCS1
        case 0x0401: return .rsaSignatureMessagePKCS1v15SHA256
        case 0x0501: return .rsaSignatureMessagePKCS1v15SHA384
        case 0x0601: return .rsaSignatureMessagePKCS1v15SHA512
        case 0x0201: return .rsaSignatureMessagePKCS1v15SHA1
        // Ed25519
        case 0x0807: return .ecdsaSignatureMessageX962SHA256 // Ed25519 verified via CryptoKit below
        default:     return .rsaSignatureMessagePSSSHA256
        }
    }

    // MARK: - CompressedCertificate (RFC 8879)

    /// Decompresses a CompressedCertificate message body.
    private func decompressCertificate(_ body: Data) -> Data? {
        guard body.count >= 5 else { return nil }

        let algorithm = UInt16(body[0]) << 8 | UInt16(body[1])
        let uncompressedLength = Int(body[2]) << 16 | Int(body[3]) << 8 | Int(body[4])
        let compressed = body.subdata(in: 5..<body.count)

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

    // MARK: - Helpers

    /// Checks whether the certificate's SHA-256 fingerprint is in the user's trusted list.
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
        // TLS 1.2 state
        clientRandom = nil
        serverRandom = nil
        masterSecret = nil
        tls12Transcript = nil
        useExtendedMasterSecret = false
        ecdhP256PrivateKey = nil
        ecdhP384PrivateKey = nil
    }
}
