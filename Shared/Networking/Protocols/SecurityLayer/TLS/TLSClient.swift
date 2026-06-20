//
//  TLSClient.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Security
import Compression

// MARK: - ServerHello Result

private enum ServerHelloResult {
    /// key_share carries an X25519 public key.
    case tls13(keyShare: Data, cipherSuite: UInt16)
    case tls12(cipherSuite: UInt16, serverRandom: Data, version: UInt16, extendedMasterSecret: Bool)
    /// Surfaced as a terminal outcome: we don't send a second ClientHello flight.
    case helloRetryRequest
}

// MARK: - TLSClient

nonisolated class TLSClient {
    let configuration: TLSConfiguration
    var connection: (any RawTransport)?

    // Cleared after handshake.
    var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var storedClientHello: Data?
    private var sentSessionID: Data?

    /// Inner-hello transcript material used to detect ECH acceptance; `nil` means ECH was not attempted.
    var echContext: ECHClientContext?
    /// Set once the ECH accept-confirmation in the ServerHello verifies.
    var echAccepted = false

    /// ECHConfigList discovered from DNS HTTPS record by `prepareECH`, when ECH is enabled without an inline `echConfig`.
    private var resolvedECHConfigList: Data?

    // Cleared after handshake.
    var tls13 = TLS13HandshakeState()

    // TLS 1.2 session state, cleared after handshake.
    var clientRandom: Data?
    var serverRandom: Data?
    var masterSecret: Data?
    var tls12CipherSuite: UInt16 = 0
    var negotiatedVersion: UInt16 = 0
    /// Whether the server echoed the extended_master_secret extension (RFC 7627).
    var useExtendedMasterSecret = false
    var ecdhP256PrivateKey: P256.KeyAgreement.PrivateKey?
    var ecdhP384PrivateKey: P384.KeyAgreement.PrivateKey?
    /// Handshake transcript for TLS 1.2 Finished computation
    var tls12Transcript: Data?

    var serverCertificates: [SecCertificate] = []

    // Buffer for data received after Server Finished (e.g. NewSessionTicket)
    var postHandshakeBuffer: Data?

    /// The value of the ALPN sent by the peer; empty when the server echoed none.
    var negotiatedALPN: String = ""

    static let offeredSignatureAlgorithms: Set<UInt16> = [
        TLSSignatureScheme.rsa_pkcs1_sha1,
        TLSSignatureScheme.ecdsa_sha1,
        TLSSignatureScheme.rsa_pkcs1_sha256,
        TLSSignatureScheme.rsa_pkcs1_sha384,
        TLSSignatureScheme.rsa_pkcs1_sha512,
        TLSSignatureScheme.ecdsa_secp256r1_sha256,
        TLSSignatureScheme.ecdsa_secp384r1_sha384,
        TLSSignatureScheme.ecdsa_secp521r1_sha512,
        TLSSignatureScheme.rsa_pss_rsae_sha256,
        TLSSignatureScheme.rsa_pss_rsae_sha384,
        TLSSignatureScheme.rsa_pss_rsae_sha512,
    ]

    private static let supportedTLS12CipherSuites: Set<UInt16> = [
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLSCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLSCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
    ]

    // MARK: Initialization

    init(configuration: TLSConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Public API

    func connect(
        host: String,
        port: UInt16,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        let completion = releasingConnectionOnFailure(completion)
        prepareECH { [weak self] echError in
            guard let self else {
                completion(.failure(TLSError.connectionFailed("Client deallocated")))
                return
            }
            if let echError {
                completion(.failure(echError))
                return
            }

            self.ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            guard let privateKey = self.ephemeralPrivateKey else {
                completion(.failure(TLSError.handshakeFailed("No ephemeral key")))
                return
            }

            let clientHello: Data
            do {
                clientHello = try self.buildTLSClientHello(privateKey: privateKey)
            } catch {
                completion(.failure(error))
                return
            }
            self.storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

            let transport = RawTCPSocket()
            self.connection = transport

            transport.connect(host: host, port: port, initialData: clientHello) { [weak self] error in
                if let error {
                    completion(.failure(TLSError.connectionFailed(error.localizedDescription)))
                    return
                }

                guard let self else {
                    completion(.failure(TLSError.connectionFailed("Client deallocated")))
                    return
                }

                self.receiveServerResponse(completion: completion)
            }
        }
    }

    func connect(
        overTunnel tunnel: ProxyConnection,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        let completion = releasingConnectionOnFailure(completion)
        prepareECH { [weak self] echError in
            guard let self else {
                completion(.failure(TLSError.connectionFailed("Client deallocated")))
                return
            }
            if let echError {
                completion(.failure(echError))
                return
            }
            self.ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            self.connection = TunneledTransport(tunnel: tunnel)
            self.performTLSHandshake(completion: completion)
        }
    }

    func cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = nil
    }

    private func releasingConnectionOnFailure(
        _ completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) -> (Result<TLSRecordConnection, Error>) -> Void {
        let span = PerformanceMonitor.span(.tlsHandshake)
        return { [weak self] result in
            if case .failure = result {
                self?.connection?.forceCancel()
                self?.connection = nil
                self?.clearHandshakeState()
            } else {
                span.stop()
            }
            completion(result)
        }
    }

    // MARK: - Handshake

    private func performTLSHandshake(
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let privateKey = ephemeralPrivateKey else {
            completion(.failure(TLSError.handshakeFailed("No ephemeral key")))
            return
        }

        do {
            let clientHello = try buildTLSClientHello(privateKey: privateKey)

            storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

            guard let connection else {
                completion(.failure(TLSError.connectionFailed("Connection cancelled")))
                return
            }
            connection.send(data: clientHello) { [weak self] error in
                guard let self else { return }

                if let error {
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                self.receiveServerResponse(completion: completion)
            }
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - ClientHello

    /// Resolves an opportunistic ECHConfigList from DNS before the handshake.
    /// Fail-closed: a discovery miss errors so the caller never falls back to a cleartext-SNI handshake.
    private func prepareECH(completion: @escaping (Error?) -> Void) {
        guard configuration.echIsOpportunistic else {
            completion(nil)
            return
        }
        let serverName = configuration.serverName
        DNSResolver.shared.resolveECHConfigList(for: serverName) { [weak self] config in
            guard let self else {
                completion(TLSError.connectionFailed("Client deallocated"))
                return
            }
            guard let config else {
                completion(TLSError.handshakeFailed(
                    "Opportunistic ECH: no ECH config published in DNS for \(serverName)"))
                return
            }
            self.resolvedECHConfigList = config
            completion(nil)
        }
    }

    private func buildTLSClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw TLSError.handshakeFailed("Failed to generate random bytes")
        }
        clientRandom = random

        var sessionId = Data(count: 32)
        guard sessionId.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw TLSError.handshakeFailed("Failed to generate session ID")
        }
        sentSessionID = sessionId

        // ECH: send a ClientHelloOuter carrying the cover name and the HPKE-sealed inner.
        if configuration.echEnabled,
           let echConfigData = ECHConfigResolver.resolveImmediate(configuration.echConfig) ?? resolvedECHConfigList {
            let configs = try ECHConfigParser.parseConfigList(echConfigData)
            guard let config = ECHConfig.pick(from: configs) else {
                throw TLSError.handshakeFailed("ECHConfigList contains no usable config")
            }
            guard let cipherSuite = config.pickCipherSuite() else {
                throw TLSError.handshakeFailed("ECH config offers no supported cipher suite")
            }

            var innerRandom = Data(count: 32)
            guard innerRandom.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
                throw TLSError.handshakeFailed("Failed to generate inner random")
            }

            let (outerMessage, context) = try TLSClientHelloBuilder.buildECHClientHello(
                outerRandom: random,
                innerRandom: innerRandom,
                sessionId: sessionId,
                innerServerName: configuration.serverName,
                publicKey: privateKey.publicKey.rawRepresentation,
                alpn: configuration.alpn ?? ["h2", "http/1.1"],
                config: config,
                cipherSuite: cipherSuite
            )
            self.echContext = context
            return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: outerMessage)
        } else if configuration.echEnabled, configuration.echConfig != nil {
            // Fail rather than silently send the real SNI in the clear.
            throw TLSError.handshakeFailed("ECH requested but its ECHConfigList is not valid base64")
        } else if configuration.echEnabled {
            // `prepareECH` is fail-closed; guard defensively rather than leak the SNI.
            throw TLSError.handshakeFailed("Opportunistic ECH requested but no ECH config was discovered")
        }

        var rawClientHello = TLSClientHelloBuilder.buildRawClientHello(
            fingerprint: configuration.fingerprint,
            random: random,
            sessionId: sessionId,
            serverName: configuration.serverName,
            publicKey: privateKey.publicKey.rawRepresentation,
            alpn: configuration.alpn ?? ["h2", "http/1.1"],
            omitPQKeyShares: true
        )

        if let maxVersion = configuration.maxVersion, maxVersion.rawValue <= 0x0303 {
            rawClientHello = TLSClientHelloBuilder.clampSupportedVersionsToTLS12(rawClientHello)
        }

        return TLSClientHelloBuilder.wrapInTLSRecord(clientHello: rawClientHello)
    }

    // MARK: - Server Response Processing

    /// Buffers until a complete TLS record header arrives, then dispatches on content type.
    private func receiveServerResponse(
        buffer: Data = Data(),
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if buffer.count >= 5 {
            let contentType = buffer[0]

            if contentType == TLSContentType.handshake {
                self.continueReceivingHandshake(buffer: buffer, completion: completion)
            } else if contentType == TLSContentType.alert {
                let alertLevel = buffer.count > 5 ? buffer[5] : 0
                let alertDesc = buffer.count > 6 ? buffer[6] : 0
                completion(.failure(TLSError.alert(level: alertLevel, description: alertDesc)))
            } else {
                completion(.failure(TLSError.handshakeFailed("Unexpected content type: \(contentType)")))
            }
            return
        }

        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.receive() { [weak self] data, _, error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            guard let data, !data.isEmpty else {
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
            connection.receive() { [weak self] moreData, isComplete, error in
                guard let self else { return }

                if let error {
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                guard let moreData, !moreData.isEmpty else {
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
            completion(.failure(TLSError.handshakeFailed("Failed to parse ServerHello")))
            return
        }

        switch serverHelloResult {
        case .helloRetryRequest:
            // We don't implement the second ClientHello flight HRR requires. Aborting
            // here doesn't leak the inner SNI, since the ClientHello is already sent.
            completion(.failure(TLSError.helloRetryRequest))
            return

        case .tls13(let serverKeyShare, let cipherSuite):
            handleTLS13Handshake(
                buffer: buffer,
                serverKeyShare: serverKeyShare,
                cipherSuite: cipherSuite,
                clientHello: clientHello,
                completion: completion
            )

        case .tls12(let cipherSuite, let serverRandom, let version, let extendedMasterSecret):
            self.serverRandom = serverRandom
            self.tls12CipherSuite = cipherSuite
            self.negotiatedVersion = version
            self.useExtendedMasterSecret = extendedMasterSecret
            handleTLS12Handshake(
                buffer: buffer,
                clientHello: clientHello,
                completion: completion
            )
        }
    }

    // MARK: - ServerHello Parsing

    private func bufferContainsCompleteServerHello(_ buffer: Data) -> Bool {
        var offset = 0
        while offset + 5 <= buffer.count {
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if offset + 5 + recordLen > buffer.count { return false }

            if buffer[offset] == TLSContentType.handshake && offset + 5 < buffer.count && buffer[offset + 5] == TLSHandshakeType.serverHello {
                return true
            }

            offset += 5 + recordLen
        }

        return false
    }

    /// Handles records that coalesce multiple handshake messages.
    func extractServerHelloMessage(from buffer: Data) -> Data {
        var offset = 0
        while offset + 5 < buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            if contentType == TLSContentType.handshake {
                let recordStart = offset + 5
                let recordEnd = min(recordStart + recordLen, buffer.count)
                var hsOffset = recordStart
                while hsOffset + 4 <= recordEnd {
                    let hsType = buffer[hsOffset]
                    let hsLen = Int(buffer[hsOffset + 1]) << 16 | Int(buffer[hsOffset + 2]) << 8 | Int(buffer[hsOffset + 3])
                    guard hsOffset + 4 + hsLen <= recordEnd else { break }
                    if hsType == TLSHandshakeType.serverHello {
                        return buffer.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                    }
                    hsOffset += 4 + hsLen
                }
            }

            offset += 5 + recordLen
        }
        return Data()
    }

    private func parseServerHello(data: Data) -> ServerHelloResult? {
        var offset = 0

        while offset + 5 < data.count {
            let contentType = data[offset]
            guard contentType == TLSContentType.handshake else { break }

            let recordLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            offset += 5

            guard offset + recordLen <= data.count else { break }
            guard data[offset] == TLSHandshakeType.serverHello else {
                offset += recordLen
                continue
            }

            // ServerHello validation: compression must be zero; for TLS 1.3 the
            // legacy version must be TLSv1.2 and the server must echo our legacy
            // session ID (TLS 1.2 and below carry the server's own session ID, not an echo).
            let randomOffset = offset + 1 + 3 + 2
            guard randomOffset + 32 <= data.count else { return nil }

            let legacyVersion = UInt16(data[offset + 4]) << 8 | UInt16(data[offset + 5])
            let srvRandom = data.subdata(in: randomOffset..<(randomOffset + 32))

            if srvRandom == TLSRandom.helloRetryRequest {
                return .helloRetryRequest
            }

            var shOffset = randomOffset + 32
            guard shOffset < data.count else { return nil }

            let sessionIdLen = Int(data[shOffset])
            guard sessionIdLen <= 32, shOffset + 1 + sessionIdLen <= data.count else { return nil }
            let sessionIDEcho = data.subdata(in: (shOffset + 1)..<(shOffset + 1 + sessionIdLen))
            shOffset += 1 + sessionIdLen

            guard shOffset + 3 <= data.count else { return nil }
            let cipherSuite = UInt16(data[shOffset]) << 8 | UInt16(data[shOffset + 1])
            guard data[shOffset + 2] == 0 else { return nil }
            shOffset += 3

            guard shOffset + 2 <= data.count else { return nil }

            let extLen = Int(data[shOffset]) << 8 | Int(data[shOffset + 1])
            shOffset += 2

            let extEnd = shOffset + extLen
            guard extEnd <= data.count else { return nil }

            var foundVersion: UInt16 = 0
            var keyShareData: Data?
            var hasEMS = false
            var observedExtensionTypes = Set<UInt16>()

            var extOffset = shOffset
            while extOffset + 4 <= extEnd {
                let extType = UInt16(data[extOffset]) << 8 | UInt16(data[extOffset + 1])
                let extDataLen = Int(data[extOffset + 2]) << 8 | Int(data[extOffset + 3])
                extOffset += 4

                guard extOffset + extDataLen <= extEnd else { return nil }

                let (inserted, _) = observedExtensionTypes.insert(extType)
                if !inserted {
                    return nil
                }

                switch extType {
                case TLSExtensionType.supportedVersions:
                    if extDataLen == 2 {
                        foundVersion = UInt16(data[extOffset]) << 8 | UInt16(data[extOffset + 1])
                    }

                case TLSExtensionType.keyShare:
                    if extDataLen >= 4 {
                        let group = UInt16(data[extOffset]) << 8 | UInt16(data[extOffset + 1])
                        let keyLen = Int(data[extOffset + 2]) << 8 | Int(data[extOffset + 3])
                        if group == TLSNamedGroup.x25519 && keyLen == 32, 4 + 32 <= extDataLen {
                            keyShareData = data.subdata(in: (extOffset + 4)..<(extOffset + 4 + 32))
                        }
                    }

                case TLSExtensionType.extendedMasterSecret:
                    hasEMS = true

                case TLSExtensionType.applicationLayerProtocolNegotiation:
                    if extDataLen >= 3 {
                        let listLen = Int(data[extOffset]) << 8 | Int(data[extOffset + 1])
                        if 2 + listLen <= extDataLen {
                            let nameLen = Int(data[extOffset + 2])
                            if 3 + nameLen <= extDataLen {
                                let nameStart = extOffset + 3
                                let name = data.subdata(in: nameStart..<(nameStart + nameLen))
                                if let alpnProtocol = String(data: name, encoding: .utf8) {
                                    guard (configuration.alpn ?? ["h2", "http/1.1"]).contains(alpnProtocol) else {
                                        return nil
                                    }
                                    self.negotiatedALPN = alpnProtocol
                                }
                            }
                        }
                    }

                default:
                    break
                }

                extOffset += extDataLen
            }

            // supported_versions is required to indicate TLS 1.3.
            if foundVersion == 0x0304 {
                guard legacyVersion == 0x0303 else { return nil }
                if let sent = sentSessionID, sessionIDEcho != sent {
                    return nil
                }
                switch cipherSuite {
                case TLSCipherSuite.TLS_AES_128_GCM_SHA256,
                     TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                     TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                    break
                default:
                    return nil
                }
                if let keyShare = keyShareData {
                    return .tls13(keyShare: keyShare, cipherSuite: cipherSuite)
                }
                return nil
            }

            let version = foundVersion != 0 ? foundVersion : legacyVersion
            guard Self.supportedTLS12CipherSuites.contains(cipherSuite) else { return nil }
            return .tls12(cipherSuite: cipherSuite, serverRandom: srvRandom, version: version, extendedMasterSecret: hasEMS)
        }

        return nil
    }

    // MARK: - Certificate Validation

    func validateCertificate(completion: @escaping (Result<Void, Error>) -> Void) {
        switch CertificatePolicy.verify(chain: serverCertificates, serverName: configuration.serverName) {
        case .trusted:
            completion(.success(()))
        case .rejected(let reason):
            completion(.failure(TLSError.certificateValidationFailed(reason)))
        }
    }


    func secKeyAlgorithm(for tlsAlgorithm: UInt16) -> SecKeyAlgorithm {
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


    // MARK: - Helpers

    func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
    }

    func clearHandshakeState() {
        ephemeralPrivateKey = nil
        storedClientHello = nil
        sentSessionID = nil
        echContext = nil
        echAccepted = false
        tls13 = TLS13HandshakeState()
        postHandshakeBuffer = nil
        serverCertificates.removeAll()
        clientRandom = nil
        serverRandom = nil
        masterSecret = nil
        tls12Transcript = nil
        useExtendedMasterSecret = false
        ecdhP256PrivateKey = nil
        ecdhP384PrivateKey = nil
    }
}
