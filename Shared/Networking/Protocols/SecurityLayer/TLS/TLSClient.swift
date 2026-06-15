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

private let logger = AnywhereLogger(category: "TLSClient")

// MARK: - ServerHello Result

private enum ServerHelloResult {
    /// TLS 1.3: server provided a key_share extension with an X25519 public key.
    case tls13(keyShare: Data, cipherSuite: UInt16)
    case tls12(cipherSuite: UInt16, serverRandom: Data, version: UInt16, extendedMasterSecret: Bool)
    /// The server sent a HelloRetryRequest. We don't perform a second ClientHello
    /// flight, so this is surfaced as a distinct, terminal outcome rather than a
    /// generic parse failure.
    case helloRetryRequest
}

// MARK: - TLSClient

nonisolated class TLSClient {
    private let configuration: TLSConfiguration
    private var connection: (any RawTransport)?

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var storedClientHello: Data?
    private var sentSessionID: Data?

    /// Encrypted Client Hello state, set when ECH is attempted — an inline
    /// `echConfig` or an opportunistic config discovered from DNS. Holds the
    /// inner-hello transcript material used to detect whether the server accepted
    /// ECH. `nil` means ECH was not attempted.
    private var echContext: ECHClientContext?
    /// Set once the ECH accept-confirmation in the ServerHello verifies.
    private(set) var echAccepted = false

    /// ECHConfigList discovered from the server domain's DNS HTTPS record,
    /// populated by `prepareECH` before the handshake when ECH is enabled without
    /// an inline `echConfig`. `nil` otherwise.
    private var resolvedECHConfigList: Data?

    /// TLS 1.3 session state (cleared after handshake).
    private var tls13 = TLS13HandshakeState()

    // TLS 1.2 session state (cleared after handshake)
    private var clientRandom: Data?
    private var serverRandom: Data?
    private var masterSecret: Data?
    private var tls12CipherSuite: UInt16 = 0
    private var negotiatedVersion: UInt16 = 0
    /// Whether the server echoed the extended_master_secret extension (RFC 7627).
    private var useExtendedMasterSecret = false
    private var ecdhP256PrivateKey: P256.KeyAgreement.PrivateKey?
    private var ecdhP384PrivateKey: P384.KeyAgreement.PrivateKey?
    /// Handshake transcript for TLS 1.2 Finished computation
    private var tls12Transcript: Data?

    private var serverCertificates: [SecCertificate] = []

    // Buffer for data received after Server Finished (e.g. NewSessionTicket)
    private var postHandshakeBuffer: Data?

    /// The value of the ALPN sent by the peer; empty when the server echoed none.
    private var negotiatedALPN: String = ""

    /// The signature algorithms offered in the ClientHello fingerprints.
    private static let offeredSignatureAlgorithms: Set<UInt16> = [
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

    /// The TLS 1.2 cipher suites this client implements.
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

    /// Connects to a server and performs the TLS handshake.
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

    /// Connects over an existing proxy tunnel (proxy chaining) and performs the TLS handshake.
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
    /// Returns immediately with no error unless ECH is enabled without an inline
    /// `echConfig` (`echIsOpportunistic`). Fail-closed: a discovery miss is
    /// surfaced as an error so the caller never falls back to a cleartext-SNI
    /// handshake.
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

        // Encrypted Client Hello: when enabled, send a ClientHelloOuter carrying
        // the cover name and the HPKE-sealed inner — the ECHConfigList is inline
        // (base64) or discovered opportunistically from DNS by `prepareECH`.
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
            // ECH was requested but its ECHConfigList isn't valid base64. Fail
            // rather than silently sending the real SNI in the clear.
            throw TLSError.handshakeFailed("ECH requested but its ECHConfigList is not valid base64")
        } else if configuration.echEnabled {
            // `prepareECH` is fail-closed, so opportunistic discovery should have
            // a resolved config by now; guard defensively rather than leak the SNI.
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
            // HelloRetryRequest requires re-sending a ClientHello (new key_share,
            // cookie, and for ECH a re-sealed inner). We don't implement that
            // second flight; fail with a specific error. The handshake aborts
            // without leaking the inner SNI, since the ClientHello is already sent.
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

    /// Whether the buffer holds a complete Handshake record whose payload starts with a ServerHello.
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

    /// Extracts the ServerHello message bytes, handling records that coalesce multiple handshake messages.
    private func extractServerHelloMessage(from buffer: Data) -> Data {
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

    /// Parses the ServerHello to detect the negotiated TLS version and key parameters; nil on failure.
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

            // Let's validate this ServerHello. The rules:
            //
            // - helloRetryRequest is forbidden
            // - the chosen compression option must be zero
            // - for TLS 1.3, the legacy version number must be TLSv1.2
            // - for TLS 1.3, the server must have echoed our legacy session ID
            //   (in TLS 1.2 and below, a full handshake carries the server's own
            //   session ID instead of an echo)
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
                                if let s = String(data: name, encoding: .utf8) {
                                    guard (configuration.alpn ?? ["h2", "http/1.1"]).contains(s) else {
                                        return nil
                                    }
                                    self.negotiatedALPN = s
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

    // MARK: - TLS 1.3 Handshake

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

            tls13.keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)

            // With ECH, the accepted handshake transcript is seeded by the inner
            // ClientHello. Detect acceptance via the confirmation embedded in the
            // ServerHello random; on rejection fall back to the outer hello so
            // the (doomed) handshake still decrypts far enough to read retry configs.
            var effectiveClientHello = clientHello
            if let ech = echContext {
                if echAcceptConfirmed(serverHello: serverHello, ech: ech, kd: tls13.keyDerivation!) {
                    echAccepted = true
                    effectiveClientHello = ech.innerTranscriptMessage
                } else {
                    ech.rejected = true
                }
            }

            var transcript = Data()
            transcript.append(effectiveClientHello)
            transcript.append(serverHello)

            let (hs, keys) = tls13.keyDerivation!.deriveHandshakeKeys(sharedSecret: sharedSecretData, transcript: transcript)
            tls13.handshakeSecret = hs
            tls13.handshakeKeys = keys
            tls13.handshakeTranscript = transcript
            negotiatedVersion = 0x0304

            consumeRemainingTLS13Handshake(buffer: buffer, completion: completion)
        } catch {
            completion(.failure(TLSError.handshakeFailed("Key derivation failed")))
        }
    }

    // MARK: - ECH Accept Confirmation

    /// Returns true if the ServerHello signals that ECH was accepted.
    ///
    /// The server places an 8-byte confirmation in the last 8 bytes of the
    /// ServerHello random, derived (with the negotiated cipher suite's hash) as:
    ///
    ///     PRK  = HKDF-Extract(salt: 0, IKM: ClientHelloInner.random)
    ///     conf = Hash(innerTranscript || ServerHello with random[24..32] zeroed)
    ///     tag  = HKDF-Expand-Label(PRK, "ech accept confirmation", conf, 8)
    private func echAcceptConfirmed(serverHello: Data, ech: ECHClientContext, kd: TLS13KeyDerivation) -> Bool {
        let sh = [UInt8](serverHello)
        guard sh.count >= 38 else { return false }

        var confInput = ech.innerTranscriptMessage
        confInput.append(contentsOf: sh[0..<30])
        confInput.append(Data(repeating: 0, count: 8))
        confInput.append(contentsOf: sh[38...])
        let confHash = kd.transcriptHash(confInput)

        let prk = kd.extract(inputKeyMaterial: ech.innerRandom, salt: Data()).key
        let expected = kd.expandLabel(secret: prk, label: "ech accept confirmation", context: confHash, length: 8)

        return constantTimeEqual(expected, Data(sh[30..<38]))
    }

    /// Extract the `retry_configs` ECHConfigList from the server's
    /// encrypted_client_hello extension in EncryptedExtensions, if present.
    private func parseECHRetryConfigList(fromEncryptedExtensions body: Data) -> Data? {
        let b = [UInt8](body)
        guard b.count >= 2 else { return nil }
        let extsTotal = Int(b[0]) << 8 | Int(b[1])
        let end = min(2 + extsTotal, b.count)
        var offset = 2
        while offset + 4 <= end {
            let extType = UInt16(b[offset]) << 8 | UInt16(b[offset + 1])
            let extLen = Int(b[offset + 2]) << 8 | Int(b[offset + 3])
            offset += 4
            guard offset + extLen <= end else { return nil }
            if extType == 0xFE0D {
                return Data(b[offset..<(offset + extLen)])
            }
            offset += extLen
        }
        return nil
    }

    // MARK: - TLS 1.3 Encrypted Handshake Processing

    /// Decrypts and processes encrypted TLS 1.3 handshake records until Server Finished is found.
    private func consumeRemainingTLS13Handshake(
        buffer: Data,
        startOffset: Int = 0,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let keys = tls13.handshakeKeys, let kd = tls13.keyDerivation else {
            completion(.failure(TLSError.handshakeFailed("Missing handshake keys")))
            return
        }

        var offset = startOffset
        var fullTranscript = tls13.handshakeTranscript ?? Data()
        var foundServerFinished = false

        var transcriptBeforeCertVerify: Data? = nil
        var certificateVerifySignature: Data? = nil
        var certificateVerifyAlgorithm: UInt16 = 0

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == TLSContentType.changeCipherSpec || contentType == TLSContentType.handshake {
                offset += 5 + recordLen
                continue
            } else if contentType == TLSContentType.applicationData {
                let recordHeader = buffer.subdata(in: offset..<(offset + 5))
                let ciphertext = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))

                do {
                    let seqNum = tls13.serverHandshakeSeqNum
                    let decrypted = try TLSRecordCrypto.decryptRecord(
                        ciphertext: ciphertext,
                        key: SymmetricKey(data: keys.serverKey),
                        iv: keys.serverIV,
                        seqNum: seqNum,
                        recordHeader: recordHeader,
                        cipherSuite: kd.cipherSuite
                    )
                    tls13.serverHandshakeSeqNum += 1

                    var hsOffset = 0
                    while hsOffset + 4 <= decrypted.count {
                        let hsType = decrypted[hsOffset]
                        let hsLen = Int(decrypted[hsOffset + 1]) << 16 | Int(decrypted[hsOffset + 2]) << 8 | Int(decrypted[hsOffset + 3])

                        guard hsOffset + 4 + hsLen <= decrypted.count else { break }

                        let hsMessage = decrypted.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                        let hsBody = decrypted.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))

                        switch hsType {
                        case TLSHandshakeType.encryptedExtensions:
                            fullTranscript.append(hsMessage)
                            if let ech = echContext, ech.rejected {
                                // ECH was rejected; the server may offer fresh
                                // configs here. Skip ALPN validation — it reflects
                                // the cover (outer) hello, and we will fail anyway.
                                ech.retryConfigList = parseECHRetryConfigList(fromEncryptedExtensions: hsBody)
                            } else if let alpn = parseALPNFromEncryptedExtensions(hsBody) {
                                guard (configuration.alpn ?? ["h2", "http/1.1"]).contains(alpn) else {
                                    completion(.failure(TLSError.handshakeFailed("Server selected an ALPN we didn't offer")))
                                    return
                                }
                                self.negotiatedALPN = alpn
                            }

                        case TLSHandshakeType.certificate:
                            fullTranscript.append(hsMessage)
                            parseTLS13CertificateMessage(hsBody)

                        case TLSHandshakeType.certificateVerify:
                            transcriptBeforeCertVerify = fullTranscript
                            fullTranscript.append(hsMessage)
                            if hsBody.count >= 4 {
                                certificateVerifyAlgorithm = UInt16(hsBody[0]) << 8 | UInt16(hsBody[1])
                                let sigLen = Int(hsBody[2]) << 8 | Int(hsBody[3])
                                if hsBody.count >= 4 + sigLen {
                                    certificateVerifySignature = hsBody.subdata(in: 4..<(4 + sigLen))
                                }
                            }

                        case TLSHandshakeType.finished:
                            if let keys = self.tls13.handshakeKeys {
                                let expectedVerifyData = kd.finishedPayload(
                                    trafficSecret: keys.serverTrafficSecret,
                                    transcript: fullTranscript
                                )
                                guard hsBody.count == expectedVerifyData.count,
                                      constantTimeEqual(hsBody, expectedVerifyData) else {
                                    completion(.failure(TLSError.handshakeFailed("Server Finished verification failed")))
                                    return
                                }
                            }
                            fullTranscript.append(hsMessage)
                            foundServerFinished = true

                        case TLSHandshakeType.compressedCertificate:
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
                    completion(.failure(TLSError.handshakeFailed("Record decryption failed")))
                    return
                }
            }

            offset += 5 + recordLen

            if foundServerFinished { break }
        }

        let processedOffset = offset
        tls13.handshakeTranscript = fullTranscript

        let remainingBuffer = offset < buffer.count ? Data(buffer[offset...]) : nil
        self.postHandshakeBuffer = remainingBuffer

        if foundServerFinished {
            // ECH rejected: the handshake terminated against the cover name, not
            // the intended server. Surface the rejection (with any retry configs)
            // rather than validating the wrong certificate.
            if let ech = echContext, ech.rejected {
                completion(.failure(TLSError.echRejected(retryConfigList: ech.retryConfigList)))
                return
            }

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
            connection.receive() { [weak self] moreData, isComplete, error in
                guard let self else { return }

                if let error {
                    logger.warning("[TLS] Error receiving more handshake data: \(error.localizedDescription)")
                    completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                    return
                }

                guard let moreData, !moreData.isEmpty else {
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

    // MARK: - TLS 1.3 EncryptedExtensions ALPN

    private func parseALPNFromEncryptedExtensions(_ body: Data) -> String? {
        guard body.count >= 2 else { return nil }
        let extsTotal = Int(body[body.startIndex]) << 8 | Int(body[body.startIndex + 1])
        let extsStart = body.startIndex + 2
        let extsEnd = extsStart + extsTotal
        guard extsEnd <= body.endIndex else { return nil }

        var offset = extsStart
        while offset + 4 <= extsEnd {
            let extType = UInt16(body[offset]) << 8 | UInt16(body[offset + 1])
            let extLen = Int(body[offset + 2]) << 8 | Int(body[offset + 3])
            offset += 4
            guard offset + extLen <= extsEnd else { return nil }

            if extType == TLSExtensionType.applicationLayerProtocolNegotiation {
                guard extLen >= 3 else { return nil }
                let listLen = Int(body[offset]) << 8 | Int(body[offset + 1])
                guard 2 + listLen <= extLen else { return nil }
                let nameLen = Int(body[offset + 2])
                guard 3 + nameLen <= extLen else { return nil }
                let nameStart = offset + 3
                let name = body.subdata(in: nameStart..<(nameStart + nameLen))
                return String(data: name, encoding: .utf8)
            }
            offset += extLen
        }
        return nil
    }

    // MARK: - TLS 1.3 Finish Handshake

    private func finishTLS13Handshake(
        fullTranscript: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        guard let kd = tls13.keyDerivation, let hs = tls13.handshakeSecret else {
            completion(.failure(TLSError.handshakeFailed("Missing handshake state")))
            return
        }

        tls13.applicationKeys = kd.deriveApplicationKeys(handshakeSecret: hs, fullTranscript: fullTranscript)

        sendTLS13ClientFinished { [weak self] error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed("Failed to send Client Finished")))
                return
            }

            guard let appKeys = self.tls13.applicationKeys else {
                completion(.failure(TLSError.handshakeFailed("Application keys not available")))
                return
            }

            let tlsConnection = TLSRecordConnection(
                clientKey: appKeys.clientKey,
                clientIV: appKeys.clientIV,
                serverKey: appKeys.serverKey,
                serverIV: appKeys.serverIV,
                cipherSuite: self.tls13.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
            )
            tlsConnection.connection = self.connection
            tlsConnection.negotiatedALPN = self.negotiatedALPN
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
        guard let keys = tls13.handshakeKeys,
              let transcript = tls13.handshakeTranscript,
              let kd = tls13.keyDerivation else {
            completion(TLSError.handshakeFailed("Missing handshake keys"))
            return
        }

        var ccsRecord = Data([TLSContentType.changeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01])

        let verifyData = kd.clientFinishedPayload(clientTrafficSecret: keys.clientTrafficSecret, transcript: transcript)

        var finishedMsg = Data()
        finishedMsg.append(TLSHandshakeType.finished)
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
                cipherSuite: tls13.keyDerivation?.cipherSuite ?? TLSCipherSuite.TLS_AES_128_GCM_SHA256
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

    private func handleTLS12Handshake(
        buffer: Data,
        clientHello: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        let serverHello = extractServerHelloMessage(from: buffer)
        var transcript = Data()
        transcript.append(clientHello)
        transcript.append(serverHello)
        self.tls12Transcript = transcript

        receiveTLS12HandshakeMessages(buffer: buffer, completion: completion)
    }

    /// Receives TLS 1.2 handshake messages until ServerHelloDone (0x0E) is found.
    private func receiveTLS12HandshakeMessages(
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        if let result = parseTLS12HandshakeMessages(buffer: buffer) {
            processTLS12HandshakeResult(result, buffer: buffer, completion: completion)
            return
        }

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
                completion(.failure(TLSError.handshakeFailed("Connection closed before TLS 1.2 handshake completed")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(moreData)
            self.receiveTLS12HandshakeMessages(buffer: newBuffer, completion: completion)
        }
    }

    private struct TLS12HandshakeMessages {
        var certificates: [SecCertificate] = []
        var certificateDERs: [Data] = []
        var serverKeyExchange: Data?
        var serverHelloDoneOffset: Int = 0
        /// All handshake message bytes (for transcript)
        var handshakeBytes: Data = Data()
    }

    /// Parses TLS 1.2 handshake messages from the buffer; returns nil if ServerHelloDone not yet seen.
    private func parseTLS12HandshakeMessages(buffer: Data) -> TLS12HandshakeMessages? {
        var result = TLS12HandshakeMessages()
        var offset = 0
        var foundServerHelloDone = false
        var pastServerHello = false

        while offset + 5 <= buffer.count {
            let contentType = buffer[offset]
            let recordLen = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])

            guard offset + 5 + recordLen <= buffer.count else { break }

            if contentType == TLSContentType.handshake {
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                var hsOffset = 0

                while hsOffset + 4 <= recordBody.count {
                    let hsType = recordBody[hsOffset]
                    let hsLen = Int(recordBody[hsOffset + 1]) << 16 | Int(recordBody[hsOffset + 2]) << 8 | Int(recordBody[hsOffset + 3])

                    guard hsOffset + 4 + hsLen <= recordBody.count else { break }

                    let hsMessage = recordBody.subdata(in: hsOffset..<(hsOffset + 4 + hsLen))
                    let hsBody = recordBody.subdata(in: (hsOffset + 4)..<(hsOffset + 4 + hsLen))

                    switch hsType {
                    case TLSHandshakeType.serverHello:
                        pastServerHello = true

                    case TLSHandshakeType.certificate:
                        if pastServerHello {
                            result.handshakeBytes.append(hsMessage)
                            parseTLS12CertificateMessage(hsBody, into: &result)
                        }

                    case TLSHandshakeType.serverKeyExchange:
                        result.handshakeBytes.append(hsMessage)
                        result.serverKeyExchange = hsBody

                    case TLSHandshakeType.serverHelloDone:
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

    private func processTLS12HandshakeResult(
        _ messages: TLS12HandshakeMessages,
        buffer: Data,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
        serverCertificates = messages.certificates

        tls12Transcript?.append(messages.handshakeBytes)

        validateCertificate { [weak self] result in
            guard let self else { return }

            switch result {
            case .failure(let error):
                completion(.failure(error))
                return
            case .success:
                break
            }

            do {
                let preMasterSecret: Data
                let clientKeyExchangeBody: Data

                if TLSCipherSuite.isECDHE(self.tls12CipherSuite) {
                    guard let ske = messages.serverKeyExchange else {
                        completion(.failure(TLSError.handshakeFailed("ECDHE cipher suite but no ServerKeyExchange")))
                        return
                    }
                    try self.verifyServerKeyExchange(ske, certificates: messages.certificates)
                    (preMasterSecret, clientKeyExchangeBody) = try self.processECDHEServerKeyExchange(ske)
                } else {
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
        case TLSNamedGroup.x25519:
            let serverPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPubKeyData)
            guard let privateKey = ephemeralPrivateKey else {
                throw TLSError.handshakeFailed("No ephemeral key")
            }
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            var cke = Data()
            let pubKey = privateKey.publicKey.rawRepresentation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        case TLSNamedGroup.secp256:
            let serverPubKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPubKeyData)
            let clientKey = P256.KeyAgreement.PrivateKey()
            self.ecdhP256PrivateKey = clientKey
            let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPubKey)
            let preMasterSecret = sharedSecret.withUnsafeBytes { Data($0) }
            var cke = Data()
            let pubKey = clientKey.publicKey.x963Representation
            cke.append(UInt8(pubKey.count))
            cke.append(pubKey)
            return (preMasterSecret, cke)

        case TLSNamedGroup.secp384:
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

    private func verifyServerKeyExchange(_ body: Data, certificates: [SecCertificate]) throws {
        guard let serverCert = certificates.first else {
            throw TLSError.certificateValidationFailed("No server certificate for ServerKeyExchange verification")
        }

        guard body.count >= 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange too short for signature")
        }

        let pubKeyLen = Int(body[3])
        let paramsEnd = 4 + pubKeyLen
        guard body.count >= paramsEnd + 4 else {
            throw TLSError.handshakeFailed("ServerKeyExchange missing signature")
        }

        let sigAlgorithm = UInt16(body[paramsEnd]) << 8 | UInt16(body[paramsEnd + 1])
        let sigLen = Int(body[paramsEnd + 2]) << 8 | Int(body[paramsEnd + 3])
        guard body.count >= paramsEnd + 4 + sigLen else {
            throw TLSError.handshakeFailed("ServerKeyExchange signature truncated")
        }

        let signature = body.subdata(in: (paramsEnd + 4)..<(paramsEnd + 4 + sigLen))

        guard let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.certificateValidationFailed("Failed to extract public key")
        }

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
            if CertificatePolicy.allowInsecure {
                return
            }
            let message = error?.takeRetainedValue().localizedDescription ?? "Signature verification failed"
            throw TLSError.certificateValidationFailed("ServerKeyExchange signature failed: \(message)")
        }
    }

    // MARK: - TLS 1.2 RSA Key Exchange

    private func processRSAKeyExchange(certificates: [SecCertificate]) throws -> (preMasterSecret: Data, clientKeyExchange: Data) {
        guard let serverCert = certificates.first,
              let serverPublicKey = SecCertificateCopyKey(serverCert) else {
            throw TLSError.handshakeFailed("No server certificate for RSA key exchange")
        }

        var preMasterSecret = Data(count: 48)
        preMasterSecret[0] = 0x03
        preMasterSecret[1] = 0x03
        guard preMasterSecret.withUnsafeMutableBytes({ ptr in
            SecRandomCopyBytes(kSecRandomDefault, 46, ptr.baseAddress! + 2)
        }) == errSecSuccess else {
            throw TLSError.handshakeFailed("Failed to generate pre-master secret")
        }

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

        var cke = Data()
        cke.append(UInt8((encrypted.count >> 8) & 0xFF))
        cke.append(UInt8(encrypted.count & 0xFF))
        cke.append(encrypted)

        return (preMasterSecret, cke)
    }

    // MARK: - TLS 1.2 Key Derivation & Finish

    /// Completes the TLS 1.2 handshake: derives keys, sends CKE + CCS + Finished, receives server CCS + Finished.
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

        var ckeMessage = Data()
        ckeMessage.append(TLSHandshakeType.clientKeyExchange)
        let ckeLen = clientKeyExchangeBody.count
        ckeMessage.append(UInt8((ckeLen >> 16) & 0xFF))
        ckeMessage.append(UInt8((ckeLen >> 8) & 0xFF))
        ckeMessage.append(UInt8(ckeLen & 0xFF))
        ckeMessage.append(clientKeyExchangeBody)

        tls12Transcript?.append(ckeMessage)

        guard let transcript = tls12Transcript else {
            completion(.failure(TLSError.handshakeFailed("Missing transcript")))
            return
        }

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

        let transcriptHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
        let clientVerifyData = TLS12KeyDerivation.finishedPayload(
            masterSecret: ms, label: "client finished",
            handshakeHash: transcriptHash, useSHA384: useSHA384
        )

        var finishedMessage = Data()
        finishedMessage.append(TLSHandshakeType.finished)
        finishedMessage.append(0x00)
        finishedMessage.append(0x00)
        finishedMessage.append(UInt8(clientVerifyData.count))
        finishedMessage.append(clientVerifyData)

        let version = negotiatedVersion
        var wireData = Data()

        wireData.append(TLSContentType.handshake)
        wireData.append(UInt8(version >> 8))
        wireData.append(UInt8(version & 0xFF))
        wireData.append(UInt8((ckeMessage.count >> 8) & 0xFF))
        wireData.append(UInt8(ckeMessage.count & 0xFF))
        wireData.append(ckeMessage)

        wireData.append(contentsOf: [TLSContentType.changeCipherSpec, UInt8(version >> 8), UInt8(version & 0xFF), 0x00, 0x01, 0x01])

        do {
            let encryptedFinished = try encryptTLS12Handshake(
                plaintext: finishedMessage,
                contentType: TLSContentType.handshake,
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

        tls12Transcript?.append(finishedMessage)

        guard let connection else {
            completion(.failure(TLSError.connectionFailed("Connection cancelled")))
            return
        }
        connection.send(data: wireData) { [weak self] error in
            guard let self else { return }

            if let error {
                completion(.failure(TLSError.handshakeFailed(error.localizedDescription)))
                return
            }

            self.receiveTLS12ServerFinished(
                buffer: remainingBuffer ?? Data(),
                keys: keys,
                completion: completion
            )
        }
    }

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
            guard iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, blockSize, $0.baseAddress!) }) == errSecSuccess else {
                throw TLSError.handshakeFailed("Failed to generate IV")
            }

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
        if let finishedResult = parseTLS12ServerCCSAndFinished(buffer: buffer, keys: keys) {
            switch finishedResult {
            case .success(let remainingData):
                self.buildTLS12Connection(keys: keys, remainingBuffer: remainingData, completion: completion)
            case .failure(let error):
                completion(.failure(error))
            }
            return
        }

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
                completion(.failure(TLSError.handshakeFailed("Connection closed before server Finished")))
                return
            }

            var newBuffer = buffer
            newBuffer.append(moreData)
            self.receiveTLS12ServerFinished(buffer: newBuffer, keys: keys, completion: completion)
        }
    }

    /// Parses server CCS + encrypted Finished; returns remaining bytes on success or nil if incomplete.
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

            if contentType == TLSContentType.changeCipherSpec {
                foundCCS = true
            } else if contentType == TLSContentType.handshake && !foundCCS {
                // Plaintext handshake before CCS (e.g. NewSessionTicket) must enter the transcript — the server's Finished hash includes it.
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))
                tls12Transcript?.append(recordBody)
            } else if contentType == TLSContentType.handshake && foundCCS {
                let recordBody = buffer.subdata(in: (offset + 5)..<(offset + 5 + recordLen))

                do {
                    let seqNum = serverSeqNum
                    serverSeqNum += 1
                    let decrypted = try decryptTLS12HandshakeRecord(
                        ciphertext: recordBody,
                        contentType: TLSContentType.handshake,
                        seqNum: seqNum,
                        serverKey: keys.serverKey,
                        serverIV: keys.serverIV,
                        serverMACKey: keys.serverMACKey
                    )

                    guard decrypted.count >= 16, decrypted[0] == TLSHandshakeType.finished else {
                        return .failure(TLSError.handshakeFailed("Invalid server Finished"))
                    }

                    let verifyData = decrypted.subdata(in: 4..<16)

                    guard let ms = masterSecret, let transcript = tls12Transcript else {
                        return .failure(TLSError.handshakeFailed("Missing state for Finished verification"))
                    }

                    let useSHA384 = TLSCipherSuite.usesSHA384(tls12CipherSuite)
                    let transcriptHash = TLS12KeyDerivation.transcriptHash(transcript, useSHA384: useSHA384)
                    let expectedVerifyData = TLS12KeyDerivation.finishedPayload(
                        masterSecret: ms, label: "server finished",
                        handshakeHash: transcriptHash, useSHA384: useSHA384
                    )

                    guard verifyData.count == expectedVerifyData.count,
                          constantTimeEqual(verifyData, expectedVerifyData) else {
                        return .failure(TLSError.handshakeFailed("Server Finished verification failed"))
                    }

                    offset += 5 + recordLen
                    let remaining = offset < buffer.count ? Data(buffer[offset...]) : nil
                    return .success(remaining)
                } catch {
                    return .failure(error)
                }
            }

            offset += 5 + recordLen
        }

        return nil
    }

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

            let paddingByte = Int(decrypted.last ?? 0)
            let paddingLen = paddingByte + 1

            var paddingGood: UInt8 = 0
            if paddingLen > decrypted.count {
                paddingGood = 1
            } else {
                for i in (decrypted.count - paddingLen)..<decrypted.count {
                    paddingGood |= decrypted[i] ^ UInt8(paddingByte)
                }
            }

            guard paddingGood == 0 else {
                throw TLSError.handshakeFailed("Invalid CBC padding")
            }
            decrypted = decrypted.prefix(decrypted.count - paddingLen)

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

            guard receivedMAC.count == expectedMAC.count,
                  constantTimeEqual(receivedMAC, expectedMAC) else {
                throw TLSError.handshakeFailed("MAC verification failed")
            }

            return payload
        }
    }

    private func buildTLS12Connection(
        keys: TLS12Keys,
        remainingBuffer: Data?,
        completion: @escaping (Result<TLSRecordConnection, Error>) -> Void
    ) {
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
        tlsConnection.negotiatedALPN = self.negotiatedALPN
        self.connection = nil

        if let remaining = remainingBuffer, !remaining.isEmpty {
            tlsConnection.prependToReceiveBuffer(remaining)
        }

        clearHandshakeState()
        completion(.success(tlsConnection))
    }

    // MARK: - Certificate Validation

    private func validateCertificate(completion: @escaping (Result<Void, Error>) -> Void) {
        if CertificatePolicy.allowInsecure {
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
            completion(.failure(TLSError.certificateValidationFailed(message)))
        }
    }

    // MARK: - CertificateVerify (TLS 1.3)

    private func verifyCertificateVerify(
        transcript: Data,
        algorithm: UInt16,
        signature: Data
    ) throws {
        guard let kd = tls13.keyDerivation else {
            throw TLSError.handshakeFailed("Missing key derivation")
        }

        // Verify that the signature algorithm matches the client's offer.
        guard Self.offeredSignatureAlgorithms.contains(algorithm) else {
            throw TLSError.certificateValidationFailed("CertificateVerify algorithm not offered")
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

    private func secKeyAlgorithm(for tlsAlgorithm: UInt16) -> SecKeyAlgorithm {
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

    // MARK: - CompressedCertificate (RFC 8879)

    private func decompressCertificate(_ body: Data) -> Data? {
        guard body.count >= 8 else { return nil }

        let algorithm = UInt16(body[0]) << 8 | UInt16(body[1])
        let uncompressedLength = Int(body[2]) << 16 | Int(body[3]) << 8 | Int(body[4])
        let compressedLength = Int(body[5]) << 16 | Int(body[6]) << 8 | Int(body[7])
        guard 8 + compressedLength <= body.count else { return nil }
        let compressed = body.subdata(in: 8..<(8 + compressedLength))

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

    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
    }

    private static func isUserTrusted(certificate: SecCertificate) -> Bool {
        let trusted = CertificatePolicy.trustedFingerprints
        guard !trusted.isEmpty else { return false }
        let certData = SecCertificateCopyData(certificate) as Data
        let sha256 = SHA256.hash(data: certData).map { String(format: "%02x", $0) }.joined()
        return trusted.contains(sha256)
    }

    private func clearHandshakeState() {
        ephemeralPrivateKey = nil
        storedClientHello = nil
        sentSessionID = nil
        echContext = nil
        echAccepted = false
        tls13 = TLS13HandshakeState()
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
