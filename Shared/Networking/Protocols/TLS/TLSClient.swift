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
import Synchronization

// MARK: - ServerHello Result

nonisolated private enum ServerHelloResult {
    /// key_share carries an X25519 public key.
    case tls13(keyShare: Data, cipherSuite: UInt16)
    case tls12(cipherSuite: UInt16, serverRandom: Data, version: UInt16, extendedMasterSecret: Bool)
    /// Surfaced as a terminal outcome: we don't send a second ClientHello flight.
    case helloRetryRequest
}

// MARK: - TLSClient

actor TLSClient {
    let configuration: TLSConfiguration

    /// The live transport, kept behind a `Mutex` (not actor-isolated) so the synchronous
    /// ``cancel()`` — called from teardown on other tasks — can abort an in-flight handshake without
    /// hopping onto the actor. Cancelling it makes the driver's parked `receive()` throw, which
    /// unwinds the handshake and clears the isolated crypto state via `releaseOnFailure`.
    /// Read via the ``connection`` snapshot; mutations go through ``adoptTransport(_:)`` and the
    /// atomic ``takeConnection()`` so no caller treats the lock as a plain variable.
    private let connectionBox = Mutex<(any ByteTransport)?>(nil)

    /// Read-only snapshot of the live transport; `nil` before adoption and after teardown.
    nonisolated var connection: (any ByteTransport)? { connectionBox.withLock { $0 } }

    /// Publishes the handshake's transport. Called once per connect attempt before the first send.
    private func adoptTransport(_ transport: any ByteTransport) {
        connectionBox.withLock { $0 = transport }
    }

    /// Atomically detaches and returns the transport, so a racing adopt/cancel can never leave a
    /// transport both published and cancelled-behind-its-back. Internal: the TLS 1.2/1.3 finish
    /// paths use it to hand the transport over to the record connection.
    nonisolated func takeConnection() -> (any ByteTransport)? {
        connectionBox.withLock { connection in
            let taken = connection
            connection = nil
            return taken
        }
    }

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
    /// Handshake transcript for TLS 1.2 Finished computation.
    var tls12Transcript: Data?

    var serverCertificates: [SecCertificate] = []

    // Buffer for data received after Server Finished (e.g. NewSessionTicket)
    var postHandshakeBuffer: Data?

    /// The value of the ALPN sent by the peer; empty when the server echoed none.
    var negotiatedALPN: String = ""

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

    /// Dials a fresh TCP connection and performs the TLS handshake async-natively over the
    /// transport's async surface. The ClientHello rides the connect as initial data, saving a
    /// round trip.
    func connect(host: String, port: UInt16) async throws -> TLSRecordConnection {
        do {
            try await prepareECH()

            ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            guard let privateKey = ephemeralPrivateKey else {
                throw TLSError.handshakeFailed("No ephemeral key")
            }

            let clientHello = try buildTLSClientHello(privateKey: privateKey)
            storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

            let transport = TCPTransport(host: host, port: port)
            adoptTransport(transport)
            do {
                try await transport.connect(initialData: clientHello)
            } catch {
                throw TLSError.connectionFailed(error.localizedDescription)
            }

            return try await receiveServerResponse()
        } catch {
            releaseOnFailure()
            throw error
        }
    }

    /// Performs the TLS handshake over an existing proxy tunnel (proxy chaining).
    func connect(overTunnel tunnel: ProxyConnection) async throws -> TLSRecordConnection {
        do {
            try await prepareECH()

            ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            guard let privateKey = ephemeralPrivateKey else {
                throw TLSError.handshakeFailed("No ephemeral key")
            }
            adoptTransport(TunneledTransport(tunnel: tunnel))

            let clientHello = try buildTLSClientHello(privateKey: privateKey)
            storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

            guard let connection = self.connection else {
                throw TLSError.connectionFailed("Connection cancelled")
            }
            do {
                try await connection.send(clientHello)
            } catch {
                throw TLSError.handshakeFailed(error.localizedDescription)
            }

            return try await receiveServerResponse()
        } catch {
            releaseOnFailure()
            throw error
        }
    }

    /// Aborts an in-flight handshake from any task. Cancelling the transport makes the driver's
    /// parked `receive()` throw, so `releaseOnFailure` clears the isolated crypto state as it unwinds
    /// — this nonisolated path only needs to drop the transport.
    nonisolated func cancel() {
        takeConnection()?.cancel()
    }

    private func releaseOnFailure() {
        takeConnection()?.cancel()
        clearHandshakeState()
    }

    // MARK: - ClientHello

    /// Resolves an opportunistic ECHConfigList from DNS before the handshake.
    /// Fail-closed: a discovery miss errors so the caller never falls back to a cleartext-SNI handshake.
    private func prepareECH() async throws {
        guard configuration.echIsOpportunistic else { return }
        let serverName = configuration.serverName
        let config: Data? = await DNSResolver.shared.resolveECHConfigList(for: serverName)
        guard let config else {
            throw TLSError.handshakeFailed(
                "Opportunistic ECH: no ECH config published in DNS for \(serverName)")
        }
        self.resolvedECHConfigList = config
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
    private func receiveServerResponse(buffer: Data = Data()) async throws -> TLSRecordConnection {
        var buffer = buffer
        while buffer.count < 5 {
            guard let connection else {
                throw TLSError.connectionFailed("Connection cancelled")
            }
            switch try await connection.receive() {
            case .bytes(let data):
                buffer.append(data)
            case .end:
                throw TLSError.handshakeFailed("No server response")
            }
        }

        let contentType = buffer[buffer.startIndex]
        if contentType == TLSContentType.handshake {
            return try await continueReceivingHandshake(buffer: buffer)
        } else if contentType == TLSContentType.alert {
            let alertLevel = buffer.count > 5 ? buffer[buffer.startIndex + 5] : 0
            let alertDesc = buffer.count > 6 ? buffer[buffer.startIndex + 6] : 0
            throw TLSError.alert(level: alertLevel, description: alertDesc)
        } else {
            throw TLSError.handshakeFailed("Unexpected content type: \(contentType)")
        }
    }

    /// Continues receiving handshake messages until ServerHello is complete, then dispatches.
    private func continueReceivingHandshake(buffer: Data) async throws -> TLSRecordConnection {
        var buffer = buffer
        while !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                throw TLSError.connectionFailed("Connection cancelled")
            }
            switch try await connection.receive() {
            case .bytes(let moreData):
                buffer.append(moreData)
            case .end:
                throw TLSError.handshakeFailed("Connection closed before ServerHello")
            }
        }

        guard let serverHelloResult = parseServerHello(data: buffer),
              let clientHello = storedClientHello else {
            throw TLSError.handshakeFailed("Failed to parse ServerHello")
        }

        switch serverHelloResult {
        case .helloRetryRequest:
            // We don't implement the second ClientHello flight HRR requires. Aborting
            // here doesn't leak the inner SNI, since the ClientHello is already sent.
            throw TLSError.helloRetryRequest

        case .tls13(let serverKeyShare, let cipherSuite):
            return try await handleTLS13Handshake(
                buffer: buffer,
                serverKeyShare: serverKeyShare,
                cipherSuite: cipherSuite,
                clientHello: clientHello
            )

        case .tls12(let cipherSuite, let serverRandom, let version, let extendedMasterSecret):
            self.serverRandom = serverRandom
            self.tls12CipherSuite = cipherSuite
            self.negotiatedVersion = version
            self.useExtendedMasterSecret = extendedMasterSecret
            return try await handleTLS12Handshake(
                buffer: buffer,
                clientHello: clientHello
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

    func validateCertificate() throws {
        if configuration.insecureSkipVerify {
            return
        }
        switch CertificatePolicy.verify(chain: serverCertificates, serverName: configuration.serverName) {
        case .trusted:
            return
        case .rejected(let reason):
            throw TLSError.certificateValidationFailed(reason)
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
