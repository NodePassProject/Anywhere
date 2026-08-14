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
    case tls13(keyShare: Data, cipherSuite: UInt16)
    case tls12(cipherSuite: UInt16, serverRandom: Data, version: UInt16, extendedMasterSecret: Bool)
    case helloRetryRequest
}

// MARK: - TLSClient

actor TLSClient {
    let configuration: TLSConfiguration

    // MARK: Lifecycle

    private enum Phase: PhaseTransitionable {
        case idle, connecting, established, failed, cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .established),
                 (.connecting, .failed):
                return true
            case (_, .cancelled):
                return old != .cancelled
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle
        var connection: (any ByteTransport)?
    }
    private nonisolated let state = Mutex(State())

    nonisolated var connection: (any ByteTransport)? { state.withLock { $0.connection } }

    private nonisolated func adoptTransport(_ transport: any ByteTransport) {
        let adopted = state.withLock { state -> Bool in
            switch state.phase {
            case .cancelled, .failed:
                return false
            case .idle, .connecting, .established:
                state.connection = transport
                return true
            }
        }
        if !adopted { transport.cancel() }
    }

    private func claimConnect() throws {
        try state.withLock { state in
            switch state.phase {
            case .idle:
                break
            case .cancelled:
                throw AnywhereError.tls(.handshakeFailed(detail: "TLS client cancelled"))
            case .connecting, .established, .failed:
                throw AnywhereError.tls(.handshakeFailed(detail: "TLS client reused"))
            }
            state.transition(to: .connecting)
        }
    }

    func commitHandshake(_ record: TLSRecordConnection) throws {
        let (committed, taken): (Bool, (any ByteTransport)?) = state.withLock { state in
            let committed = state.transition(to: .established)
            let taken = state.connection
            state.connection = nil
            return (committed, taken)
        }
        guard committed else {
            taken?.cancel()
            record.cancel()
            throw AnywhereError.tls(.handshakeFailed(detail: "cancelled during handshake"))
        }
        record.adoptTransport(taken)
    }

    var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var storedClientHello: Data?
    private var sentSessionID: Data?

    var echContext: ECHClientContext?
    private var resolvedECHConfigList: Data?

    var tls13 = TLS13HandshakeState()

    var clientRandom: Data?
    var serverRandom: Data?
    var masterSecret: Data?
    var tls12CipherSuite: UInt16 = 0
    var negotiatedVersion: UInt16 = 0
    var useExtendedMasterSecret = false
    var ecdhP256PrivateKey: P256.KeyAgreement.PrivateKey?
    var ecdhP384PrivateKey: P384.KeyAgreement.PrivateKey?
    var tls12Transcript: Data?

    var serverCertificates: [SecCertificate] = []

    var postHandshakeBuffer: Data?

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

    private static let handshakeDeadline: Duration = .seconds(30)

    private func withHandshakeDeadline(
        _ handshake: @escaping @Sendable () async throws -> TLSRecordConnection
    ) async throws -> TLSRecordConnection {
        do {
            return try await withDialDeadline(Self.handshakeDeadline, onExpiry: {
                self.cancel()
            }, error: {
                AnywhereError.tls(.handshakeFailed(detail: "handshake timed out"))
            }, discardingLateResult: { record in
                record.cancel()
            }, operation: handshake)
        } catch {
            releaseOnFailure()
            throw error
        }
    }

    func connect(host: String, port: UInt16) async throws -> TLSRecordConnection {
        try claimConnect()
        return try await withHandshakeDeadline {
            try await self.performConnect(host: host, port: port)
        }
    }

    private func performConnect(host: String, port: UInt16) async throws -> TLSRecordConnection {
        try await prepareECH()

        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        guard let privateKey = ephemeralPrivateKey else {
            throw AnywhereError.tls(.handshakeFailed(detail: "No ephemeral key"))
        }

        let clientHello = try buildTLSClientHello(privateKey: privateKey)
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        let transport = TCPTransport(host: host, port: port, resolvesViaProxyDNS: true)
        adoptTransport(transport)
        do {
            try await transport.connect(initialData: clientHello)
        } catch {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: error.localizedDescription))
        }

        return try await receiveServerResponse()
    }

    func connect(overTunnel tunnel: ProxyConnection) async throws -> TLSRecordConnection {
        try claimConnect()
        return try await withHandshakeDeadline {
            try await self.performConnect(overTunnel: tunnel)
        }
    }

    private func performConnect(overTunnel tunnel: ProxyConnection) async throws -> TLSRecordConnection {
        try await prepareECH()

        ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        guard let privateKey = ephemeralPrivateKey else {
            throw AnywhereError.tls(.handshakeFailed(detail: "No ephemeral key"))
        }
        adoptTransport(TunneledTransport(tunnel: tunnel))

        let clientHello = try buildTLSClientHello(privateKey: privateKey)
        storedClientHello = clientHello.subdata(in: 5..<clientHello.count)

        guard let connection = self.connection else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
        }
        do {
            try await connection.send(clientHello)
        } catch {
            throw AnywhereError.tls(.handshakeFailed(detail: error.localizedDescription))
        }

        return try await receiveServerResponse()
    }

    nonisolated func cancel() {
        let victim = state.withLock { state -> (any ByteTransport)? in
            _ = state.transition(to: .cancelled)
            let connection = state.connection
            state.connection = nil
            return connection
        }
        victim?.cancel()
    }

    private func releaseOnFailure() {
        let victim = state.withLock { state -> (any ByteTransport)? in
            _ = state.transition(to: .failed)
            let connection = state.connection
            state.connection = nil
            return connection
        }
        victim?.cancel()
        clearHandshakeState()
    }

    // MARK: - ClientHello

    private func prepareECH() async throws {
        guard configuration.echIsOpportunistic else { return }
        let serverName = configuration.serverName
        let config: Data? = await DNSResolver.shared.resolveECHConfigList(for: serverName)
        guard let config else {
            throw AnywhereError.tls(.handshakeFailed(detail:
                "Opportunistic ECH: no ECH config published in DNS for \(serverName)"))
        }
        self.resolvedECHConfigList = config
    }

    private func buildTLSClientHello(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        var random = Data(count: 32)
        guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Failed to generate random bytes"))
        }
        clientRandom = random

        var sessionId = Data(count: 32)
        guard sessionId.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Failed to generate session ID"))
        }
        sentSessionID = sessionId

        if configuration.echEnabled,
           let echConfigData = ECHConfigResolver.resolveImmediate(configuration.echConfig) ?? resolvedECHConfigList {
            let configs = try ECHConfigParser.parseConfigList(echConfigData)
            guard let config = ECHConfig.pick(from: configs) else {
                throw AnywhereError.tls(.handshakeFailed(detail: "ECHConfigList contains no usable config"))
            }
            guard let cipherSuite = config.pickCipherSuite() else {
                throw AnywhereError.tls(.handshakeFailed(detail: "ECH config offers no supported cipher suite"))
            }

            var innerRandom = Data(count: 32)
            guard innerRandom.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
                throw AnywhereError.tls(.handshakeFailed(detail: "Failed to generate inner random"))
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
            throw AnywhereError.tls(.handshakeFailed(detail: "ECH requested but its ECHConfigList is not valid base64"))
        } else if configuration.echEnabled {
            throw AnywhereError.tls(.handshakeFailed(detail: "Opportunistic ECH requested but no ECH config was discovered"))
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

    private func receiveServerResponse(buffer: Data = Data()) async throws -> TLSRecordConnection {
        var buffer = buffer
        while buffer.count < 5 {
            guard let connection else {
                throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
            }
            switch try await connection.receive() {
            case .bytes(let data):
                buffer.append(data)
            case .end:
                throw AnywhereError.tls(.handshakeFailed(detail: "No server response"))
            }
        }

        let contentType = buffer[buffer.startIndex]
        if contentType == TLSContentType.handshake {
            return try await continueReceivingHandshake(buffer: buffer)
        } else if contentType == TLSContentType.alert {
            let alertLevel = buffer.count > 5 ? buffer[buffer.startIndex + 5] : 0
            let alertDesc = buffer.count > 6 ? buffer[buffer.startIndex + 6] : 0
            throw AnywhereError.tls(.alert(level: alertLevel, code: alertDesc))
        } else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Unexpected content type: \(contentType)"))
        }
    }

    private func continueReceivingHandshake(buffer: Data) async throws -> TLSRecordConnection {
        var buffer = buffer
        while !bufferContainsCompleteServerHello(buffer) {
            guard let connection else {
                throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Connection cancelled"))
            }
            switch try await connection.receive() {
            case .bytes(let moreData):
                buffer.append(moreData)
            case .end:
                throw AnywhereError.tls(.handshakeFailed(detail: "Connection closed before ServerHello"))
            }
        }

        guard let serverHelloResult = parseServerHello(data: buffer),
              let clientHello = storedClientHello else {
            throw AnywhereError.tls(.handshakeFailed(detail: "Failed to parse ServerHello"))
        }

        switch serverHelloResult {
        case .helloRetryRequest:
            throw AnywhereError.tls(.helloRetryRequest)

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
            throw AnywhereError.tls(.certificateValidationFailed(detail: reason))
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
