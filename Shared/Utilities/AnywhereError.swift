//
//  AnywhereError.swift
//  Anywhere
//
//  Created by NodePassProject on 7/19/26.
//

import Foundation

nonisolated enum AnywhereError: Error {
    case dns(DNS)
    case transport(Transport)
    case tls(TLS)
    case quic(QUIC)
    case proxy(Wire, Proxy)
    case routing(Routing)
    case mitm(MITM)
    case certificate(Certificate)
    case store(Store)
    case parse(Parse)
    case subscription(Subscription)
    case tunnel(Tunnel)
    case diagnostics(Diagnostics)
    case wrapped(context: String, underlying: any Error)

    // MARK: Wire
    
    enum Wire: String, Sendable {
        case direct = "Direct"
        case socks5 = "SOCKS5"
        case httpConnect = "HTTP"
        case http1 = "HTTP/1"
        case http2 = "HTTP/2"
        case http3 = "HTTP/3"
        case shadowsocks = "Shadowsocks"
        case trojan = "Trojan"
        case anyTLS = "AnyTLS"
        case vless = "VLESS"
        case vlessEncryption = "VLESS Encryption"
        case sudoku = "Sudoku"
        case naive = "Naive"
        case hysteria = "Hysteria"
        case nowhere = "Nowhere"
        case webSocket = "WebSocket"
        case grpc = "gRPC"
        case xhttp = "XHTTP"
        case httpUpgrade = "HTTPUpgrade"
    }

    // MARK: DNS

    enum DNS: Sendable, Equatable {
        case resolutionFailed(host: String?, detail: String?)
        case noAddresses(host: String)
        case malformedResponse
        case timedOut(host: String)
    }

    // MARK: Transport
    
    enum Transport: Sendable, Equatable {
        enum Operation: String, Sendable {
            case connect, send, receive, close
        }
        
        case posix(Operation, errno: Int32)
        case lwip(Operation, code: Int32)
        case notConnected
        case connectionFailed(endpoint: String?, detail: String)
        case timedOut(Operation, endpoint: String?, detail: String?)
        case terminated
        /// A fatal `tcp_write` on the downlink (not backpressure — that retries silently).
        case writeFailed(pending: Int, sndbuf: Int)
    }

    // MARK: TLS

    enum TLS: Sendable, Equatable {
        case handshakeFailed(detail: String)
        case certificateValidationFailed(detail: String)
        case unsupportedVersion
        case alert(level: UInt8, code: UInt8)
        case unexpectedAlert
        case helloRetryRequest
        case record(Record)
        case clientHello(ClientHello)
        case ech(ECH)
        case reality(Reality)
        
        enum Record: Sendable, Equatable {
            case ciphertextTooShort
            case emptyPlaintext
            case missingContentType
            case invalidPadding
            case encryptionFailed
            case ivGenerationFailed
            case authenticationFailed
            case macVerificationFailed
            case malformed(detail: String)
            case connectionUnavailable
        }
        
        enum ClientHello: Sendable, Equatable {
            case truncated
            case notHandshake
            case notClientHello
            case lengthMismatch
            case malformed(detail: String)
        }

        enum ECH: Sendable, Equatable {
            case malformedConfigList
            case malformedConfig
            case malformedInnerHello
            case noCompatibleConfig
            case noCompatibleCipherSuite
            case unsupportedKEM
            case unsupportedKDF
            case unsupportedAEAD
            case invalidPublicKey
            case hpkeSetupFailed
            case sealFailed
            case rejected(retryConfigList: Data?)
        }

        enum Reality: Sendable, Equatable {
            case invalidPublicKey
            case authenticationFailed
            case decryptionFailed
        }
    }

    // MARK: QUIC

    enum QUIC: Sendable, Equatable {
        case connectionFailed(detail: String)
        case handshakeFailed(detail: String)
        case streamFailed(detail: String)
        case streamReset(applicationCode: UInt64)
        case streamClosedWithError(applicationCode: UInt64)
        case datagramTooLarge(limit: Int)
        case datagramQueueFull
        case timedOut
        case closed(graceful: Bool)
    }

    // MARK: Proxy
    
    enum Proxy: Sendable, Equatable {
        case invalidConfiguration(detail: String)
        case notReady
        case handshakeFailed(detail: String)
        case authenticationRequired
        case authenticationRejected(status: Int?, detail: String?)
        case tunnelRejected(detail: String)
        case protocolViolation(detail: String)
        case upgradeFailed(detail: String)
        case rpcFailed(status: Int, method: String, message: String?)
        case streamClosed
        case connectionClosed(detail: String?)
        case webSocketClosed(code: UInt16, reason: String)
        case streamReset(code: UInt32)
        case goaway
        case streamIDsExhausted
        case flowRejected(code: UInt8)
        case openTimeout
        case unsupported(feature: String)
        case datagramTooLarge(maxFrame: Int, headerSize: Int)
        case packetTooLarge
        case cipher(Cipher)
        
        enum Cipher: Sendable, Equatable {
            case unsupportedMethod(String)
            case invalidKey
            case encryptionFailed
            case decryptionFailed
            case staleTimestamp
            case replayedSalt
            case malformedHeader
        }
    }

    // MARK: Routing

    enum Routing: Sendable, Equatable {
        case rejectedByRule(host: String)
        case dropped
        case payloadCorrupted(BinaryPayload)
        case configurationMissing(host: String)
    }
    
    enum BinaryPayload: Sendable, Equatable {
        case badMagic
        case unsupportedVersion
        case truncated
        case malformed
    }

    // MARK: MITM

    enum MITM: Sendable, Equatable {
        case notHTTP
        case responseTooLarge(limit: Int)
        case scriptBudgetExceeded(limit: Int)
        case scriptStoreCapacityExceeded
        case scriptStoreWriteFailed
        case scriptMessageMalformed(detail: String)
        case invalidScriptRequest
        case upstreamHandshakeTimeout
        case requestHeadersTooLarge
        case needsHTTP1Fallback
        case rewriteRulesCorrupted(BinaryPayload)
        case profileServerBindFailed
    }

    // MARK: Certificate
    
    enum Certificate: Sendable {
        case keyGenerationFailed(detail: String)
        case keychainWriteFailed(status: OSStatus)
        case keychainReadFailed(status: OSStatus)
        case missingCAComponents
        case buildFailed(underlying: any Error)
        case signingFailed(detail: String)
        case publicKeyExportFailed
        case invalidPublicKey
        case asn1ParseFailed(detail: String)
    }

    // MARK: Store
    
    enum Store: Sendable {
        enum Resource: String, Sendable {
            case configurations, chains, subscriptions, certificates
            case routingRuleSets, mitmRuleSets, routingDatabase
            case routingPayload, mitmPayload, scripts
        }

        case loadFailed(Resource, underlying: any Error)
        case saveFailed(Resource, underlying: any Error)
        case missing(Resource)
        case corrupted(Resource, detail: String?)
        case migrationFailed(file: String, underlying: any Error)
        case syncFailed(underlying: any Error)
    }

    // MARK: Parse
    
    enum Parse: Sendable, Equatable {
        case yaml(detail: String)
        case clashConfigMissingProxies
        case invalidURL(String)
        case proxyURI(ProxyURI)

        enum ProxyURI: Sendable, Equatable {
            case unsupportedScheme(String?)
            case missingFields
            case invalidValue(field: String, value: String)
            case noPublicKeys
        }
    }

    // MARK: Subscription
    
    enum Subscription: Sendable {
        case invalidURL
        case noConfigurations
        case fetchFailed(underlying: any Error)
    }

    // MARK: Tunnel
    
    enum Tunnel: Sendable {
        case invalidConfiguration
        case settingsApplyFailed(underlying: any Error)
        case ipcFailed(underlying: any Error)
        case sessionUnavailable
    }

    // MARK: Diagnostics

    enum Diagnostics: Sendable, Equatable {
        case latencyProbeFailed(status: String)
    }
}

// MARK: - Descriptions

nonisolated extension AnywhereError: LocalizedError {
    var errorDescription: String? {
        domainTag.isEmpty ? conciseDescription : "\(domainTag): \(conciseDescription)"
    }
    
    var conciseDescription: String {
        switch self {
        case .dns(let f): f.failureDescription
        case .transport(let f): f.failureDescription
        case .tls(let f): f.failureDescription
        case .quic(let f): f.failureDescription
        case .proxy(_, let f): f.failureDescription
        case .routing(let f): f.failureDescription
        case .mitm(let f): f.failureDescription
        case .certificate(let f): f.failureDescription
        case .store(let f): f.failureDescription
        case .parse(let f): f.failureDescription
        case .subscription(let f): f.failureDescription
        case .tunnel(let f): f.failureDescription
        case .diagnostics(let f): f.failureDescription
        case .wrapped(let context, let underlying): "\(context): \(Self.describe(underlying))"
        }
    }

    private var domainTag: String {
        switch self {
        case .dns: "DNS"
        case .transport: "Transport"
        case .tls: "TLS"
        case .quic: "QUIC"
        case .proxy(let wire, _): wire.rawValue
        case .routing: "Routing"
        case .mitm: "MITM"
        case .certificate: "Certificate"
        case .store: "Store"
        case .parse: "Parse"
        case .tunnel: "Tunnel"
        case .diagnostics: "Diagnostics"
        case .subscription, .wrapped: ""
        }
    }
}

nonisolated extension AnywhereError.DNS {
    var failureDescription: String {
        switch self {
        case .resolutionFailed(let host, let detail):
            "resolution failed" + (host.map { " for \($0)" } ?? "") + (detail.map { ": \($0)" } ?? "")
        case .noAddresses(let host): "no addresses for \(host)"
        case .malformedResponse: "malformed response"
        case .timedOut(let host): "resolution timed out for \(host)"
        }
    }
}

nonisolated extension AnywhereError.Transport {
    var failureDescription: String {
        switch self {
        case .posix(let op, let errno): "\(op.rawValue) failed: \(String(cString: strerror(errno)))"
        case .lwip(let op, let code): "\(op.rawValue) failed: \(Self.lwipName(code))"
        case .notConnected: "not connected"
        case .connectionFailed(let endpoint, let detail):
            "connect" + (endpoint.map { " to \($0)" } ?? "") + " failed: \(detail)"
        case .timedOut(let op, let endpoint, let detail):
            "\(op.rawValue) timed out" + (endpoint.map { ": \($0)" } ?? "") + (detail.map { " (\($0))" } ?? "")
        case .terminated: "transport terminated"
        case .writeFailed(let pending, let sndbuf):
            "downlink write failed (pending \(pending), send buffer \(sndbuf))"
        }
    }
    
    static func lwipName(_ err: Int32) -> String {
        switch err {
        case 0:   "ERR_OK"
        case -1:  "ERR_MEM (out of memory)"
        case -2:  "ERR_BUF (buffer error)"
        case -3:  "ERR_TIMEOUT (timed out)"
        case -4:  "ERR_RTE (routing problem)"
        case -5:  "ERR_INPROGRESS"
        case -6:  "ERR_VAL (illegal value)"
        case -7:  "ERR_WOULDBLOCK"
        case -8:  "ERR_USE (address in use)"
        case -9:  "ERR_ALREADY (already connecting)"
        case -10: "ERR_ISCONN (already connected)"
        case -11: "ERR_CONN (not connected)"
        case -12: "ERR_IF (low-level netif error)"
        case -13: "ERR_ABRT (aborted locally)"
        case -14: "ERR_RST (reset by peer)"
        case -15: "ERR_CLSD (connection closed)"
        case -16: "ERR_ARG (illegal argument)"
        default:  "lwIP err=\(err)"
        }
    }
}

nonisolated extension AnywhereError.TLS {
    var failureDescription: String {
        switch self {
        case .handshakeFailed(let detail): "handshake failed: \(detail)"
        case .certificateValidationFailed(let detail): "certificate validation failed: \(detail)"
        case .unsupportedVersion: "unsupported protocol version"
        case .alert(let level, let code): "alert received (level \(level), code \(code))"
        case .unexpectedAlert: "unexpected alert"
        case .helloRetryRequest: "server requested hello retry"
        case .record(let f): f.failureDescription
        case .clientHello(let f): f.failureDescription
        case .ech(let f): f.failureDescription
        case .reality(let f): f.failureDescription
        }
    }
}

nonisolated extension AnywhereError.TLS.Record {
    var failureDescription: String {
        switch self {
        case .ciphertextTooShort: "record ciphertext too short"
        case .emptyPlaintext: "decrypted record is empty"
        case .missingContentType: "no content type in record"
        case .invalidPadding: "invalid record padding"
        case .encryptionFailed: "record encryption failed"
        case .ivGenerationFailed: "IV generation failed"
        case .authenticationFailed: "record authentication failed"
        case .macVerificationFailed: "record MAC verification failed"
        case .malformed(let detail): "malformed record: \(detail)"
        case .connectionUnavailable: "record connection unavailable"
        }
    }
}

nonisolated extension AnywhereError.TLS.ClientHello {
    var failureDescription: String {
        switch self {
        case .truncated: "ClientHello truncated"
        case .notHandshake: "not a handshake record"
        case .notClientHello: "not a ClientHello"
        case .lengthMismatch: "ClientHello length mismatch"
        case .malformed(let detail): "malformed ClientHello: \(detail)"
        }
    }
}

nonisolated extension AnywhereError.TLS.ECH {
    var failureDescription: String {
        switch self {
        case .malformedConfigList: "ECH config list malformed"
        case .malformedConfig: "ECH config malformed"
        case .malformedInnerHello: "ECH inner hello malformed"
        case .noCompatibleConfig: "no compatible ECH config"
        case .noCompatibleCipherSuite: "no compatible ECH cipher suite"
        case .unsupportedKEM: "unsupported HPKE KEM"
        case .unsupportedKDF: "unsupported HPKE KDF"
        case .unsupportedAEAD: "unsupported HPKE AEAD"
        case .invalidPublicKey: "invalid ECH public key"
        case .hpkeSetupFailed: "HPKE sender setup failed"
        case .sealFailed: "HPKE seal failed"
        case .rejected(let retry):
            "ECH rejected by server" + (retry != nil ? " (retry configs provided)" : "")
        }
    }
}

nonisolated extension AnywhereError.TLS.Reality {
    var failureDescription: String {
        switch self {
        case .invalidPublicKey: "invalid REALITY public key"
        case .authenticationFailed: "REALITY authentication failed"
        case .decryptionFailed: "REALITY decryption failed"
        }
    }
}

nonisolated extension AnywhereError.QUIC {
    var failureDescription: String {
        switch self {
        case .connectionFailed(let detail): "connection failed: \(detail)"
        case .handshakeFailed(let detail): "handshake failed: \(detail)"
        case .streamFailed(let detail): "stream failed: \(detail)"
        case .streamReset(let code): "stream reset (application code \(code))"
        case .streamClosedWithError(let code): "stream closed (application code \(code))"
        case .datagramTooLarge(let limit): "datagram exceeds \(limit) bytes"
        case .datagramQueueFull: "datagram queue full"
        case .timedOut: "timed out"
        case .closed(let graceful): graceful ? "closed" : "closed unexpectedly"
        }
    }
}

nonisolated extension AnywhereError.Proxy {
    var failureDescription: String {
        switch self {
        case .invalidConfiguration(let detail): "invalid configuration: \(detail)"
        case .notReady: "session not ready"
        case .handshakeFailed(let detail): "handshake failed: \(detail)"
        case .authenticationRequired: "authentication required"
        case .authenticationRejected(let status, let detail):
            "authentication rejected"
                + (status.map { " (status \($0))" } ?? "")
                + (detail.map { ": \($0)" } ?? "")
        case .tunnelRejected(let detail): "tunnel rejected: \(detail)"
        case .protocolViolation(let detail): "protocol violation: \(detail)"
        case .upgradeFailed(let detail): "upgrade failed: \(detail)"
        case .rpcFailed(let status, let method, let message):
            "RPC \(method) failed (status \(status))" + (message.map { ": \($0)" } ?? "")
        case .streamClosed: "stream closed"
        case .connectionClosed(let detail):
            "connection closed" + (detail.map { ": \($0)" } ?? "")
        case .webSocketClosed(let code, let reason): "closed by peer (code \(code)): \(reason)"
        case .streamReset(let code): "stream reset (code \(code))"
        case .goaway: "GOAWAY received"
        case .streamIDsExhausted: "stream IDs exhausted"
        case .flowRejected(let code): "flow rejected (code \(code))"
        case .openTimeout: "flow open timed out"
        case .unsupported(let feature): "unsupported: \(feature)"
        case .datagramTooLarge(let maxFrame, let headerSize):
            "destination too large for datagram (max frame \(maxFrame), header \(headerSize))"
        case .packetTooLarge: "packet exceeds datagram size limit"
        case .cipher(let f): f.failureDescription
        }
    }
}

nonisolated extension AnywhereError.Proxy.Cipher {
    var failureDescription: String {
        switch self {
        case .unsupportedMethod(let name): "unsupported cipher method: \(name)"
        case .invalidKey: "invalid key material"
        case .encryptionFailed: "encryption failed"
        case .decryptionFailed: "decryption failed"
        case .staleTimestamp: "stale timestamp (possible replay)"
        case .replayedSalt: "repeated request salt (possible replay)"
        case .malformedHeader: "malformed cipher header"
        }
    }
}

nonisolated extension AnywhereError.Routing {
    var failureDescription: String {
        switch self {
        case .rejectedByRule(let host): "rejected by routing rule: \(host)"
        case .dropped: "dropped by routing policy"
        case .payloadCorrupted(let issue): "routing payload corrupted (\(issue.label))"
        case .configurationMissing(let host): "configuration for routing rule not found: \(host)"
        }
    }
}

nonisolated extension AnywhereError.BinaryPayload {
    var label: String {
        switch self {
        case .badMagic: "bad magic"
        case .unsupportedVersion: "unsupported version"
        case .truncated: "truncated"
        case .malformed: "malformed"
        }
    }
}

nonisolated extension AnywhereError.MITM {
    var failureDescription: String {
        switch self {
        case .notHTTP: "stream is not HTTP"
        case .responseTooLarge(let limit): "response exceeds \(limit) bytes"
        case .scriptBudgetExceeded(let limit): "script body budget exceeded (\(limit) bytes)"
        case .scriptStoreCapacityExceeded: "script store capacity exceeded"
        case .scriptStoreWriteFailed: "script store write failed"
        case .scriptMessageMalformed(let detail): "script bridge message malformed: \(detail)"
        case .invalidScriptRequest: "script request could not be serialized"
        case .upstreamHandshakeTimeout: "upstream TLS handshake timed out"
        case .requestHeadersTooLarge: "request headers too large"
        case .needsHTTP1Fallback: "origin requires HTTP/1 fallback"
        case .rewriteRulesCorrupted(let issue): "rewrite rules corrupted (\(issue.label))"
        case .profileServerBindFailed: "failed to start local profile server"
        }
    }
}

nonisolated extension AnywhereError.Certificate {
    var failureDescription: String {
        switch self {
        case .keyGenerationFailed(let detail): "key generation failed: \(detail)"
        case .keychainWriteFailed(let status): "keychain write failed (OSStatus \(status))"
        case .keychainReadFailed(let status): "keychain read failed (OSStatus \(status))"
        case .missingCAComponents: "CA key or certificate missing"
        case .buildFailed(let underlying): "certificate build failed: \(AnywhereError.describe(underlying))"
        case .signingFailed(let detail): "signing failed: \(detail)"
        case .publicKeyExportFailed: "public key export failed"
        case .invalidPublicKey: "invalid public key"
        case .asn1ParseFailed(let detail): "ASN.1 parse failed: \(detail)"
        }
    }
}

nonisolated extension AnywhereError.Store {
    var failureDescription: String {
        switch self {
        case .loadFailed(let resource, let underlying):
            "failed to load \(resource.rawValue): \(AnywhereError.describe(underlying))"
        case .saveFailed(let resource, let underlying):
            "failed to save \(resource.rawValue): \(AnywhereError.describe(underlying))"
        case .missing(let resource): "\(resource.rawValue) not found"
        case .corrupted(let resource, let detail):
            "\(resource.rawValue) corrupted" + (detail.map { ": \($0)" } ?? "")
        case .migrationFailed(let file, let underlying):
            "failed to migrate \(file): \(AnywhereError.describe(underlying))"
        case .syncFailed(let underlying): "sync failed: \(AnywhereError.describe(underlying))"
        }
    }
}

nonisolated extension AnywhereError.Parse {
    var failureDescription: String {
        switch self {
        case .yaml(let detail): "YAML: \(detail)"
        case .clashConfigMissingProxies: "missing 'proxies' key"
        case .invalidURL(let string): "invalid URL: \(string)"
        case .proxyURI(let f): f.failureDescription
        }
    }
}

nonisolated extension AnywhereError.Parse.ProxyURI {
    var failureDescription: String {
        switch self {
        case .unsupportedScheme(let scheme):
            "unsupported scheme" + (scheme.map { ": \($0)" } ?? "")
        case .missingFields: "required fields missing"
        case .invalidValue(let field, let value): "invalid \(field): \(value)"
        case .noPublicKeys: "no public keys"
        }
    }
}

nonisolated extension AnywhereError.Subscription {
    var failureDescription: String {
        switch self {
        case .invalidURL:
            String(localized: "Invalid subscription URL.")
        case .noConfigurations:
            String(localized: "No valid configurations found in subscription.")
        case .fetchFailed(let underlying):
            String(localized: "Network error: \(underlying.localizedDescription)")
        }
    }
}

nonisolated extension AnywhereError.Tunnel {
    var failureDescription: String {
        switch self {
        case .invalidConfiguration: "invalid or missing configuration"
        case .settingsApplyFailed(let underlying):
            "failed to apply tunnel settings: \(AnywhereError.describe(underlying))"
        case .ipcFailed(let underlying):
            "provider message failed: \(AnywhereError.describe(underlying))"
        case .sessionUnavailable: "tunnel session unavailable"
        }
    }
}

nonisolated extension AnywhereError.Diagnostics {
    var failureDescription: String {
        switch self {
        case .latencyProbeFailed(let status): "latency probe returned unexpected status: \(status)"
        }
    }
}

// MARK: - Classification

nonisolated extension AnywhereError {
    enum PeerClose {
        case cascade
        case reset
    }

    var peerClose: PeerClose? {
        switch self {
        case .transport(.posix(_, errno: EPIPE)): .cascade
        case .transport(.posix(_, errno: ECONNRESET)): .reset
        default: nil
        }
    }

    var posixErrno: Int32? {
        if case .transport(.posix(_, let errno)) = self { errno } else { nil }
    }

    var underlyingError: (any Error)? {
        switch self {
        case .wrapped(_, let e),
             .certificate(.buildFailed(let e)),
             .store(.loadFailed(_, let e)), .store(.saveFailed(_, let e)),
             .store(.migrationFailed(_, let e)), .store(.syncFailed(let e)),
             .subscription(.fetchFailed(let e)),
             .tunnel(.settingsApplyFailed(let e)), .tunnel(.ipcFailed(let e)):
            e
        default:
            nil
        }
    }
    var suggestedLogLevel: AnywhereLogger.Level {
        switch self {
        case .transport(.posix(_, errno: EPIPE)),
             .quic(.closed(graceful: true)),
             .tls(.helloRetryRequest),
             .mitm(.needsHTTP1Fallback),
             .routing(.dropped),
             .proxy(.naive, _):
            .debug
        case .transport(.posix(_, errno: ECONNRESET)),
             .routing(.rejectedByRule),
             .proxy(_, .streamClosed), .proxy(_, .connectionClosed):
            .info
        case .routing(.configurationMissing):
            .warning
        default:
            .error
        }
    }
}

// MARK: - Capture & Interop

nonisolated extension AnywhereError {
    static func capture(_ error: any Error, context: @autoclosure () -> String) -> any Error {
        switch error {
        case is CancellationError, is AnywhereError: error
        default: AnywhereError.wrapped(context: context(), underlying: error)
        }
    }
    
    static func describe(_ error: any Error) -> String {
        switch error {
        case let error as AnywhereError: error.conciseDescription
        case is CancellationError: "cancelled"
        default: error.localizedDescription
        }
    }
    static func severity(of error: any Error) -> AnywhereLogger.Level {
        switch error {
        case let error as AnywhereError: error.suggestedLogLevel
        case is CancellationError: .debug
        default: .error
        }
    }
}

// MARK: - AnywhereLogger Coordination

nonisolated extension AnywhereLogger {
    func report(_ message: @autoclosure () -> String, error: any Error) {
        emit("\(message()): \(AnywhereError.describe(error))", at: AnywhereError.severity(of: error))
    }
    
    func report(_ error: any Error) {
        emit((error as? AnywhereError)?.errorDescription ?? AnywhereError.describe(error),
             at: AnywhereError.severity(of: error))
    }

    private func emit(_ line: String, at level: Level) {
        switch level {
        case .debug: debug(line)
        case .info: info(line)
        case .warning: warning(line)
        case .error: self.error(line)
        }
    }
}
