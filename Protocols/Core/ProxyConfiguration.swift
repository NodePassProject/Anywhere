//
//  ProxyConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Outbound protocol type.
enum OutboundProtocol: String, Codable {
    case vless
    case hysteria
    case trojan
    case shadowsocks
    case socks5
    case http11
    case http2
    case http3

    /// Whether this protocol uses a CONNECT tunnel (HTTP/1.1, HTTP/2, or HTTP/3).
    var isNaive: Bool { self == .http11 || self == .http2 || self == .http3 }

    /// Whether the protocol's handshake can carry the caller's first bytes
    /// inline, letting the client ship the TLS ClientHello / MTProto nonce /
    /// etc. in the same packet as the handshake.
    ///
    /// `false` for protocols whose handshake has no payload slot (Shadowsocks,
    /// Naive's HTTP CONNECT, Hysteria's TCPRequest, SOCKS5's method negotiation).
    /// ``LWIPTCPConnection`` checks this to decide whether to hand `pendingData`
    /// to the handshake (true) or to leave it buffered and forward it via a
    /// separate `send(...)` right after the tunnel is up (false).
    ///
    /// Getting this wrong for Hysteria silently swallowed the caller's first
    /// bytes — `connectWithHysteria` drops any `initialData` argument — which
    /// manifested as Telegram hanging at "Updating" because its 64-byte MTProto
    /// obfuscation nonce never reached the server.
    var handshakeCarriesInitialData: Bool {
        switch self {
        case .vless:
            return true
        case .hysteria, .trojan, .shadowsocks, .socks5, .http11, .http2, .http3:
            return false
        }
    }

    /// Whether the protocol can multiplex several logical streams inside one
    /// tunnel (Xray-compatible mux.cool, routed via ``MuxManager``). Only
    /// VLESS carries a mux-capable framing on the wire; every other protocol
    /// must reject a ``ProxyCommand/mux`` request at dispatch time.
    var supportsMux: Bool {
        self == .vless
    }

    var name: String {
        switch self {
        case .vless:
            "VLESS"
        case .hysteria:
            "Hysteria"
        case .trojan:
            "Trojan"
        case .shadowsocks:
            "Shadowsocks"
        case .socks5:
            "SOCKS5"
        case .http11:
            "HTTPS"
        case .http2:
            "HTTP/2"
        case .http3:
            "QUIC"
        }
    }
}

// MARK: - Outbound Protocol Configuration

/// Type-safe outbound protocol with associated credentials and settings.
/// Protocol-specific plumbing (VLESS transport/security/flow, Hysteria SNI,
/// etc.) lives on each case's associated values — outbounds that don't need
/// a given knob simply don't expose it.
enum Outbound: Hashable {
    /// VLESS is the only outbound with a user-selectable transport layer and
    /// TLS/Reality security layer, plus flow/mux/xudp knobs.
    case vless(
        uuid: UUID,
        encryption: String,
        flow: String?,
        transport: TransportLayer,
        security: SecurityLayer,
        muxEnabled: Bool,
        xudpEnabled: Bool
    )
    /// Hysteria2 runs over QUIC with its own internal TLS. The SNI is always
    /// populated — callers default it to the server address when there is no
    /// explicit override. `uploadMbps` is clamped to `HysteriaUploadMbpsRange`.
    case hysteria(password: String, uploadMbps: Int, sni: String)
    /// Trojan runs as a thin SHA224(password)+CRLF+request header layered on
    /// top of mandatory TLS. The TLS knobs (SNI/ALPN/fingerprint) live in the
    /// associated `TLSConfiguration`; there is no plaintext variant.
    case trojan(password: String, tls: TLSConfiguration)
    /// Shadowsocks runs over bare TCP with AEAD / 2022 wire encryption.
    case shadowsocks(password: String, method: String)
    /// SOCKS5 runs over bare TCP in the clear.
    case socks5(username: String?, password: String?)
    /// Naive over HTTP/1.1-over-TLS. TLS is managed internally by the Naive stack.
    case http11(username: String, password: String)
    /// Naive over HTTP/2-over-TLS.
    case http2(username: String, password: String)
    /// Naive over HTTP/3-over-QUIC.
    case http3(username: String, password: String)
}

/// Clamps any integer to the 1-100 Mbit/s range used by `.hysteria`.
/// Used at every construction boundary so the associated value is always
/// valid regardless of source (URL, dict, legacy Codable without the key).
func clampHysteriaUploadMbps(_ raw: Int) -> Int {
    max(HysteriaUploadMbpsRange.lowerBound, min(HysteriaUploadMbpsRange.upperBound, raw))
}
let HysteriaUploadMbpsRange: ClosedRange<Int> = 0...100
let HysteriaUploadMbpsDefault: Int = 20

// MARK: - Transport Layer Configuration

/// Type-safe transport layer (mutually exclusive).
/// Replaces the flat `transport` string + optional transport configs.
enum TransportLayer: Hashable {
    case tcp
    case ws(WebSocketConfiguration)
    case httpUpgrade(HTTPUpgradeConfiguration)
    case grpc(GRPCConfiguration)
    case xhttp(XHTTPConfiguration)
}

// MARK: - Security Layer Configuration

/// Type-safe security layer (mutually exclusive).
/// Replaces the flat `security` string + optional security configs.
enum SecurityLayer: Hashable {
    case none
    case tls(TLSConfiguration)
    case reality(RealityConfiguration)
}

// MARK: - ProxyConfiguration

/// Proxy configuration for all supported outbound protocols.
struct ProxyConfiguration: Identifiable, Hashable, Codable {
    let id: UUID
    let name: String
    let serverAddress: String
    let serverPort: UInt16
    /// Pre-resolved IP address for `serverAddress`. When set, socket connections and tunnel
    /// routing use this IP instead of the domain name to avoid DNS-over-tunnel routing loops.
    /// Populated at connect time by the app; `nil` when `serverAddress` is already an IP.
    let resolvedIP: String?
    /// The subscription this configuration belongs to, if any.
    let subscriptionId: UUID?
    /// Protocol-specific settings. All VLESS transport/security/flow/mux/xudp
    /// knobs and Hysteria's optional SNI live on the `Outbound` enum's
    /// associated values — read them via the computed accessors below.
    let outbound: Outbound
    /// Ordered list of proxy configurations to chain through before reaching this proxy's server.
    /// The first element is the outermost proxy (real TCP connection); the last tunnels to this proxy.
    /// `nil` or empty means a direct connection to the server.
    let chain: [ProxyConfiguration]?

    /// The pre-resolved IP if available, otherwise `serverAddress`.
    /// Used by opt-in first-hop dials (for example latency testing) and logging.
    var connectAddress: String { resolvedIP ?? serverAddress }

    // MARK: - VLESS-specific computed accessors
    //
    // These derive from the `.vless` case's associated values and return
    // harmless defaults for every other outbound. Callers that are ready
    // for a type-safe switch can pattern-match on `outbound` directly.

    /// Transport layer. Always `.tcp` for non-VLESS outbounds.
    var transportLayer: TransportLayer {
        if case .vless(_, _, _, let t, _, _, _) = outbound { return t }
        return .tcp
    }
    /// Security layer. Always `.none` for non-VLESS outbounds.
    var securityLayer: SecurityLayer {
        if case .vless(_, _, _, _, let s, _, _) = outbound { return s }
        return .none
    }
    /// Whether Mux is enabled. Only meaningful for VLESS+TCP with Vision flow.
    var muxEnabled: Bool {
        if case .vless(_, _, _, _, _, let m, _) = outbound { return m }
        return false
    }
    /// Whether XUDP (GlobalID-based flow identification) is enabled for muxed UDP.
    var xudpEnabled: Bool {
        if case .vless(_, _, _, _, _, _, let x) = outbound { return x }
        return false
    }

    init(
        id: UUID = UUID(),
        name: String,
        serverAddress: String,
        serverPort: UInt16,
        resolvedIP: String? = nil,
        subscriptionId: UUID? = nil,
        outbound: Outbound,
        chain: [ProxyConfiguration]? = nil
    ) {
        self.id = id
        self.name = name
        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.resolvedIP = resolvedIP
        self.subscriptionId = subscriptionId
        self.outbound = outbound
        self.chain = chain
    }

    /// Returns a copy with the given chain, preserving all other fields.
    func withChain(_ chain: [ProxyConfiguration]?) -> ProxyConfiguration {
        ProxyConfiguration(
            id: id, name: name, serverAddress: serverAddress, serverPort: serverPort,
            resolvedIP: resolvedIP, subscriptionId: subscriptionId,
            outbound: outbound, chain: chain
        )
    }

    /// Compares configuration content, ignoring `id`, `resolvedIP`, and `subscriptionId`.
    /// Used to detect unchanged configs during subscription updates.
    func contentEquals(_ other: ProxyConfiguration) -> Bool {
        name == other.name &&
        serverAddress == other.serverAddress &&
        serverPort == other.serverPort &&
        outbound == other.outbound &&
        chain == other.chain
    }

    // MARK: - Backward-Compatible Codable

    private enum CodingKeys: String, CodingKey {
        case id, name, serverAddress, serverPort, resolvedIP, subscriptionId
        case outboundProtocol, uuid, encryption, flow
        case transport, websocket, httpUpgrade, grpc, xhttp
        case security, tls, reality
        case muxEnabled, xudpEnabled
        case hysteriaPassword, hysteriaUploadMbps, hysteriaSNI
        case trojanPassword, trojanTLS
        case ssPassword, ssMethod
        case socks5Username, socks5Password
        case http11Username, http11Password
        case http2Username, http2Password
        case http3Username, http3Password
        case chain
    }

    /// Custom decoder. Legacy on-disk JSON stored transport/security/mux/xudp
    /// at the top level; we now fold those into the `.vless` case and
    /// Hysteria's SNI into `.hysteria`, discarding any fields that appear on
    /// outbounds that no longer support them (Shadowsocks/SOCKS5 TLS, etc.).
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        serverAddress = try container.decode(String.self, forKey: .serverAddress)
        serverPort = try container.decode(UInt16.self, forKey: .serverPort)
        resolvedIP = try container.decodeIfPresent(String.self, forKey: .resolvedIP)
        subscriptionId = try container.decodeIfPresent(UUID.self, forKey: .subscriptionId)

        let proto = try container.decodeIfPresent(OutboundProtocol.self, forKey: .outboundProtocol) ?? .vless

        switch proto {
        case .vless:
            // Transport layer
            let transportStr = try container.decodeIfPresent(String.self, forKey: .transport) ?? "tcp"
            let transport: TransportLayer
            switch transportStr {
            case "ws":
                transport = (try container.decodeIfPresent(WebSocketConfiguration.self, forKey: .websocket)).map { .ws($0) } ?? .tcp
            case "httpupgrade":
                transport = (try container.decodeIfPresent(HTTPUpgradeConfiguration.self, forKey: .httpUpgrade)).map { .httpUpgrade($0) } ?? .tcp
            case "grpc":
                transport = (try container.decodeIfPresent(GRPCConfiguration.self, forKey: .grpc)).map { .grpc($0) } ?? .tcp
            case "xhttp":
                transport = (try container.decodeIfPresent(XHTTPConfiguration.self, forKey: .xhttp)).map { .xhttp($0) } ?? .tcp
            default:
                transport = .tcp
            }
            // Security layer
            let securityStr = try container.decodeIfPresent(String.self, forKey: .security) ?? "none"
            let security: SecurityLayer
            switch securityStr {
            case "tls":
                security = (try container.decodeIfPresent(TLSConfiguration.self, forKey: .tls)).map { .tls($0) } ?? .none
            case "reality":
                security = (try container.decodeIfPresent(RealityConfiguration.self, forKey: .reality)).map { .reality($0) } ?? .none
            default:
                security = .none
            }
            outbound = .vless(
                uuid: try container.decode(UUID.self, forKey: .uuid),
                encryption: try container.decode(String.self, forKey: .encryption),
                flow: try container.decodeIfPresent(String.self, forKey: .flow),
                transport: transport,
                security: security,
                muxEnabled: try container.decodeIfPresent(Bool.self, forKey: .muxEnabled) ?? true,
                xudpEnabled: try container.decodeIfPresent(Bool.self, forKey: .xudpEnabled) ?? true
            )

        case .hysteria:
            // Older builds stashed SNI inside a top-level TLSConfiguration
            // blob; read from either the dedicated key or the legacy blob,
            // and fall back to `serverAddress` so the SNI is always populated.
            let legacySNI: String? = {
                guard let legacyTLS = try? container.decodeIfPresent(TLSConfiguration.self, forKey: .tls) else { return nil }
                return legacyTLS.serverName
            }()
            let explicitSNI = try container.decodeIfPresent(String.self, forKey: .hysteriaSNI) ?? legacySNI
            let raw = try container.decodeIfPresent(Int.self, forKey: .hysteriaUploadMbps)
                ?? HysteriaUploadMbpsDefault
            outbound = .hysteria(
                password: try container.decodeIfPresent(String.self, forKey: .hysteriaPassword) ?? "",
                uploadMbps: clampHysteriaUploadMbps(raw),
                sni: (explicitSNI?.isEmpty == false ? explicitSNI! : serverAddress)
            )

        case .trojan:
            let password = try container.decodeIfPresent(String.self, forKey: .trojanPassword) ?? ""
            // Trojan TLS is mandatory; fall back to an SNI=serverAddress default
            // so legacy/partial configs still decode to a usable outbound.
            let trojanTLS = try container.decodeIfPresent(TLSConfiguration.self, forKey: .trojanTLS)
            let legacyTLS = try container.decodeIfPresent(TLSConfiguration.self, forKey: .tls)
            let tls = trojanTLS ?? legacyTLS ?? TLSConfiguration(serverName: serverAddress)
            outbound = .trojan(password: password, tls: tls)

        case .shadowsocks:
            outbound = .shadowsocks(
                password: try container.decodeIfPresent(String.self, forKey: .ssPassword) ?? "",
                method: try container.decodeIfPresent(String.self, forKey: .ssMethod) ?? ""
            )
        case .socks5:
            outbound = .socks5(
                username: try container.decodeIfPresent(String.self, forKey: .socks5Username),
                password: try container.decodeIfPresent(String.self, forKey: .socks5Password)
            )
        case .http11:
            outbound = .http11(
                username: try container.decodeIfPresent(String.self, forKey: .http11Username) ?? "",
                password: try container.decodeIfPresent(String.self, forKey: .http11Password) ?? ""
            )
        case .http2:
            outbound = .http2(
                username: try container.decodeIfPresent(String.self, forKey: .http2Username) ?? "",
                password: try container.decodeIfPresent(String.self, forKey: .http2Password) ?? ""
            )
        case .http3:
            outbound = .http3(
                username: try container.decodeIfPresent(String.self, forKey: .http3Username) ?? "",
                password: try container.decodeIfPresent(String.self, forKey: .http3Password) ?? ""
            )
        }

        chain = try container.decodeIfPresent([ProxyConfiguration].self, forKey: .chain)
    }

    /// Custom encoder that flattens enums back to legacy JSON keys for backward compatibility.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(serverAddress, forKey: .serverAddress)
        try container.encode(serverPort, forKey: .serverPort)
        try container.encodeIfPresent(resolvedIP, forKey: .resolvedIP)
        try container.encodeIfPresent(subscriptionId, forKey: .subscriptionId)

        // Flatten outbound back to the legacy JSON schema. VLESS carries
        // its own transport/security/mux/xudp associated values;
        // Hysteria carries an optional SNI; every other outbound writes
        // only its protocol-specific credential fields.
        try container.encode(outboundProtocol, forKey: .outboundProtocol)
        switch outbound {
        case .vless(let uuid, let encryption, let flow, let transport, let security, let muxEnabled, let xudpEnabled):
            try container.encode(uuid, forKey: .uuid)
            try container.encode(encryption, forKey: .encryption)
            try container.encodeIfPresent(flow, forKey: .flow)

            try container.encode(transportString(for: transport), forKey: .transport)
            switch transport {
            case .tcp: break
            case .ws(let config): try container.encode(config, forKey: .websocket)
            case .httpUpgrade(let config): try container.encode(config, forKey: .httpUpgrade)
            case .grpc(let config): try container.encode(config, forKey: .grpc)
            case .xhttp(let config): try container.encode(config, forKey: .xhttp)
            }

            try container.encode(securityString(for: security), forKey: .security)
            switch security {
            case .none: break
            case .tls(let config): try container.encode(config, forKey: .tls)
            case .reality(let config): try container.encode(config, forKey: .reality)
            }

            try container.encode(muxEnabled, forKey: .muxEnabled)
            try container.encode(xudpEnabled, forKey: .xudpEnabled)

        case .hysteria(let password, let uploadMbps, let sni):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .hysteriaPassword)
            try container.encode(uploadMbps, forKey: .hysteriaUploadMbps)
            try container.encode(sni, forKey: .hysteriaSNI)
        case .trojan(let password, let tls):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .trojanPassword)
            try container.encode(tls, forKey: .trojanTLS)
        case .shadowsocks(let password, let method):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .ssPassword)
            try container.encode(method, forKey: .ssMethod)
        case .socks5(let username, let password):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encodeIfPresent(username, forKey: .socks5Username)
            try container.encodeIfPresent(password, forKey: .socks5Password)
        case .http11(let username, let password):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(username, forKey: .http11Username)
            try container.encode(password, forKey: .http11Password)
        case .http2(let username, let password):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(username, forKey: .http2Username)
            try container.encode(password, forKey: .http2Password)
        case .http3(let username, let password):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(username, forKey: .http3Username)
            try container.encode(password, forKey: .http3Password)
        }

        try container.encodeIfPresent(chain, forKey: .chain)
    }

    // Serialize a transport/security layer to the legacy string tag used in
    // URL query params and the flat JSON schema.
    private func transportString(for layer: TransportLayer) -> String {
        switch layer {
        case .tcp:          "tcp"
        case .ws:           "ws"
        case .httpUpgrade:  "httpupgrade"
        case .grpc:         "grpc"
        case .xhttp:        "xhttp"
        }
    }
    private func securityString(for layer: SecurityLayer) -> String {
        switch layer {
        case .none:     "none"
        case .tls:      "tls"
        case .reality:  "reality"
        }
    }
}

// MARK: - Compatibility Bridges
//
// Computed properties that expose the old flat-field API. Consumers that only
// *read* individual fields can continue to use these without changes.

extension ProxyConfiguration {

    /// Protocol type discriminator.
    var outboundProtocol: OutboundProtocol {
        switch outbound {
        case .vless:        .vless
        case .hysteria:     .hysteria
        case .trojan:       .trojan
        case .shadowsocks:  .shadowsocks
        case .socks5:       .socks5
        case .http11:       .http11
        case .http2:        .http2
        case .http3:        .http3
        }
    }

    /// VLESS UUID (returns `id` as stable fallback for non-VLESS protocols).
    var uuid: UUID {
        if case .vless(let uuid, _, _, _, _, _, _) = outbound { return uuid }
        return id
    }

    /// Encryption type (always `"none"` for non-VLESS).
    var encryption: String {
        if case .vless(_, let encryption, _, _, _, _, _) = outbound { return encryption }
        return "none"
    }

    /// VLESS flow (e.g. `"xtls-rprx-vision"`). `nil` for non-VLESS.
    var flow: String? {
        if case .vless(_, _, let flow, _, _, _, _) = outbound { return flow }
        return nil
    }

    /// Hysteria password. `nil` for non-Hysteria.
    var hysteriaPassword: String? {
        if case .hysteria(let password, _, _) = outbound { return password }
        return nil
    }

    /// Client's declared upload bandwidth (Mbit/s) for Hysteria Brutal CC.
    /// `nil` for non-Hysteria.
    var hysteriaUploadMbps: Int? {
        if case .hysteria(_, let mbps, _) = outbound { return mbps }
        return nil
    }

    /// SNI sent on the wire for Hysteria's internal TLS handshake.
    /// Always populated for Hysteria (defaults to `serverAddress`); `nil`
    /// for non-Hysteria outbounds.
    var hysteriaSNI: String? {
        if case .hysteria(_, _, let sni) = outbound { return sni }
        return nil
    }

    /// Trojan password. `nil` for non-Trojan.
    var trojanPassword: String? {
        if case .trojan(let password, _) = outbound { return password }
        return nil
    }

    /// Trojan's mandatory TLS configuration. `nil` for non-Trojan.
    var trojanTLS: TLSConfiguration? {
        if case .trojan(_, let tls) = outbound { return tls }
        return nil
    }

    /// Shadowsocks password. `nil` for non-Shadowsocks.
    var ssPassword: String? {
        if case .shadowsocks(let password, _) = outbound { return password }
        return nil
    }

    /// Shadowsocks method. `nil` for non-Shadowsocks.
    var ssMethod: String? {
        if case .shadowsocks(_, let method) = outbound { return method }
        return nil
    }

    /// SOCKS5 username. `nil` for non-SOCKS5.
    var socks5Username: String? {
        if case .socks5(let username, _) = outbound { return username }
        return nil
    }

    /// SOCKS5 password. `nil` for non-SOCKS5.
    var socks5Password: String? {
        if case .socks5(_, let password) = outbound { return password }
        return nil
    }

    /// Username for the active protocol, or `nil` if not applicable.
    var activeUsername: String? {
        switch outbound {
        case .socks5(let u, _): u
        case .http11(let u, _): u
        case .http2(let u, _):  u
        case .http3(let u, _):  u
        default: nil
        }
    }

    /// Password for the active protocol, or `nil` if not applicable.
    var activePassword: String? {
        switch outbound {
        case .socks5(_, let p): p
        case .http11(_, let p): p
        case .http2(_, let p):  p
        case .http3(_, let p):  p
        default: nil
        }
    }

    /// Transport type string.
    var transport: String {
        switch transportLayer {
        case .tcp:          "tcp"
        case .ws:           "ws"
        case .httpUpgrade:  "httpupgrade"
        case .grpc:         "grpc"
        case .xhttp:        "xhttp"
        }
    }

    /// Security type string.
    var security: String {
        switch securityLayer {
        case .none:     "none"
        case .tls:      "tls"
        case .reality:  "reality"
        }
    }

    /// TLS configuration, if active.
    var tls: TLSConfiguration? {
        if case .tls(let config) = securityLayer { return config }
        return nil
    }

    /// Reality configuration, if active.
    var reality: RealityConfiguration? {
        if case .reality(let config) = securityLayer { return config }
        return nil
    }

    /// WebSocket configuration, if active.
    var websocket: WebSocketConfiguration? {
        if case .ws(let config) = transportLayer { return config }
        return nil
    }

    /// HTTP upgrade configuration, if active.
    var httpUpgrade: HTTPUpgradeConfiguration? {
        if case .httpUpgrade(let config) = transportLayer { return config }
        return nil
    }
    
    /// gRPC configuration, if active.
    var grpc: GRPCConfiguration? {
        if case .grpc(let config) = transportLayer { return config }
        return nil
    }

    /// XHTTP configuration, if active.
    var xhttp: XHTTPConfiguration? {
        if case .xhttp(let config) = transportLayer { return config }
        return nil
    }
}

enum ProxyError: Error, LocalizedError {
    case invalidURL(String)
    case connectionFailed(String)
    case protocolError(String)
    case invalidResponse(String)
    case dropped

    var errorDescription: String? {
        switch self {
        case .invalidURL(let message):
            return "Invalid URL: \(message)"
        case .connectionFailed(let message):
            return "Connection failed: \(message)"
        case .protocolError(let message):
            return "Protocol error: \(message)"
        case .invalidResponse(let message):
            return "Invalid response: \(message)"
        case .dropped:
            return nil
        }
    }
}
