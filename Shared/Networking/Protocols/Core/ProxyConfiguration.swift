//
//  ProxyConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

/// Outbound protocol type.
enum OutboundProtocol: String, Codable {
    case vless
    case hysteria
    case nowhere
    case trojan
    case anytls
    case shadowsocks
    case socks5
    case sudoku
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
    /// ``TCPConnection`` checks this to decide whether to hand `pendingData`
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
        case .sudoku:
            return true
        case .hysteria, .nowhere, .trojan, .anytls, .shadowsocks, .socks5, .http11, .http2, .http3:
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

    /// Transport this protocol needs from the chain hop below it to service
    /// `downstreamCommand`. `nil` when the protocol can't carry the command.
    func upstreamCommand(for downstreamCommand: ProxyCommand) -> ProxyCommand? {
        switch self {
        case .vless, .trojan, .anytls:
            return .tcp
        case .shadowsocks:
            return downstreamCommand == .udp ? .udp : .tcp
        case .socks5:
            // The UDP-ASSOCIATE relay socket is opened separately
            // (see `openSOCKS5UDPRelay`); the link below only carries
            // the TCP control channel.
            return .tcp
        case .hysteria, .nowhere:
            return .udp
        case .sudoku, .http11, .http2, .http3:
            return downstreamCommand == .tcp ? .tcp : nil
        }
    }

    var name: String {
        switch self {
        case .vless:
            "VLESS"
        case .hysteria:
            "Hysteria"
        case .nowhere:
            "Nowhere"
        case .trojan:
            "Trojan"
        case .anytls:
            "AnyTLS"
        case .shadowsocks:
            "Shadowsocks"
        case .socks5:
            "SOCKS5"
        case .sudoku:
            "Sudoku"
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
    /// explicit override. `uploadMbps` / `downloadMbps` are clamped to their
    /// ranges and only take effect when `congestionControl` is `.brutal`.
    case hysteria(
        password: String,
        congestionControl: HysteriaCongestionControl,
        uploadMbps: Int,
        downloadMbps: Int,
        sni: String
    )
    /// Nowhere runs over QUIC with a shared-key auth frame.
    case nowhere(key: String)
    /// Trojan runs as a thin SHA224(password)+CRLF+request header layered on
    /// top of mandatory TLS. The TLS knobs (SNI/ALPN/fingerprint) live in the
    /// associated `TLSConfiguration`; there is no plaintext variant.
    case trojan(password: String, tls: TLSConfiguration)
    /// AnyTLS multiplexes streams over one TLS connection per pooled session,
    /// authenticating with SHA256(password) and obfuscating with a server-driven
    /// padding scheme. `idleCheckInterval` / `idleTimeout` (seconds) and
    /// `minIdleSession` tune the warm-pool behaviour; mirrors sing-anytls's
    /// `ClientConfig` knobs and clamps to the same minimums (≥30s/≥30s/≥0).
    case anytls(
        password: String,
        idleCheckInterval: Int,
        idleTimeout: Int,
        minIdleSession: Int,
        tls: TLSConfiguration
    )
    /// Shadowsocks runs over bare TCP with AEAD / 2022 wire encryption.
    case shadowsocks(password: String, method: String)
    /// SOCKS5 runs over bare TCP in the clear.
    case socks5(username: String?, password: String?)
    /// Sudoku runs over TCP with protocol-native obfuscation, KIP, and optional HTTPMask tunneling.
    case sudoku(SudokuConfiguration)
    /// Naive over HTTP/1.1-over-TLS. TLS is managed internally by the Naive stack.
    case http11(username: String, password: String)
    /// Naive over HTTP/2-over-TLS.
    case http2(username: String, password: String)
    /// Naive over HTTP/3-over-QUIC.
    case http3(username: String, password: String)
}

// MARK: - Transport Layer Configuration

/// Type-safe transport layer (mutually exclusive).
/// Replaces the flat `transport` string + optional transport configs.
enum TransportLayer: Hashable {
    case tcp
    case ws(WebSocketConfiguration)
    case httpUpgrade(HTTPUpgradeConfiguration)
    case grpc(GRPCConfiguration)
    case xhttp(XHTTPConfiguration)

    /// Wire tag used in the flat JSON schema and `vless://` query params.
    var tag: String {
        switch self {
        case .tcp:          "tcp"
        case .ws:           "ws"
        case .httpUpgrade:  "httpupgrade"
        case .grpc:         "grpc"
        case .xhttp:        "xhttp"
        }
    }
}

// MARK: - Security Layer Configuration

/// Type-safe security layer (mutually exclusive).
/// Replaces the flat `security` string + optional security configs.
enum SecurityLayer: Hashable {
    case none
    case tls(TLSConfiguration)
    case reality(RealityConfiguration)

    /// Wire tag used in the flat JSON schema and `vless://` query params.
    var tag: String {
        switch self {
        case .none:     "none"
        case .tls:      "tls"
        case .reality:  "reality"
        }
    }
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

    /// Protocol discriminator derived from `outbound`. Use this for type
    /// checks and to reach ``OutboundProtocol``'s behaviour (`isNaive`,
    /// `supportsMux`, …); pattern-match on `outbound` for the payload.
    var outboundProtocol: OutboundProtocol {
        switch outbound {
        case .vless:        .vless
        case .hysteria:     .hysteria
        case .nowhere:      .nowhere
        case .trojan:       .trojan
        case .anytls:       .anytls
        case .shadowsocks:  .shadowsocks
        case .socks5:       .socks5
        case .sudoku:       .sudoku
        case .http11:       .http11
        case .http2:        .http2
        case .http3:        .http3
        }
    }

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

    /// Whether this configuration is VLESS-over-XHTTP negotiating HTTP/3.
    ///
    /// XHTTP selects HTTP/3 when TLS advertises exactly one ALPN of `h3`
    /// (mirrors Xray-core's `decideHTTPVersion` and ``ProxyClient``'s
    /// `decideXHTTPHTTPVersion`). Unlike XHTTP over HTTP/1.1 or HTTP/2 — which
    /// ride a TCP stream — HTTP/3 runs over QUIC (UDP), so a chain hop below it
    /// must provide a `.udp` relay, exactly like Hysteria and Nowhere. Reality
    /// (always HTTP/2) and the plaintext path (HTTP/1.1) are never h3.
    var isXHTTPOverHTTP3: Bool {
        guard case .xhttp = transportLayer else { return false }
        guard case .tls(let tls) = securityLayer else { return false }
        let alpn = tls.alpn ?? []
        return alpn.count == 1 && alpn[0].caseInsensitiveCompare("h3") == .orderedSame
    }

    /// Transport this configuration needs from the chain hop below it to
    /// service `downstreamCommand`. A transport-aware superset of
    /// ``OutboundProtocol/upstreamCommand(for:)``: XHTTP-over-HTTP/3 rides QUIC,
    /// so it always needs a `.udp` relay regardless of the command it carries
    /// onward; every other configuration defers to the protocol-level rule.
    func upstreamCommand(for downstreamCommand: ProxyCommand) -> ProxyCommand? {
        if isXHTTPOverHTTP3 { return .udp }
        return outboundProtocol.upstreamCommand(for: downstreamCommand)
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

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case id, name, serverAddress, serverPort, resolvedIP, subscriptionId
        case outboundProtocol, uuid, encryption, flow
        case transport, websocket, httpUpgrade, grpc, xhttp
        case security, tls, reality
        case muxEnabled, xudpEnabled
        case hysteriaPassword, hysteriaCongestionControl, hysteriaUploadMbps, hysteriaDownloadMbps, hysteriaSNI
        case nowhereKey
        case trojanPassword, trojanTLS
        case anytlsPassword, anytlsIdleCheckInterval, anytlsIdleTimeout, anytlsMinIdleSession, anytlsTLS
        case ssPassword, ssMethod
        case socks5Username, socks5Password
        case sudoku
        case http11Username, http11Password
        case http2Username, http2Password
        case http3Username, http3Password
        case chain
    }

    /// Custom decoder. The on-disk JSON keeps transport/security/mux/xudp at
    /// the top level; we fold those into the `.vless` case's associated values
    /// and read every other outbound's settings from its own keys.
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
            // Absent congestion-control / cap keys default to Brutal uplink
            // with a server-driven downlink. SNI falls back to `serverAddress`
            // so it is always populated.
            let cc = try container.decodeIfPresent(HysteriaCongestionControl.self, forKey: .hysteriaCongestionControl) ?? .brutal
            let rawUp = try container.decodeIfPresent(Int.self, forKey: .hysteriaUploadMbps)
                ?? HysteriaCongestionControl.uploadMbpsDefault
            let rawDown = try container.decodeIfPresent(Int.self, forKey: .hysteriaDownloadMbps) ?? 0
            let explicitSNI = try container.decodeIfPresent(String.self, forKey: .hysteriaSNI)
            outbound = .hysteria(
                password: try container.decodeIfPresent(String.self, forKey: .hysteriaPassword) ?? "",
                congestionControl: cc,
                uploadMbps: HysteriaCongestionControl.clampUploadMbps(rawUp),
                downloadMbps: HysteriaCongestionControl.clampDownloadMbps(rawDown),
                sni: (explicitSNI?.isEmpty == false ? explicitSNI! : serverAddress)
            )

        case .nowhere:
            outbound = .nowhere(
                key: try container.decodeIfPresent(String.self, forKey: .nowhereKey) ?? ""
            )

        case .trojan:
            let password = try container.decodeIfPresent(String.self, forKey: .trojanPassword) ?? ""
            // Trojan TLS is mandatory; fall back to an SNI=serverAddress default
            // so partial configs still decode to a usable outbound.
            let tls = try container.decodeIfPresent(TLSConfiguration.self, forKey: .trojanTLS)
                ?? TLSConfiguration(serverName: serverAddress)
            outbound = .trojan(password: password, tls: tls)

        case .anytls:
            let password = try container.decodeIfPresent(String.self, forKey: .anytlsPassword) ?? ""
            // sing-anytls clamps to ≥30s/≥30s/≥0; we store the raw value and
            // let `AnyTLSClient` clamp at use time so the JSON round-trips.
            let ici = try container.decodeIfPresent(Int.self, forKey: .anytlsIdleCheckInterval) ?? 30
            let it  = try container.decodeIfPresent(Int.self, forKey: .anytlsIdleTimeout) ?? 30
            let mis = try container.decodeIfPresent(Int.self, forKey: .anytlsMinIdleSession) ?? 0
            let tls = try container.decodeIfPresent(TLSConfiguration.self, forKey: .anytlsTLS)
                ?? TLSConfiguration(serverName: serverAddress)
            outbound = .anytls(
                password: password,
                idleCheckInterval: ici,
                idleTimeout: it,
                minIdleSession: mis,
                tls: tls
            )

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
        case .sudoku:
            outbound = .sudoku(try container.decode(SudokuConfiguration.self, forKey: .sudoku))
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

    /// Custom encoder that flattens the `Outbound` enum to the flat JSON schema.
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

            try container.encode(transport.tag, forKey: .transport)
            switch transport {
            case .tcp: break
            case .ws(let config): try container.encode(config, forKey: .websocket)
            case .httpUpgrade(let config): try container.encode(config, forKey: .httpUpgrade)
            case .grpc(let config): try container.encode(config, forKey: .grpc)
            case .xhttp(let config): try container.encode(config, forKey: .xhttp)
            }

            try container.encode(security.tag, forKey: .security)
            switch security {
            case .none: break
            case .tls(let config): try container.encode(config, forKey: .tls)
            case .reality(let config): try container.encode(config, forKey: .reality)
            }

            try container.encode(muxEnabled, forKey: .muxEnabled)
            try container.encode(xudpEnabled, forKey: .xudpEnabled)

        case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let sni):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .hysteriaPassword)
            try container.encode(congestionControl, forKey: .hysteriaCongestionControl)
            try container.encode(uploadMbps, forKey: .hysteriaUploadMbps)
            try container.encode(downloadMbps, forKey: .hysteriaDownloadMbps)
            try container.encode(sni, forKey: .hysteriaSNI)
        case .nowhere(let key):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(key, forKey: .nowhereKey)
        case .trojan(let password, let tls):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .trojanPassword)
            try container.encode(tls, forKey: .trojanTLS)
        case .anytls(let password, let ici, let it, let mis, let tls):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .anytlsPassword)
            try container.encode(ici, forKey: .anytlsIdleCheckInterval)
            try container.encode(it, forKey: .anytlsIdleTimeout)
            try container.encode(mis, forKey: .anytlsMinIdleSession)
            try container.encode(tls, forKey: .anytlsTLS)
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
        case .sudoku(let configuration):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(configuration, forKey: .sudoku)
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
