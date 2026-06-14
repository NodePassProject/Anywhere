//
//  ProxyConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

enum OutboundProtocol: String, Codable, CaseIterable {
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

    /// Whether the handshake has a payload slot for the caller's first bytes; when `false`
    /// they must be sent separately after the tunnel is up or the opening payload is dropped.
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

    /// Whether the protocol supports mux.cool multiplexing (VLESS only).
    var supportsMux: Bool {
        self == .vless
    }

    /// Transport needed from the chain hop below to service `downstreamCommand`;
    /// `nil` when the protocol can't carry the command.
    func upstreamCommand(for downstreamCommand: ProxyCommand) -> ProxyCommand? {
        switch self {
        case .vless, .trojan, .anytls:
            return .tcp
        case .shadowsocks:
            return downstreamCommand == .udp ? .udp : .tcp
        case .socks5:
            // The UDP-ASSOCIATE relay is opened separately; the link below
            // only carries the TCP control channel.
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
enum Outbound: Hashable {
    /// The only outbound with a user-selectable transport and TLS/Reality security layer.
    case vless(
        uuid: UUID,
        encryption: String,
        flow: String?,
        transport: TransportLayer,
        security: SecurityLayer,
        muxEnabled: Bool,
        xudpEnabled: Bool
    )
    /// Hysteria2 over QUIC. SNI is always populated; the Mbps values are clamped
    /// and only take effect with `.brutal` congestion control. `portHopping` is `nil`
    /// for a fixed single port.
    case hysteria(
        password: String,
        congestionControl: HysteriaCongestionControl,
        uploadMbps: Int,
        downloadMbps: Int,
        portHopping: HysteriaPortHopping?,
        sni: String
    )
    /// Nowhere runs over QUIC with a shared-key auth frame and spec-shaped TLS ALPN.
    case nowhere(key: String, spec: String?, tls: TLSConfiguration)
    /// Trojan: SHA224(password)+CRLF+request over mandatory TLS. No plaintext variant.
    case trojan(password: String, tls: TLSConfiguration)
    /// AnyTLS: stream multiplexer over pooled TLS sessions, authenticated with SHA256(password);
    /// `idleCheckInterval`/`idleTimeout` (seconds) and `minIdleSession` tune the warm pool.
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

    /// SNI / server name carried by this layer; `fallback` when unsecured.
    func serverName(fallback: String) -> String {
        switch self {
        case .tls(let tls): return tls.serverName
        case .reality(let reality): return reality.serverName
        case .none: return fallback
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
    /// Pre-resolved IP used instead of `serverAddress` to avoid DNS-over-tunnel routing loops;
    /// populated at connect time, `nil` when the address is already an IP.
    let resolvedIP: String?
    let subscriptionId: UUID?
    let outbound: Outbound
    /// Proxies to chain through, outermost first; `nil` or empty means a direct connection.
    let chain: [ProxyConfiguration]?
    var deletedAt: Date? = nil

    /// The pre-resolved IP if available, otherwise `serverAddress`.
    var connectAddress: String { resolvedIP ?? serverAddress }

    /// Protocol discriminator. Use for type checks; pattern-match on `outbound` for payload.
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

    /// Whether Vision-flow mux applies: VLESS with `xtls-rprx-vision` flow and Mux enabled.
    var usesVisionMux: Bool {
        guard case .vless(_, _, let flow, _, _, let muxEnabled, _) = outbound else { return false }
        return muxEnabled && flow == "xtls-rprx-vision"
    }

    /// Uppercased transport tag for display (VLESS only); `nil` when not VLESS or the tag is empty.
    var displayTransportTag: String? {
        guard outboundProtocol == .vless else { return nil }
        let tag = transportLayer.tag
        return tag.isEmpty ? nil : tag.uppercased()
    }

    /// Uppercased security tag for display; `nil` when there is no security layer.
    var displaySecurityTag: String? {
        let tag = securityLayer.tag.uppercased()
        return tag == "NONE" ? nil : tag
    }

    /// Whether the VLESS flow is an XTLS Vision variant (loose match, e.g. `xtls-rprx-vision-udp443`).
    var hasVisionFlow: Bool {
        if case .vless(_, _, let flow?, _, _, _, _) = outbound {
            return flow.uppercased().contains("VISION")
        }
        return false
    }

    /// Whether this configuration is VLESS-over-XHTTP negotiating HTTP/3.
    var isXHTTPOverHTTP3: Bool {
        guard case .xhttp = transportLayer else { return false }
        guard case .tls(let tls) = securityLayer else { return false }
        let alpn = tls.alpn ?? []
        return alpn.count == 1 && alpn[0].caseInsensitiveCompare("h3") == .orderedSame
    }

    /// XHTTP-over-HTTP/3 always needs `.udp` (rides QUIC); otherwise defers to the protocol rule.
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

    func withChain(_ chain: [ProxyConfiguration]?) -> ProxyConfiguration {
        ProxyConfiguration(
            id: id, name: name, serverAddress: serverAddress, serverPort: serverPort,
            resolvedIP: resolvedIP, subscriptionId: subscriptionId,
            outbound: outbound, chain: chain
        )
    }

    /// Compares content ignoring `id`, `resolvedIP`, and `subscriptionId`,
    /// to detect unchanged configs during subscription updates.
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
        case hysteriaPorts, hysteriaHopInterval
        case nowhereKey, nowhereSpec, nowhereSNI, nowhereALPN, nowhereTLS
        case trojanPassword, trojanTLS
        case anytlsPassword, anytlsIdleCheckInterval, anytlsIdleTimeout, anytlsMinIdleSession, anytlsTLS
        case ssPassword, ssMethod
        case socks5Username, socks5Password
        case sudoku
        case http11Username, http11Password
        case http2Username, http2Password
        case http3Username, http3Password
        case chain
        case deletedAt
    }

    /// Folds the flat JSON transport/security/mux/xudp keys into `.vless` associated values.
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
            // Absent keys default to Brutal with server-driven downlink; SNI falls
            // back to serverAddress so it is always populated.
            let cc = try container.decodeIfPresent(HysteriaCongestionControl.self, forKey: .hysteriaCongestionControl) ?? .brutal
            let rawUp = try container.decodeIfPresent(Int.self, forKey: .hysteriaUploadMbps)
                ?? HysteriaCongestionControl.uploadMbpsDefault
            let rawDown = try container.decodeIfPresent(Int.self, forKey: .hysteriaDownloadMbps) ?? 0
            let explicitSNI = try container.decodeIfPresent(String.self, forKey: .hysteriaSNI)
            let portsSpec = try container.decodeIfPresent(String.self, forKey: .hysteriaPorts)
            let hopInterval = try container.decodeIfPresent(Int.self, forKey: .hysteriaHopInterval)
            outbound = .hysteria(
                password: try container.decodeIfPresent(String.self, forKey: .hysteriaPassword) ?? "",
                congestionControl: cc,
                uploadMbps: HysteriaCongestionControl.clampUploadMbps(rawUp),
                downloadMbps: HysteriaCongestionControl.clampDownloadMbps(rawDown),
                portHopping: HysteriaPortHopping.make(spec: portsSpec, intervalSeconds: hopInterval),
                sni: (explicitSNI?.isEmpty == false ? explicitSNI! : serverAddress)
            )

        case .nowhere:
            let legacyTLS = try container.decodeIfPresent(TLSConfiguration.self, forKey: .nowhereTLS)
            let explicitSNI = try container.decodeIfPresent(String.self, forKey: .nowhereSNI)
            let alpnString = try container.decodeIfPresent(String.self, forKey: .nowhereALPN)
            let alpn = alpnString.flatMap { $0.isEmpty ? nil : [$0] } ?? legacyTLS?.alpn
            outbound = .nowhere(
                key: try container.decodeIfPresent(String.self, forKey: .nowhereKey) ?? "",
                spec: try container.decodeIfPresent(String.self, forKey: .nowhereSpec),
                tls: TLSConfiguration(
                    serverName: (explicitSNI?.isEmpty == false ? explicitSNI : nil)
                        ?? legacyTLS?.serverName
                        ?? serverAddress,
                    alpn: alpn
                )
            )

        case .trojan:
            let password = try container.decodeIfPresent(String.self, forKey: .trojanPassword) ?? ""
            // TLS is mandatory; fall back to SNI=serverAddress so partial configs decode cleanly.
            let tls = try container.decodeIfPresent(TLSConfiguration.self, forKey: .trojanTLS)
                ?? TLSConfiguration(serverName: serverAddress)
            outbound = .trojan(password: password, tls: tls)

        case .anytls:
            let password = try container.decodeIfPresent(String.self, forKey: .anytlsPassword) ?? ""
            // Stored unclamped so the JSON round-trips exactly; AnyTLSClient clamps at use time.
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
        deletedAt = try container.decodeIfPresent(Date.self, forKey: .deletedAt)
    }

    /// Flattens `Outbound` to the flat JSON schema.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(serverAddress, forKey: .serverAddress)
        try container.encode(serverPort, forKey: .serverPort)
        try container.encodeIfPresent(resolvedIP, forKey: .resolvedIP)
        try container.encodeIfPresent(subscriptionId, forKey: .subscriptionId)

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

        case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let portHopping, let sni):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(password, forKey: .hysteriaPassword)
            try container.encode(congestionControl, forKey: .hysteriaCongestionControl)
            try container.encode(uploadMbps, forKey: .hysteriaUploadMbps)
            try container.encode(downloadMbps, forKey: .hysteriaDownloadMbps)
            if let portHopping {
                try container.encode(portHopping.portsSpec, forKey: .hysteriaPorts)
                try container.encode(portHopping.intervalSeconds, forKey: .hysteriaHopInterval)
            }
            try container.encode(sni, forKey: .hysteriaSNI)
        case .nowhere(let key, let spec, let tls):
            try container.encode(id, forKey: .uuid)
            try container.encode("none", forKey: .encryption)
            try container.encode(key, forKey: .nowhereKey)
            try container.encodeIfPresent(spec, forKey: .nowhereSpec)
            try container.encode(tls.serverName, forKey: .nowhereSNI)
            if let alpn = tls.alpn?.first, !alpn.isEmpty {
                try container.encode(alpn, forKey: .nowhereALPN)
            }
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
        try container.encodeIfPresent(deletedAt, forKey: .deletedAt)
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
