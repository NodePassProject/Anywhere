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
    case shadowsocks
    case http11
    case http2
    case http3

    /// Whether this protocol uses a CONNECT tunnel (HTTP/1.1, HTTP/2, or HTTP/3).
    var isNaive: Bool { self == .http11 || self == .http2 || self == .http3 }
    
    var name: String {
        switch self {
        case .vless:
            "VLESS"
        case .shadowsocks:
            "Shadowsocks"
        case .http11:
            "HTTPS"
        case .http2:
            "HTTP/2"
        case .http3:
            "QUIC"
        }
    }
}

/// Proxy configuration for VLESS and Shadowsocks outbound protocols.
struct ProxyConfiguration: Identifiable, Hashable, Codable {
    let id: UUID
    let name: String
    let serverAddress: String
    let serverPort: UInt16
    /// Pre-resolved IP address for `serverAddress`. When set, socket connections and tunnel
    /// routing use this IP instead of the domain name to avoid DNS-over-tunnel routing loops.
    /// Populated at connect time by the app; `nil` when `serverAddress` is already an IP.
    let resolvedIP: String?
    let uuid: UUID
    let encryption: String
    /// Transport type: `"tcp"` (default), `"ws"`, `"httpupgrade"`, or `"xhttp"`.
    let transport: String
    let flow: String?
    let security: String
    let tls: TLSConfiguration?
    let reality: RealityConfiguration?
    /// WebSocket configuration when `transport == "ws"`.
    let websocket: WebSocketConfiguration?
    /// HTTP upgrade configuration when `transport == "httpupgrade"`.
    let httpUpgrade: HTTPUpgradeConfiguration?
    /// XHTTP configuration when `transport == "xhttp"`.
    let xhttp: XHTTPConfiguration?
    /// Vision padding seed: `[contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]`.
    /// Default `[900, 500, 900, 256]` matches Xray-core.
    let testseed: [UInt32]
    /// Whether to multiplex UDP flows through the VLESS connection.
    /// Only effective when Vision flow is active. Default `true` matches Xray-core behavior.
    let muxEnabled: Bool
    /// Whether to use XUDP (GlobalID-based flow identification) for muxed UDP.
    /// Only effective when `muxEnabled` is `true`. Default `true` matches Xray-core behavior.
    let xudpEnabled: Bool
    /// The subscription this configuration belongs to, if any.
    let subscriptionId: UUID?

    /// The outbound protocol. Default `.vless`.
    let outboundProtocol: OutboundProtocol
    /// Shadowsocks password (only when `outboundProtocol == .shadowsocks`).
    let ssPassword: String?
    /// Shadowsocks method (e.g. "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305").
    let ssMethod: String?
    /// HTTP/1.1 CONNECT username (only when `outboundProtocol == .http11`).
    let http11Username: String?
    /// HTTP/1.1 CONNECT password (only when `outboundProtocol == .http11`).
    let http11Password: String?
    /// HTTP/2 CONNECT username (only when `outboundProtocol == .http2`).
    let http2Username: String?
    /// HTTP/2 CONNECT password (only when `outboundProtocol == .http2`).
    let http2Password: String?
    /// HTTP/3 CONNECT username (only when `outboundProtocol == .http3`).
    let http3Username: String?
    /// HTTP/3 CONNECT password (only when `outboundProtocol == .http3`).
    let http3Password: String?
    /// Ordered list of proxy configurations to chain through before reaching this proxy's server.
    /// The first element is the outermost proxy (real TCP connection); the last tunnels to this proxy.
    /// `nil` or empty means a direct connection to the server.
    let chain: [ProxyConfiguration]?

    /// The pre-resolved IP if available, otherwise `serverAddress`.
    /// Used for logging; actual connections resolve lazily via ``ProxyDNSCache``.
    var connectAddress: String { resolvedIP ?? serverAddress }

    /// Username for the active protocol, or `nil` if not applicable.
    var activeUsername: String? {
        switch outboundProtocol {
        case .http11: return http11Username
        case .http2:  return http2Username
        case .http3:  return http3Username
        default:      return nil
        }
    }

    /// Password for the active protocol, or `nil` if not applicable.
    var activePassword: String? {
        switch outboundProtocol {
        case .http11: return http11Password
        case .http2:  return http2Password
        case .http3:  return http3Password
        default:      return nil
        }
    }

    /// Compares configuration content, ignoring `id`, `resolvedIP`, and `subscriptionId`.
    /// Used to detect unchanged configs during subscription updates.
    func contentEquals(_ other: ProxyConfiguration) -> Bool {
        name == other.name &&
        serverAddress == other.serverAddress &&
        serverPort == other.serverPort &&
        uuid == other.uuid &&
        encryption == other.encryption &&
        transport == other.transport &&
        flow == other.flow &&
        security == other.security &&
        tls == other.tls &&
        reality == other.reality &&
        websocket == other.websocket &&
        httpUpgrade == other.httpUpgrade &&
        xhttp == other.xhttp &&
        testseed == other.testseed &&
        muxEnabled == other.muxEnabled &&
        xudpEnabled == other.xudpEnabled &&
        outboundProtocol == other.outboundProtocol &&
        ssPassword == other.ssPassword &&
        ssMethod == other.ssMethod &&
        http11Username == other.http11Username &&
        http11Password == other.http11Password &&
        http2Username == other.http2Username &&
        http2Password == other.http2Password &&
        http3Username == other.http3Username &&
        http3Password == other.http3Password &&
        chain == other.chain
    }

    init(id: UUID = UUID(), name: String, serverAddress: String, serverPort: UInt16, uuid: UUID, encryption: String, transport: String = "tcp", flow: String? = nil, security: String = "none", tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil, websocket: WebSocketConfiguration? = nil, httpUpgrade: HTTPUpgradeConfiguration? = nil, xhttp: XHTTPConfiguration? = nil, testseed: [UInt32]? = nil, muxEnabled: Bool = true, xudpEnabled: Bool = true, resolvedIP: String? = nil, subscriptionId: UUID? = nil, outboundProtocol: OutboundProtocol = .vless, ssPassword: String? = nil, ssMethod: String? = nil, http11Username: String? = nil, http11Password: String? = nil, http2Username: String? = nil, http2Password: String? = nil, http3Username: String? = nil, http3Password: String? = nil, chain: [ProxyConfiguration]? = nil) {
        self.id = id
        self.name = name
        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.resolvedIP = resolvedIP
        self.uuid = uuid
        self.encryption = encryption
        self.transport = transport
        self.flow = flow
        self.security = security
        self.tls = tls
        self.reality = reality
        self.websocket = websocket
        self.httpUpgrade = httpUpgrade
        self.xhttp = xhttp
        self.testseed = (testseed?.count ?? 0) >= 4 ? testseed! : [900, 500, 900, 256]
        self.muxEnabled = muxEnabled
        self.xudpEnabled = xudpEnabled
        self.subscriptionId = subscriptionId
        self.outboundProtocol = outboundProtocol
        self.ssPassword = ssPassword
        self.ssMethod = ssMethod
        self.http11Username = http11Username
        self.http11Password = http11Password
        self.http2Username = http2Username
        self.http2Password = http2Password
        self.http3Username = http3Username
        self.http3Password = http3Password
        self.chain = chain
    }

    /// Returns a copy with the given chain, preserving all other fields.
    func withChain(_ chain: [ProxyConfiguration]?) -> ProxyConfiguration {
        ProxyConfiguration(
            id: id, name: name, serverAddress: serverAddress, serverPort: serverPort,
            uuid: uuid, encryption: encryption, transport: transport, flow: flow,
            security: security, tls: tls, reality: reality, websocket: websocket,
            httpUpgrade: httpUpgrade, xhttp: xhttp, testseed: testseed,
            muxEnabled: muxEnabled, xudpEnabled: xudpEnabled, resolvedIP: resolvedIP,
            subscriptionId: subscriptionId, outboundProtocol: outboundProtocol,
            ssPassword: ssPassword, ssMethod: ssMethod,
            http11Username: http11Username, http11Password: http11Password,
            http2Username: http2Username, http2Password: http2Password,
            http3Username: http3Username, http3Password: http3Password,
            chain: chain
        )
    }

    /// Convenience initializer that defaults the name to `"Untitled"`.
    init(serverAddress: String, serverPort: UInt16, uuid: UUID, encryption: String, transport: String = "tcp", flow: String?, security: String = "none", tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil, websocket: WebSocketConfiguration? = nil, httpUpgrade: HTTPUpgradeConfiguration? = nil, xhttp: XHTTPConfiguration? = nil, testseed: [UInt32]? = nil, muxEnabled: Bool = true, xudpEnabled: Bool = true, resolvedIP: String? = nil, subscriptionId: UUID? = nil, outboundProtocol: OutboundProtocol = .vless, ssPassword: String? = nil, ssMethod: String? = nil, http11Username: String? = nil, http11Password: String? = nil, http2Username: String? = nil, http2Password: String? = nil, http3Username: String? = nil, http3Password: String? = nil, chain: [ProxyConfiguration]? = nil) {
        self.init(name: "Untitled", serverAddress: serverAddress, serverPort: serverPort, uuid: uuid, encryption: encryption, transport: transport, flow: flow, security: security, tls: tls, reality: reality, websocket: websocket, httpUpgrade: httpUpgrade, xhttp: xhttp, testseed: testseed, muxEnabled: muxEnabled, xudpEnabled: xudpEnabled, resolvedIP: resolvedIP, subscriptionId: subscriptionId, outboundProtocol: outboundProtocol, ssPassword: ssPassword, ssMethod: ssMethod, http11Username: http11Username, http11Password: http11Password, http2Username: http2Username, http2Password: http2Password, http3Username: http3Username, http3Password: http3Password, chain: chain)
    }

    /// Custom decoder for backward compatibility (old configs may lack newer fields like
    /// `xudpEnabled` or `resolvedIP`). Uses `decodeIfPresent` with sensible defaults.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        serverAddress = try container.decode(String.self, forKey: .serverAddress)
        serverPort = try container.decode(UInt16.self, forKey: .serverPort)
        resolvedIP = try container.decodeIfPresent(String.self, forKey: .resolvedIP)
        uuid = try container.decode(UUID.self, forKey: .uuid)
        encryption = try container.decode(String.self, forKey: .encryption)
        transport = try container.decode(String.self, forKey: .transport)
        flow = try container.decodeIfPresent(String.self, forKey: .flow)
        security = try container.decode(String.self, forKey: .security)
        tls = try container.decodeIfPresent(TLSConfiguration.self, forKey: .tls)
        reality = try container.decodeIfPresent(RealityConfiguration.self, forKey: .reality)
        websocket = try container.decodeIfPresent(WebSocketConfiguration.self, forKey: .websocket)
        httpUpgrade = try container.decodeIfPresent(HTTPUpgradeConfiguration.self, forKey: .httpUpgrade)
        xhttp = try container.decodeIfPresent(XHTTPConfiguration.self, forKey: .xhttp)
        let ts = try container.decodeIfPresent([UInt32].self, forKey: .testseed)
        testseed = (ts?.count ?? 0) >= 4 ? ts! : [900, 500, 900, 256]
        muxEnabled = try container.decodeIfPresent(Bool.self, forKey: .muxEnabled) ?? true
        xudpEnabled = try container.decodeIfPresent(Bool.self, forKey: .xudpEnabled) ?? true
        subscriptionId = try container.decodeIfPresent(UUID.self, forKey: .subscriptionId)
        outboundProtocol = try container.decodeIfPresent(OutboundProtocol.self, forKey: .outboundProtocol) ?? .vless
        ssPassword = try container.decodeIfPresent(String.self, forKey: .ssPassword)
        ssMethod = try container.decodeIfPresent(String.self, forKey: .ssMethod)
        http11Username = try container.decodeIfPresent(String.self, forKey: .http11Username)
        http11Password = try container.decodeIfPresent(String.self, forKey: .http11Password)
        http2Username = try container.decodeIfPresent(String.self, forKey: .http2Username)
        http2Password = try container.decodeIfPresent(String.self, forKey: .http2Password)
        http3Username = try container.decodeIfPresent(String.self, forKey: .http3Username)
        http3Password = try container.decodeIfPresent(String.self, forKey: .http3Password)
        chain = try container.decodeIfPresent([ProxyConfiguration].self, forKey: .chain)
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
