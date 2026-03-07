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

    /// The address to use for socket connections: the resolved IP if available, otherwise `serverAddress`.
    var connectAddress: String { resolvedIP ?? serverAddress }

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
        ssMethod == other.ssMethod
    }

    init(id: UUID = UUID(), name: String, serverAddress: String, serverPort: UInt16, uuid: UUID, encryption: String, transport: String = "tcp", flow: String? = nil, security: String = "none", tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil, websocket: WebSocketConfiguration? = nil, httpUpgrade: HTTPUpgradeConfiguration? = nil, xhttp: XHTTPConfiguration? = nil, testseed: [UInt32]? = nil, muxEnabled: Bool = true, xudpEnabled: Bool = true, resolvedIP: String? = nil, subscriptionId: UUID? = nil, outboundProtocol: OutboundProtocol = .vless, ssPassword: String? = nil, ssMethod: String? = nil) {
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
    }

    /// Convenience initializer that defaults the name to `"Untitled"`.
    init(serverAddress: String, serverPort: UInt16, uuid: UUID, encryption: String, transport: String = "tcp", flow: String?, security: String = "none", tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil, websocket: WebSocketConfiguration? = nil, httpUpgrade: HTTPUpgradeConfiguration? = nil, xhttp: XHTTPConfiguration? = nil, testseed: [UInt32]? = nil, muxEnabled: Bool = true, xudpEnabled: Bool = true, resolvedIP: String? = nil, subscriptionId: UUID? = nil, outboundProtocol: OutboundProtocol = .vless, ssPassword: String? = nil, ssMethod: String? = nil) {
        self.init(name: "Untitled", serverAddress: serverAddress, serverPort: serverPort, uuid: uuid, encryption: encryption, transport: transport, flow: flow, security: security, tls: tls, reality: reality, websocket: websocket, httpUpgrade: httpUpgrade, xhttp: xhttp, testseed: testseed, muxEnabled: muxEnabled, xudpEnabled: xudpEnabled, resolvedIP: resolvedIP, subscriptionId: subscriptionId, outboundProtocol: outboundProtocol, ssPassword: ssPassword, ssMethod: ssMethod)
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
    }
    
    /// Parse a VLESS or Shadowsocks URL into configuration.
    /// Format: vless://uuid@host:port/?type=tcp&encryption=none&security=none
    /// SS format: ss://base64(method:password)@host:port#name
    static func parse(url: String) throws -> ProxyConfiguration {
        if url.hasPrefix("ss://") {
            return try parseShadowsocks(url: url)
        }
        guard url.hasPrefix("vless://") else {
            throw ProxyError.invalidURL("URL must start with vless:// or ss://")
        }

        var urlWithoutScheme = String(url.dropFirst("vless://".count))

        // Extract fragment (#name) — standard VLESS share link format
        var fragmentName: String?
        if let hashIndex = urlWithoutScheme.lastIndex(of: "#") {
            fragmentName = String(urlWithoutScheme[urlWithoutScheme.index(after: hashIndex)...])
                .removingPercentEncoding
            urlWithoutScheme = String(urlWithoutScheme[..<hashIndex])
        }

        // Split by @ to get UUID and server info
        guard let atIndex = urlWithoutScheme.firstIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator")
        }

        let uuidString = String(urlWithoutScheme[..<atIndex])
        let serverPart = String(urlWithoutScheme[urlWithoutScheme.index(after: atIndex)...])

        // Parse UUID
        guard let uuid = UUID(uuidString: uuidString) else {
            throw ProxyError.invalidURL("Invalid UUID: \(uuidString)")
        }

        // Separate host:port from query string.
        // Handles both "host:port/?params" and "host:port?params" formats.
        let hostPort: String
        var queryString: String?
        if let questionIndex = serverPart.firstIndex(of: "?") {
            let before = String(serverPart[..<questionIndex])
            // Strip trailing "/" if present (e.g. "host:port/")
            hostPort = before.hasSuffix("/") ? String(before.dropLast()) : before
            queryString = String(serverPart[serverPart.index(after: questionIndex)...])
        } else {
            // No query params — strip trailing "/" or path
            let parts = serverPart.split(separator: "/", maxSplits: 1)
            hostPort = String(parts[0])
        }

        // Parse host:port (handles IPv6 bracket notation: [::1]:443)
        let host: String
        let portString: String
        if hostPort.hasPrefix("[") {
            guard let closeBracket = hostPort.firstIndex(of: "]") else {
                throw ProxyError.invalidURL("Missing closing bracket for IPv6 address")
            }
            host = String(hostPort[hostPort.index(after: hostPort.startIndex)..<closeBracket])
            let afterBracket = hostPort[hostPort.index(after: closeBracket)...]
            guard afterBracket.hasPrefix(":") else {
                throw ProxyError.invalidURL("Missing port after IPv6 address")
            }
            portString = String(afterBracket.dropFirst())
        } else {
            guard let colonIndex = hostPort.lastIndex(of: ":") else {
                throw ProxyError.invalidURL("Missing port in server address")
            }
            host = String(hostPort[..<colonIndex])
            portString = String(hostPort[hostPort.index(after: colonIndex)...])
        }

        guard let port = UInt16(portString) else {
            throw ProxyError.invalidURL("Invalid port: \(portString)")
        }

        // Parse query parameters into dictionary
        var params: [String: String] = [:]

        if let queryString {
            for param in queryString.split(separator: "&") {
                let keyValue = param.split(separator: "=", maxSplits: 1)
                if keyValue.count == 2 {
                    let key = String(keyValue[0])
                    let value = String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])
                    params[key] = value
                }
            }
        }

        let encryption = params["encryption"] ?? "none"
        let flow = params["flow"]
        let security = params["security"] ?? "none"
        let transport = params["type"] ?? "tcp"

        // Parse testseed (comma-separated 4 uint32 values, e.g. "900,500,900,256")
        var testseed: [UInt32]? = nil
        if let testseedStr = params["testseed"] {
            let values = testseedStr.split(separator: ",").compactMap { UInt32($0) }
            if values.count >= 4 {
                testseed = Array(values.prefix(4))
            }
        }

        // Parse Reality configuration if security=reality
        var realityConfiguration: RealityConfiguration? = nil
        if security == "reality" {
            do {
                realityConfiguration = try RealityConfiguration.parse(from: params)
            } catch {
                throw ProxyError.invalidURL("Reality configuration error: \(error.localizedDescription)")
            }
        }

        // Parse TLS configuration if security=tls
        var tlsConfiguration: TLSConfiguration? = nil
        if security == "tls" {
            do {
                tlsConfiguration = try TLSConfiguration.parse(from: params, serverAddress: host)
            } catch {
                throw ProxyError.invalidURL("TLS configuration error: \(error.localizedDescription)")
            }
        }

        // Parse WebSocket configuration if type=ws
        var wsConfiguration: WebSocketConfiguration? = nil
        if transport == "ws" {
            wsConfiguration = WebSocketConfiguration.parse(from: params, serverAddress: host)
        }

        // Parse HTTP upgrade configuration if type=httpupgrade
        var httpUpgradeConfiguration: HTTPUpgradeConfiguration? = nil
        if transport == "httpupgrade" {
            httpUpgradeConfiguration = HTTPUpgradeConfiguration.parse(from: params, serverAddress: host)
        }

        // Parse XHTTP configuration if type=xhttp
        var xhttpConfiguration: XHTTPConfiguration? = nil
        if transport == "xhttp" {
            xhttpConfiguration = XHTTPConfiguration.parse(from: params, serverAddress: host)
        }

        // Parse mux and xudp flags (default true, matching Xray-core behavior)
        let muxEnabled = params["mux"].map { $0 != "false" && $0 != "0" } ?? true
        let xudpEnabled = params["xudp"].map { $0 != "false" && $0 != "0" } ?? true

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: uuid,
            encryption: encryption,
            transport: transport,
            flow: flow,
            security: security,
            tls: tlsConfiguration,
            reality: realityConfiguration,
            websocket: wsConfiguration,
            httpUpgrade: httpUpgradeConfiguration,
            xhttp: xhttpConfiguration,
            testseed: testseed,
            muxEnabled: muxEnabled,
            xudpEnabled: xudpEnabled
        )
    }

    /// Parse a Shadowsocks URL into configuration.
    /// Format: ss://base64(method:password)@host:port#name
    /// Also handles: ss://base64(method:password@host:port)#name (SIP002)
    private static func parseShadowsocks(url: String) throws -> ProxyConfiguration {
        var urlWithoutScheme = String(url.dropFirst("ss://".count))

        // Extract fragment (#name)
        var fragmentName: String?
        if let hashIndex = urlWithoutScheme.lastIndex(of: "#") {
            fragmentName = String(urlWithoutScheme[urlWithoutScheme.index(after: hashIndex)...])
                .removingPercentEncoding
            urlWithoutScheme = String(urlWithoutScheme[..<hashIndex])
        }

        let method: String
        let password: String
        let host: String
        let port: UInt16
        var queryString: String?

        if let atIndex = urlWithoutScheme.firstIndex(of: "@") {
            // Standard format: base64(method:password)@host:port/?params
            let userInfo = String(urlWithoutScheme[..<atIndex])
            var serverPart = String(urlWithoutScheme[urlWithoutScheme.index(after: atIndex)...])

            // Extract query string before stripping path
            if let questionIndex = serverPart.firstIndex(of: "?") {
                queryString = String(serverPart[serverPart.index(after: questionIndex)...])
                serverPart = String(serverPart[..<questionIndex])
            }
            // Strip trailing path
            if let slashIndex = serverPart.firstIndex(of: "/") {
                serverPart = String(serverPart[..<slashIndex])
            }

            // Decode base64 user info
            guard let decoded = Data(base64Encoded: padBase64(userInfo)),
                  let decodedString = String(data: decoded, encoding: .utf8),
                  let colonIndex = decodedString.firstIndex(of: ":") else {
                throw ProxyError.invalidURL("Invalid SS user info encoding")
            }
            method = String(decodedString[..<colonIndex])
            password = String(decodedString[decodedString.index(after: colonIndex)...])

            // Parse host:port
            (host, port) = try parseHostPort(serverPart)
        } else {
            // SIP002 format: base64(method:password@host:port)
            guard let decoded = Data(base64Encoded: padBase64(urlWithoutScheme)),
                  let decodedString = String(data: decoded, encoding: .utf8) else {
                throw ProxyError.invalidURL("Invalid SS URL encoding")
            }
            guard let colonIndex = decodedString.firstIndex(of: ":") else {
                throw ProxyError.invalidURL("Missing method:password separator")
            }
            method = String(decodedString[..<colonIndex])
            let rest = String(decodedString[decodedString.index(after: colonIndex)...])
            guard let atIndex = rest.lastIndex(of: "@") else {
                throw ProxyError.invalidURL("Missing @ separator in decoded SS URL")
            }
            password = String(rest[..<atIndex])
            let serverPart = String(rest[rest.index(after: atIndex)...])
            (host, port) = try parseHostPort(serverPart)
        }

        guard ShadowsocksCipher(method: method) != nil else {
            throw ProxyError.invalidURL("Unsupported SS method: \(method)")
        }

        // Parse query parameters (same format as VLESS: type, security, sni, host, path, etc.)
        var params: [String: String] = [:]
        if let queryString {
            for param in queryString.split(separator: "&") {
                let keyValue = param.split(separator: "=", maxSplits: 1)
                if keyValue.count == 2 {
                    let key = String(keyValue[0])
                    let value = String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])
                    params[key] = value
                }
            }
        }

        let transport = params["type"] ?? "tcp"
        let security = params["security"] ?? "none"

        var tlsConfiguration: TLSConfiguration? = nil
        if security == "tls" {
            tlsConfiguration = try TLSConfiguration.parse(from: params, serverAddress: host)
        }

        var wsConfiguration: WebSocketConfiguration? = nil
        if transport == "ws" {
            wsConfiguration = WebSocketConfiguration.parse(from: params, serverAddress: host)
        }

        var httpUpgradeConfiguration: HTTPUpgradeConfiguration? = nil
        if transport == "httpupgrade" {
            httpUpgradeConfiguration = HTTPUpgradeConfiguration.parse(from: params, serverAddress: host)
        }

        var xhttpConfiguration: XHTTPConfiguration? = nil
        if transport == "xhttp" {
            xhttpConfiguration = XHTTPConfiguration.parse(from: params, serverAddress: host)
        }

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for SS
            encryption: "none",
            transport: transport,
            security: security,
            tls: tlsConfiguration,
            websocket: wsConfiguration,
            httpUpgrade: httpUpgradeConfiguration,
            xhttp: xhttpConfiguration,
            outboundProtocol: .shadowsocks,
            ssPassword: password,
            ssMethod: method
        )
    }

    /// Pads a base64 string to a multiple of 4 characters.
    private static func padBase64(_ string: String) -> String {
        let remainder = string.count % 4
        if remainder == 0 { return string }
        return string + String(repeating: "=", count: 4 - remainder)
    }

    /// Parses a host:port string, handling IPv6 brackets.
    private static func parseHostPort(_ string: String) throws -> (String, UInt16) {
        let host: String
        let portString: String
        if string.hasPrefix("[") {
            guard let closeBracket = string.firstIndex(of: "]") else {
                throw ProxyError.invalidURL("Missing closing bracket for IPv6")
            }
            host = String(string[string.index(after: string.startIndex)..<closeBracket])
            let afterBracket = string[string.index(after: closeBracket)...]
            guard afterBracket.hasPrefix(":") else {
                throw ProxyError.invalidURL("Missing port after IPv6 address")
            }
            portString = String(afterBracket.dropFirst())
        } else {
            guard let colonIndex = string.lastIndex(of: ":") else {
                throw ProxyError.invalidURL("Missing port")
            }
            host = String(string[..<colonIndex])
            portString = String(string[string.index(after: colonIndex)...])
        }
        guard let port = UInt16(portString) else {
            throw ProxyError.invalidURL("Invalid port: \(portString)")
        }
        return (host, port)
    }

    /// Export configuration as a shareable URL string.
    /// Produces `vless://...` for VLESS or `ss://...` for Shadowsocks.
    func toURL() -> String {
        switch outboundProtocol {
        case .shadowsocks:
            return toShadowsocksURL()
        case .vless:
            return toVLESSURL()
        }
    }

    private func toVLESSURL() -> String {
        var params: [String] = []

        if encryption != "none" {
            params.append("encryption=\(encryption)")
        }
        if let flow, !flow.isEmpty {
            params.append("flow=\(flow)")
        }
        params.append("security=\(security)")
        if transport != "tcp" {
            params.append("type=\(transport)")
        }

        // TLS parameters
        if security == "tls", let tls {
            if tls.serverName != serverAddress {
                params.append("sni=\(tls.serverName)")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                params.append("alpn=\(alpn.joined(separator: ",").addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? alpn.joined(separator: ","))")
            }
            if tls.allowInsecure {
                params.append("allowInsecure=1")
            }
            if tls.fingerprint != .chrome120 {
                params.append("fp=\(tls.fingerprint.rawValue)")
            }
        }

        // Reality parameters
        if security == "reality", let reality {
            params.append("sni=\(reality.serverName)")
            params.append("pbk=\(reality.publicKey.base64URLEncodedString())")
            if !reality.shortId.isEmpty {
                params.append("sid=\(reality.shortId.hexEncodedString())")
            }
            if reality.fingerprint != .chrome120 {
                params.append("fp=\(reality.fingerprint.rawValue)")
            }
        }

        // Transport parameters
        appendTransportParams(to: &params)

        // Mux/XUDP
        if !muxEnabled {
            params.append("mux=false")
        }
        if !xudpEnabled {
            params.append("xudp=false")
        }

        // Testseed (only if non-default)
        if testseed != [900, 500, 900, 256] {
            params.append("testseed=\(testseed.map { String($0) }.joined(separator: ","))")
        }

        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "vless://\(uuid.uuidString.lowercased())@\(serverAddress):\(serverPort)/\(query)#\(fragment)"
    }

    private func toShadowsocksURL() -> String {
        guard let method = ssMethod, let password = ssPassword else {
            return "ss://invalid"
        }
        let userInfo = "\(method):\(password)"
        let encoded = Data(userInfo.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        var params: [String] = []
        if transport != "tcp" {
            params.append("type=\(transport)")
        }
        if security != "none" {
            params.append("security=\(security)")
        }

        // TLS parameters
        if security == "tls", let tls {
            if tls.serverName != serverAddress {
                params.append("sni=\(tls.serverName)")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                params.append("alpn=\(alpn.joined(separator: ",").addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? alpn.joined(separator: ","))")
            }
            if tls.allowInsecure {
                params.append("allowInsecure=1")
            }
            if tls.fingerprint != .chrome120 {
                params.append("fp=\(tls.fingerprint.rawValue)")
            }
        }

        // Transport parameters
        appendTransportParams(to: &params)

        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "ss://\(encoded)@\(serverAddress):\(serverPort)/\(query)#\(fragment)"
    }

    private func appendTransportParams(to params: inout [String]) {
        if let ws = websocket, transport == "ws" {
            if ws.host != serverAddress {
                params.append("host=\(ws.host)")
            }
            if ws.path != "/" {
                params.append("path=\(ws.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ws.path)")
            }
            if ws.maxEarlyData > 0 {
                params.append("ed=\(ws.maxEarlyData)")
            }
        }
        if let hu = httpUpgrade, transport == "httpupgrade" {
            if hu.host != serverAddress {
                params.append("host=\(hu.host)")
            }
            if hu.path != "/" {
                params.append("path=\(hu.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? hu.path)")
            }
        }
        if let xhttp, transport == "xhttp" {
            if xhttp.host != serverAddress {
                params.append("host=\(xhttp.host)")
            }
            if xhttp.path != "/" {
                params.append("path=\(xhttp.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? xhttp.path)")
            }
            if xhttp.mode != .auto {
                params.append("mode=\(xhttp.mode.rawValue)")
            }
        }
    }

    /// Parses a VLESS configuration from a serialized dictionary.
    ///
    /// Used by PacketTunnelProvider (from tunnel start options / app messages)
    /// and DomainRouter (from routing.json configs).
    static func parse(from configurationDict: [String: Any]) -> ProxyConfiguration? {
        guard let serverAddress = configurationDict["serverAddress"] as? String else {
            return nil
        }
        // UUID is required for VLESS but optional for Shadowsocks
        let uuidString = configurationDict["uuid"] as? String
        let uuid = uuidString.flatMap { UUID(uuidString: $0) } ?? UUID()
        let encryption = (configurationDict["encryption"] as? String) ?? "none"

        // serverPort may arrive as UInt16 (from startTunnel options) or Int (from JSON)
        let serverPort: UInt16
        if let port = configurationDict["serverPort"] as? UInt16 {
            serverPort = port
        } else if let port = configurationDict["serverPort"] as? Int, port > 0, port <= UInt16.max {
            serverPort = UInt16(port)
        } else {
            return nil
        }

        let flow = (configurationDict["flow"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let security = (configurationDict["security"] as? String) ?? "none"

        // Parse Reality configuration if present
        var realityConfiguration: RealityConfiguration? = nil
        if security == "reality",
           let serverName = configurationDict["realityServerName"] as? String,
           let publicKeyBase64 = configurationDict["realityPublicKey"] as? String,
           let publicKey = Data(base64Encoded: publicKeyBase64),
           publicKey.count == 32 {
            let shortIdHex = (configurationDict["realityShortId"] as? String) ?? ""
            let shortId = Data(hexString: shortIdHex) ?? Data()
            let fpString = (configurationDict["realityFingerprint"] as? String) ?? "chrome_120"
            let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

            realityConfiguration = RealityConfiguration(
                serverName: serverName,
                publicKey: publicKey,
                shortId: shortId,
                fingerprint: fingerprint
            )
        }

        // Parse TLS configuration if present
        var tlsConfiguration: TLSConfiguration? = nil
        if security == "tls" {
            let sni = (configurationDict["tlsServerName"] as? String) ?? serverAddress
            var alpn: [String]? = nil
            if let alpnString = configurationDict["tlsAlpn"] as? String, !alpnString.isEmpty {
                alpn = alpnString.split(separator: ",").map { String($0) }
            }
            let allowInsecure = (configurationDict["tlsAllowInsecure"] as? Bool) ?? false
            let fpString = (configurationDict["tlsFingerprint"] as? String) ?? "chrome_120"
            let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

            tlsConfiguration = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
                allowInsecure: allowInsecure,
                fingerprint: fingerprint
            )
        }

        // Parse transport and WebSocket configuration
        let transport = (configurationDict["transport"] as? String) ?? "tcp"

        var wsConfiguration: WebSocketConfiguration? = nil
        if transport == "ws" {
            let wsHost = (configurationDict["wsHost"] as? String) ?? serverAddress
            let wsPath = (configurationDict["wsPath"] as? String) ?? "/"
            var wsHeaders: [String: String] = [:]
            if let headersString = configurationDict["wsHeaders"] as? String, !headersString.isEmpty {
                for pair in headersString.split(separator: ",") {
                    let kv = pair.split(separator: ":", maxSplits: 1)
                    if kv.count == 2 {
                        wsHeaders[String(kv[0])] = String(kv[1])
                    }
                }
            }
            let wsMaxEarlyData = (configurationDict["wsMaxEarlyData"] as? Int) ?? 0
            let wsEarlyDataHeaderName = (configurationDict["wsEarlyDataHeaderName"] as? String) ?? "Sec-WebSocket-Protocol"

            wsConfiguration = WebSocketConfiguration(
                host: wsHost,
                path: wsPath,
                headers: wsHeaders,
                maxEarlyData: wsMaxEarlyData,
                earlyDataHeaderName: wsEarlyDataHeaderName
            )
        }

        // Parse HTTP upgrade configuration if transport=httpupgrade
        var httpUpgradeConfiguration: HTTPUpgradeConfiguration? = nil
        if transport == "httpupgrade" {
            let huHost = (configurationDict["huHost"] as? String) ?? serverAddress
            let huPath = (configurationDict["huPath"] as? String) ?? "/"
            var huHeaders: [String: String] = [:]
            if let headersString = configurationDict["huHeaders"] as? String, !headersString.isEmpty {
                for pair in headersString.split(separator: ",") {
                    let kv = pair.split(separator: ":", maxSplits: 1)
                    if kv.count == 2 {
                        huHeaders[String(kv[0])] = String(kv[1])
                    }
                }
            }

            httpUpgradeConfiguration = HTTPUpgradeConfiguration(
                host: huHost,
                path: huPath,
                headers: huHeaders
            )
        }

        // Parse XHTTP configuration if transport=xhttp
        var xhttpConfiguration: XHTTPConfiguration? = nil
        if transport == "xhttp" {
            let xhttpHost = (configurationDict["xhttpHost"] as? String) ?? serverAddress
            let xhttpPath = (configurationDict["xhttpPath"] as? String) ?? "/"
            let xhttpModeStr = (configurationDict["xhttpMode"] as? String) ?? "auto"
            let xhttpMode = XHTTPMode(rawValue: xhttpModeStr) ?? .auto
            var xhttpHeaders: [String: String] = [:]
            if let headersString = configurationDict["xhttpHeaders"] as? String, !headersString.isEmpty {
                for pair in headersString.split(separator: ",") {
                    let kv = pair.split(separator: ":", maxSplits: 1)
                    if kv.count == 2 {
                        xhttpHeaders[String(kv[0])] = String(kv[1])
                    }
                }
            }
            let xhttpNoGRPCHeader = (configurationDict["xhttpNoGRPCHeader"] as? Bool) ?? false

            xhttpConfiguration = XHTTPConfiguration(
                host: xhttpHost,
                path: xhttpPath,
                mode: xhttpMode,
                headers: xhttpHeaders,
                noGRPCHeader: xhttpNoGRPCHeader
            )
        }

        let muxEnabled = (configurationDict["muxEnabled"] as? Bool) ?? true
        let xudpEnabled = (configurationDict["xudpEnabled"] as? Bool) ?? true
        let resolvedIP = configurationDict["resolvedIP"] as? String

        let protocolStr = (configurationDict["outboundProtocol"] as? String) ?? "vless"
        let outboundProtocol = OutboundProtocol(rawValue: protocolStr) ?? .vless
        let ssPassword = configurationDict["ssPassword"] as? String
        let ssMethod = configurationDict["ssMethod"] as? String

        return ProxyConfiguration(
            name: (configurationDict["name"] as? String) ?? serverAddress,
            serverAddress: serverAddress,
            serverPort: serverPort,
            uuid: uuid,
            encryption: encryption,
            transport: transport,
            flow: flow,
            security: security,
            tls: tlsConfiguration,
            reality: realityConfiguration,
            websocket: wsConfiguration,
            httpUpgrade: httpUpgradeConfiguration,
            xhttp: xhttpConfiguration,
            muxEnabled: muxEnabled,
            xudpEnabled: xudpEnabled,
            resolvedIP: resolvedIP,
            outboundProtocol: outboundProtocol,
            ssPassword: ssPassword,
            ssMethod: ssMethod
        )
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
