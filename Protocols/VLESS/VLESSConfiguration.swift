//
//  VLESSConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// VLESS protocol configuration
struct VLESSConfiguration: Identifiable, Hashable, Codable {
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

    /// The address to use for socket connections: the resolved IP if available, otherwise `serverAddress`.
    var connectAddress: String { resolvedIP ?? serverAddress }

    /// Compares configuration content, ignoring `id`, `resolvedIP`, and `subscriptionId`.
    /// Used to detect unchanged configs during subscription updates.
    func contentEquals(_ other: VLESSConfiguration) -> Bool {
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
        xudpEnabled == other.xudpEnabled
    }

    init(id: UUID = UUID(), name: String, serverAddress: String, serverPort: UInt16, uuid: UUID, encryption: String, transport: String = "tcp", flow: String? = nil, security: String = "none", tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil, websocket: WebSocketConfiguration? = nil, httpUpgrade: HTTPUpgradeConfiguration? = nil, xhttp: XHTTPConfiguration? = nil, testseed: [UInt32]? = nil, muxEnabled: Bool = true, xudpEnabled: Bool = true, resolvedIP: String? = nil, subscriptionId: UUID? = nil) {
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
    }

    /// Convenience initializer that defaults the name to `"Untitled"`.
    init(serverAddress: String, serverPort: UInt16, uuid: UUID, encryption: String, transport: String = "tcp", flow: String?, security: String = "none", tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil, websocket: WebSocketConfiguration? = nil, httpUpgrade: HTTPUpgradeConfiguration? = nil, xhttp: XHTTPConfiguration? = nil, testseed: [UInt32]? = nil, muxEnabled: Bool = true, xudpEnabled: Bool = true, resolvedIP: String? = nil, subscriptionId: UUID? = nil) {
        self.init(name: "Untitled", serverAddress: serverAddress, serverPort: serverPort, uuid: uuid, encryption: encryption, transport: transport, flow: flow, security: security, tls: tls, reality: reality, websocket: websocket, httpUpgrade: httpUpgrade, xhttp: xhttp, testseed: testseed, muxEnabled: muxEnabled, xudpEnabled: xudpEnabled, resolvedIP: resolvedIP, subscriptionId: subscriptionId)
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
    }
    
    /// Parse a VLESS URL into configuration
    /// Format: vless://uuid@host:port/?type=tcp&encryption=none&security=none
    /// Reality format: vless://uuid@host:port/?security=reality&sni=example.com&pbk=...&sid=...&fp=chrome
    static func parse(url: String) throws -> VLESSConfiguration {
        guard url.hasPrefix("vless://") else {
            throw VLESSError.invalidURL("URL must start with vless://")
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
            throw VLESSError.invalidURL("Missing @ separator")
        }

        let uuidString = String(urlWithoutScheme[..<atIndex])
        let serverPart = String(urlWithoutScheme[urlWithoutScheme.index(after: atIndex)...])

        // Parse UUID
        guard let uuid = UUID(uuidString: uuidString) else {
            throw VLESSError.invalidURL("Invalid UUID: \(uuidString)")
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
                throw VLESSError.invalidURL("Missing closing bracket for IPv6 address")
            }
            host = String(hostPort[hostPort.index(after: hostPort.startIndex)..<closeBracket])
            let afterBracket = hostPort[hostPort.index(after: closeBracket)...]
            guard afterBracket.hasPrefix(":") else {
                throw VLESSError.invalidURL("Missing port after IPv6 address")
            }
            portString = String(afterBracket.dropFirst())
        } else {
            guard let colonIndex = hostPort.lastIndex(of: ":") else {
                throw VLESSError.invalidURL("Missing port in server address")
            }
            host = String(hostPort[..<colonIndex])
            portString = String(hostPort[hostPort.index(after: colonIndex)...])
        }

        guard let port = UInt16(portString) else {
            throw VLESSError.invalidURL("Invalid port: \(portString)")
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
                throw VLESSError.invalidURL("Reality configuration error: \(error.localizedDescription)")
            }
        }

        // Parse TLS configuration if security=tls
        var tlsConfiguration: TLSConfiguration? = nil
        if security == "tls" {
            do {
                tlsConfiguration = try TLSConfiguration.parse(from: params, serverAddress: host)
            } catch {
                throw VLESSError.invalidURL("TLS configuration error: \(error.localizedDescription)")
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

        return VLESSConfiguration(
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

    /// Parses a VLESS configuration from a serialized dictionary.
    ///
    /// Used by PacketTunnelProvider (from tunnel start options / app messages)
    /// and DomainRouter (from routing.json configs).
    static func parse(from configurationDict: [String: Any]) -> VLESSConfiguration? {
        guard let serverAddress = configurationDict["serverAddress"] as? String,
              let uuidString = configurationDict["uuid"] as? String,
              let uuid = UUID(uuidString: uuidString),
              let encryption = configurationDict["encryption"] as? String else {
            return nil
        }

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

        return VLESSConfiguration(
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
            resolvedIP: resolvedIP
        )
    }

}

enum VLESSError: Error, LocalizedError {
    case invalidURL(String)
    case connectionFailed(String)
    case protocolError(String)
    case invalidResponse(String)
    case dropped

    var errorDescription: String? {
        switch self {
        case .invalidURL(let message):
            return "Invalid VLESS URL: \(message)"
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
