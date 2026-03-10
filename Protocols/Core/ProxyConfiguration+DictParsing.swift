//
//  ProxyConfiguration+DictParsing.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - Dictionary Parsing

extension ProxyConfiguration {

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
            let fpString = (configurationDict["tlsFingerprint"] as? String) ?? "chrome_120"
            let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

            tlsConfiguration = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
                fingerprint: fingerprint
            )
        }

        // Parse transport configuration
        let transport = (configurationDict["transport"] as? String) ?? "tcp"

        var wsConfiguration: WebSocketConfiguration? = nil
        if transport == "ws" {
            let wsHost = (configurationDict["wsHost"] as? String) ?? serverAddress
            let wsPath = (configurationDict["wsPath"] as? String) ?? "/"
            let wsHeaders = parseHeaders(configurationDict["wsHeaders"] as? String)
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

        var httpUpgradeConfiguration: HTTPUpgradeConfiguration? = nil
        if transport == "httpupgrade" {
            let huHost = (configurationDict["huHost"] as? String) ?? serverAddress
            let huPath = (configurationDict["huPath"] as? String) ?? "/"
            let huHeaders = parseHeaders(configurationDict["huHeaders"] as? String)

            httpUpgradeConfiguration = HTTPUpgradeConfiguration(
                host: huHost,
                path: huPath,
                headers: huHeaders
            )
        }

        var xhttpConfiguration: XHTTPConfiguration? = nil
        if transport == "xhttp" {
            let xhttpHost = (configurationDict["xhttpHost"] as? String) ?? serverAddress
            let xhttpPath = (configurationDict["xhttpPath"] as? String) ?? "/"
            let xhttpModeStr = (configurationDict["xhttpMode"] as? String) ?? "auto"
            let xhttpMode = XHTTPMode(rawValue: xhttpModeStr) ?? .auto
            let xhttpHeaders = parseHeaders(configurationDict["xhttpHeaders"] as? String)
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
        let http11Username = configurationDict["http11Username"] as? String
        let http11Password = configurationDict["http11Password"] as? String
        let http2Username = configurationDict["http2Username"] as? String
        let http2Password = configurationDict["http2Password"] as? String
        let http3Username = configurationDict["http3Username"] as? String
        let http3Password = configurationDict["http3Password"] as? String

        // Parse proxy chain if present
        var chain: [ProxyConfiguration]? = nil
        if let chainDicts = configurationDict["chain"] as? [[String: Any]] {
            chain = chainDicts.compactMap { ProxyConfiguration.parse(from: $0) }
            if chain?.isEmpty == true { chain = nil }
        }

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
            ssMethod: ssMethod,
            http11Username: http11Username,
            http11Password: http11Password,
            http2Username: http2Username,
            http2Password: http2Password,
            http3Username: http3Username,
            http3Password: http3Password,
            chain: chain
        )
    }

    /// Parses comma-separated "key:value" header pairs from a string.
    private static func parseHeaders(_ headersString: String?) -> [String: String] {
        guard let headersString, !headersString.isEmpty else { return [:] }
        var headers: [String: String] = [:]
        for pair in headersString.split(separator: ",") {
            let kv = pair.split(separator: ":", maxSplits: 1)
            if kv.count == 2 {
                headers[String(kv[0])] = String(kv[1])
            }
        }
        return headers
    }
}
