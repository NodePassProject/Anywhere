//
//  ProxyConfiguration+DictParsing.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - Dictionary Parsing

extension ProxyConfiguration {

    /// Parses a configuration from a serialized dictionary.
    ///
    /// Used by PacketTunnelProvider (from tunnel start options / app messages)
    /// and DomainRouter (from routing.json configs).
    static func parse(from configurationDict: [String: Any]) -> ProxyConfiguration? {
        guard let serverAddress = configurationDict["serverAddress"] as? String else {
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

        let muxEnabled = (configurationDict["muxEnabled"] as? Bool) ?? true
        let xudpEnabled = (configurationDict["xudpEnabled"] as? Bool) ?? true
        let resolvedIP = configurationDict["resolvedIP"] as? String

        // Parse outbound protocol
        let protocolStr = (configurationDict["outboundProtocol"] as? String) ?? "vless"
        let proto = OutboundProtocol(rawValue: protocolStr) ?? .vless

        let outbound: Outbound
        switch proto {
        case .vless:
            let uuidString = configurationDict["uuid"] as? String
            let uuid = uuidString.flatMap { UUID(uuidString: $0) } ?? UUID()
            let encryption = (configurationDict["encryption"] as? String) ?? "none"
            let flow = (configurationDict["flow"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            outbound = .vless(uuid: uuid, encryption: encryption, flow: flow)
        case .hysteria2:
            outbound = .hysteria2(
                auth: (configurationDict["hysteriaAuth"] as? String) ?? ""
            )
        case .shadowsocks:
            let password = (configurationDict["ssPassword"] as? String) ?? ""
            let method = (configurationDict["ssMethod"] as? String) ?? ""
            outbound = .shadowsocks(password: password, method: method)
        case .socks5:
            outbound = .socks5(
                username: configurationDict["socks5Username"] as? String,
                password: configurationDict["socks5Password"] as? String
            )
        case .http11:
            outbound = .http11(
                username: (configurationDict["http11Username"] as? String) ?? "",
                password: (configurationDict["http11Password"] as? String) ?? ""
            )
        case .http2:
            outbound = .http2(
                username: (configurationDict["http2Username"] as? String) ?? "",
                password: (configurationDict["http2Password"] as? String) ?? ""
            )
        case .http3:
            outbound = .http3(
                username: (configurationDict["http3Username"] as? String) ?? "",
                password: (configurationDict["http3Password"] as? String) ?? ""
            )
        }

        // Parse security layer
        let security = (configurationDict["security"] as? String) ?? "none"
        let securityLayer: SecurityLayer

        if security == "reality",
           let serverName = configurationDict["realityServerName"] as? String,
           let publicKeyBase64 = configurationDict["realityPublicKey"] as? String,
           let publicKey = Data(base64Encoded: publicKeyBase64),
           publicKey.count == 32 {
            let shortIdHex = (configurationDict["realityShortId"] as? String) ?? ""
            let shortId = Data(hexString: shortIdHex) ?? Data()
            let fpString = (configurationDict["realityFingerprint"] as? String) ?? "chrome_133"
            let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome133
            securityLayer = .reality(RealityConfiguration(
                serverName: serverName, publicKey: publicKey,
                shortId: shortId, fingerprint: fingerprint
            ))
        } else if security == "tls" {
            let sni = (configurationDict["tlsServerName"] as? String) ?? serverAddress
            var alpn: [String]? = nil
            if let alpnString = configurationDict["tlsAlpn"] as? String, !alpnString.isEmpty {
                alpn = alpnString.split(separator: ",").map { String($0) }
            }
            let fpString = (configurationDict["tlsFingerprint"] as? String) ?? "chrome_133"
            let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome133
            securityLayer = .tls(TLSConfiguration(
                serverName: sni, alpn: alpn, fingerprint: fingerprint
            ))
        } else {
            securityLayer = .none
        }

        // Parse transport layer
        let transport = (configurationDict["transport"] as? String) ?? "tcp"
        let transportLayer: TransportLayer

        switch transport {
        case "ws":
            let wsHost = (configurationDict["wsHost"] as? String) ?? serverAddress
            let wsPath = (configurationDict["wsPath"] as? String) ?? "/"
            let wsHeaders = parseHeaders(configurationDict["wsHeaders"] as? String)
            let wsMaxEarlyData = (configurationDict["wsMaxEarlyData"] as? Int) ?? 0
            let wsEarlyDataHeaderName = (configurationDict["wsEarlyDataHeaderName"] as? String) ?? "Sec-WebSocket-Protocol"
            transportLayer = .ws(WebSocketConfiguration(
                host: wsHost, path: wsPath, headers: wsHeaders,
                maxEarlyData: wsMaxEarlyData, earlyDataHeaderName: wsEarlyDataHeaderName
            ))
        case "httpupgrade":
            let huHost = (configurationDict["huHost"] as? String) ?? serverAddress
            let huPath = (configurationDict["huPath"] as? String) ?? "/"
            let huHeaders = parseHeaders(configurationDict["huHeaders"] as? String)
            transportLayer = .httpUpgrade(HTTPUpgradeConfiguration(
                host: huHost, path: huPath, headers: huHeaders
            ))
        case "xhttp":
            let tlsServerName: String?
            if case .tls(let tls) = securityLayer { tlsServerName = tls.serverName }
            else { tlsServerName = nil }
            let realityServerName: String?
            if case .reality(let reality) = securityLayer { realityServerName = reality.serverName }
            else { realityServerName = nil }
            let xhttpHost = (configurationDict["xhttpHost"] as? String) ?? tlsServerName ?? realityServerName ?? serverAddress
            let xhttpPath = (configurationDict["xhttpPath"] as? String) ?? "/"
            let xhttpModeStr = (configurationDict["xhttpMode"] as? String) ?? "auto"
            let xhttpMode = XHTTPMode(rawValue: xhttpModeStr) ?? .auto
            let xhttpHeaders = parseHeaders(configurationDict["xhttpHeaders"] as? String)
            let xhttpNoGRPCHeader = (configurationDict["xhttpNoGRPCHeader"] as? Bool) ?? false
            transportLayer = .xhttp(XHTTPConfiguration(
                host: xhttpHost, path: xhttpPath, mode: xhttpMode,
                headers: xhttpHeaders, noGRPCHeader: xhttpNoGRPCHeader
            ))
        default:
            transportLayer = .tcp
        }

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
            resolvedIP: resolvedIP,
            outbound: outbound,
            transportLayer: transportLayer,
            securityLayer: securityLayer,
            muxEnabled: muxEnabled,
            xudpEnabled: xudpEnabled,
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
