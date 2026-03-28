//
//  ClashProxyParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/2/26.
//

import Foundation
import YAML

struct ClashProxyParser {
    struct ParseResult {
        let configurations: [ProxyConfiguration]
        let skippedCount: Int
    }

    enum ParseError: Error, LocalizedError {
        case invalidYAML(String)
        case missingProxiesKey

        var errorDescription: String? {
            switch self {
            case .invalidYAML(let reason):
                return "Invalid Clash YAML: \(reason)"
            case .missingProxiesKey:
                return "Clash YAML is missing 'proxies' key."
            }
        }
    }

    static func parse(yaml yamlString: String) throws -> ParseResult {
        let root: Node
        do {
            root = try load(yamlString)
        } catch {
            throw ParseError.invalidYAML(error.localizedDescription)
        }

        guard root.type == .map else {
            throw ParseError.invalidYAML("Root document is not a mapping")
        }

        let proxies = root["proxies"]
        guard proxies.type == .sequence else {
            throw ParseError.missingProxiesKey
        }

        var configurations: [ProxyConfiguration] = []
        var skippedCount = 0

        for proxyNode in proxies {
            if proxyNode.type == .map, let configuration = parseProxy(proxyNode) {
                configurations.append(configuration)
            } else {
                skippedCount += 1
            }
        }

        return ParseResult(configurations: configurations, skippedCount: skippedCount)
    }

    // MARK: - Node access helpers

    private static func getString(_ node: Node, key: String) -> String? {
        let value = node[key]
        guard value.type == .scalar else { return nil }
        return value.scalar
    }

    private static func getInt(_ node: Node, key: String) -> Int? {
        guard let s = getString(node, key: key) else { return nil }
        return Int(s)
    }

    private static func getBool(_ node: Node, key: String) -> Bool? {
        guard let s = getString(node, key: key) else { return nil }
        switch s.lowercased() {
        case "true", "yes", "1": return true
        case "false", "no", "0": return false
        default: return nil
        }
    }

    private static func getStringSequence(_ node: Node, key: String) -> [String]? {
        let seq = node[key]
        guard seq.type == .sequence else { return nil }
        var result: [String] = []
        for item in seq {
            if item.type == .scalar {
                result.append(item.scalar)
            }
        }
        return result.isEmpty ? nil : result
    }

    // MARK: - Proxy parsing

    private static func parseProxy(_ node: Node) -> ProxyConfiguration? {
        let proxyType = getString(node, key: "type")
        if proxyType == "ss" {
            return parseShadowsocksProxy(node)
        }
        if proxyType == "socks5" {
            return parseSOCKS5Proxy(node)
        }
        guard proxyType == "vless" else { return nil }

        guard
            let name = getString(node, key: "name"),
            let server = getString(node, key: "server"),
            let uuidString = getString(node, key: "uuid"),
            let uuid = UUID(uuidString: uuidString)
        else { return nil }

        guard
            let portInt = getInt(node, key: "port"),
            portInt > 0, portInt <= Int(UInt16.max)
        else { return nil }
        let port = UInt16(portInt)

        // Transport: tcp (default) or ws; skip h2/grpc
        let network = getString(node, key: "network") ?? "tcp"
        guard network != "h2" && network != "grpc" else { return nil }
        let transport = (network == "ws") ? "ws" : "tcp"

        let encryption = getString(node, key: "encryption") ?? "none"
        let rawFlow = getString(node, key: "flow")
        let flow: String? = (rawFlow?.isEmpty == false) ? rawFlow : nil

        // Security: reality > tls > none
        let tlsEnabled = getBool(node, key: "tls") ?? false
        let realityOpts = node["reality-opts"]
        let hasReality = realityOpts.type == .map

        let security: String
        if hasReality {
            security = "reality"
        } else if tlsEnabled {
            security = "tls"
        } else {
            security = "none"
        }

        // Common TLS/Reality fields
        let serverName = getString(node, key: "servername")
            ?? getString(node, key: "sni")
            ?? server
        let clientFP = getString(node, key: "client-fingerprint")
        let fingerprint = TLSFingerprint(rawValue: mapFingerprint(clientFP)) ?? .chrome133
        let alpn = getStringSequence(node, key: "alpn")

        // Build TLS configuration
        var tlsConfig: TLSConfiguration? = nil
        if security == "tls" {
            tlsConfig = TLSConfiguration(
                serverName: serverName,
                alpn: alpn,
                fingerprint: fingerprint
            )
        }

        // Build Reality configuration
        var realityConfig: RealityConfiguration? = nil
        if security == "reality" {
            let pubKeyStr = getString(realityOpts, key: "public-key") ?? ""
            let shortIdStr = getString(realityOpts, key: "short-id") ?? ""
            guard let publicKey = Data(base64URLEncoded: pubKeyStr), publicKey.count == 32 else {
                return nil
            }
            realityConfig = RealityConfiguration(
                serverName: serverName,
                publicKey: publicKey,
                shortId: Data(hexString: shortIdStr) ?? Data(),
                fingerprint: fingerprint
            )
        }

        // Build WebSocket configuration
        var wsConfig: WebSocketConfiguration? = nil
        if transport == "ws" {
            var wsPath = "/"
            var wsHost = server
            var wsHeaders: [String: String] = [:]

            let wsOpts = node["ws-opts"]
            if wsOpts.type == .map {
                wsPath = getString(wsOpts, key: "path") ?? "/"

                let headers = wsOpts["headers"]
                if headers.type == .map {
                    for pair in headers {
                        let k = pair[0].scalar
                        let v = pair[1].scalar
                        wsHeaders[k] = v
                        if k == "Host" { wsHost = v }
                    }
                }
            }

            wsConfig = WebSocketConfiguration(host: wsHost, path: wsPath, headers: wsHeaders)
        }

        let transportLayer: TransportLayer = wsConfig.map { .ws($0) } ?? .tcp
        let securityLayer: SecurityLayer
        if let realityConfig { securityLayer = .reality(realityConfig) }
        else if let tlsConfig { securityLayer = .tls(tlsConfig) }
        else { securityLayer = .none }

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            outbound: .vless(uuid: uuid, encryption: encryption, flow: flow),
            transportLayer: transportLayer,
            securityLayer: securityLayer
        )
    }

    // MARK: - SOCKS5 proxy parsing

    private static func parseSOCKS5Proxy(_ node: Node) -> ProxyConfiguration? {
        guard
            let name = getString(node, key: "name"),
            let server = getString(node, key: "server"),
            let portInt = getInt(node, key: "port"),
            portInt > 0, portInt <= Int(UInt16.max)
        else { return nil }
        let username = getString(node, key: "username")
        let password = getString(node, key: "password")
        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: UInt16(portInt),
            outbound: .socks5(username: username, password: password)
        )
    }

    // MARK: - Shadowsocks proxy parsing

    private static func parseShadowsocksProxy(_ node: Node) -> ProxyConfiguration? {
        guard
            let name = getString(node, key: "name"),
            let server = getString(node, key: "server"),
            let password = getString(node, key: "password"),
            let cipher = getString(node, key: "cipher")
        else { return nil }

        guard ShadowsocksCipher(method: cipher) != nil else { return nil }

        guard
            let portInt = getInt(node, key: "port"),
            portInt > 0, portInt <= Int(UInt16.max)
        else { return nil }
        let port = UInt16(portInt)

        // Transport: tcp (default) or ws
        let network = getString(node, key: "network") ?? getString(node, key: "plugin-opts-network") ?? "tcp"
        guard network != "h2" && network != "grpc" else { return nil }
        let transport = (network == "ws") ? "ws" : "tcp"

        // TLS
        let tlsEnabled = getBool(node, key: "tls") ?? false

        var tlsConfig: TLSConfiguration? = nil
        if tlsEnabled {
            let sni = getString(node, key: "servername")
                ?? getString(node, key: "sni")
                ?? server
            let alpn = getStringSequence(node, key: "alpn")
            let clientFP = getString(node, key: "client-fingerprint")
            let fingerprint = TLSFingerprint(rawValue: mapFingerprint(clientFP)) ?? .chrome133

            tlsConfig = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
                fingerprint: fingerprint
            )
        }

        // WebSocket
        var wsConfig: WebSocketConfiguration? = nil
        if transport == "ws" {
            var wsPath = "/"
            var wsHost = server
            var wsHeaders: [String: String] = [:]

            let wsOpts = node["ws-opts"]
            if wsOpts.type == .map {
                wsPath = getString(wsOpts, key: "path") ?? "/"
                let headers = wsOpts["headers"]
                if headers.type == .map {
                    for pair in headers {
                        let k = pair[0].scalar
                        let v = pair[1].scalar
                        wsHeaders[k] = v
                        if k == "Host" { wsHost = v }
                    }
                }
            }

            wsConfig = WebSocketConfiguration(host: wsHost, path: wsPath, headers: wsHeaders)
        }

        let transportLayer: TransportLayer = wsConfig.map { .ws($0) } ?? .tcp
        let securityLayer: SecurityLayer = tlsConfig.map { .tls($0) } ?? .none

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            outbound: .shadowsocks(password: password, method: cipher),
            transportLayer: transportLayer,
            securityLayer: securityLayer
        )
    }

    /// Maps Clash `client-fingerprint` strings to `TLSFingerprint` raw values.
    private static func mapFingerprint(_ fp: String?) -> String {
        switch fp?.lowercased() {
        case "chrome":  return TLSFingerprint.chrome133.rawValue
        case "firefox": return TLSFingerprint.firefox148.rawValue
        case "safari":  return TLSFingerprint.safari26.rawValue
        case "ios":     return TLSFingerprint.ios14.rawValue
        case "edge":    return TLSFingerprint.edge85.rawValue
        case "android": return TLSFingerprint.android11.rawValue
        case "qq":      return TLSFingerprint.qq11.rawValue
        case "360":     return TLSFingerprint.browser360.rawValue
        case "random":  return TLSFingerprint.random.rawValue
        default:        return fp ?? TLSFingerprint.chrome133.rawValue
        }
    }
}
