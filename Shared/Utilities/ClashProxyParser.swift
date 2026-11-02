//
//  ClashProxyParser.swift
//  Anywhere
//
//  Created by NodePassProject on 3/2/26.
//

import Foundation
import YAML

nonisolated enum ClashProxyParser {
    struct ParseResult {
        let configurations: [ProxyConfiguration]
        let skippedCount: Int
    }

    static func parse(yaml: String) throws -> ParseResult {
        let root: YAML.Node
        do {
            root = try YAML.Node(yaml: yaml)
        } catch {
            throw AnywhereError.parse(.yaml(detail: error.description))
        }

        guard case .mapping = root else {
            throw AnywhereError.parse(.yaml(detail: "root document is not a mapping"))
        }
        guard let proxies = root["proxies"]?.sequence else {
            throw AnywhereError.parse(.clashConfigMissingProxies)
        }

        let configurations = proxies.compactMap(parseProxy)
        return ParseResult(configurations: configurations, skippedCount: proxies.count - configurations.count)
    }

    // MARK: - Dispatch

    private static func parseProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard let type = node.string(forKey: "type") else { return nil }
        switch type {
        case "vless":     return parseVLESSProxy(node)
        case "hysteria2": return parseHysteria2Proxy(node)
        case "sudoku":    return parseSudokuProxy(node)
        case "trojan":    return parseTrojanProxy(node)
        case "anytls":    return parseAnyTLSProxy(node)
        case "ss":        return parseShadowsocksProxy(node)
        case "socks5":    return parseSOCKS5Proxy(node)
        case "http":      return parseRFCProxy(node)
        case "direct":    return parseDirectProxy(node)
        default:          return nil
        }
    }

    private static func parseBasics(_ node: YAML.Node) -> (name: String, server: String, port: UInt16)? {
        guard
            let name = node.string(forKey: "name"),
            let server = node.string(forKey: "server"),
            let port = node.int(forKey: "port"),
            let validPort = UInt16(exactly: port), validPort > 0
        else { return nil }
        return (name, server, validPort)
    }

    // MARK: - VLESS

    private enum ClashECHOpts {
        case disabled
        case enabled(String)
        case enabledWithoutConfig
    }

    private static func parseECHOpts(_ node: YAML.Node) -> ClashECHOpts {
        guard let options = node["ech-opts"], options.bool(forKey: "enable") == true else { return .disabled }
        if let config = options.string(forKey: "config"), !config.isEmpty {
            return .enabled(config)
        }
        return .enabledWithoutConfig
    }

    private static func echSettings(_ node: YAML.Node) -> (config: String?, enabled: Bool) {
        switch parseECHOpts(node) {
        case .disabled:             return (nil, false)
        case .enabled(let config):  return (config, true)
        case .enabledWithoutConfig: return (nil, true)
        }
    }

    private static func parseVLESSProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let uuidString = node.string(forKey: "uuid"),
            let uuid = UUID(vlessString: uuidString)
        else { return nil }

        let network = node.string(forKey: "network") ?? "tcp"
        guard network != "h2" && network != "grpc" else { return nil }

        let encryption = node.string(forKey: "encryption") ?? "none"
        let flow = node.string(forKey: "flow").flatMap { $0.isEmpty ? nil : $0 }

        let serverName = parseSNI(node, server: basics.server)
        let alpn = node.stringArray(forKey: "alpn")
        let fingerprint = parseFingerprint(node)

        let xraySecurityLayer: XraySecurityLayer
        if let realityOptions = node["reality-opts"], case .mapping = realityOptions {
            let publicKeyString = realityOptions.string(forKey: "public-key") ?? ""
            let shortIDString = realityOptions.string(forKey: "short-id") ?? ""
            guard let publicKey = Data(base64URLEncoded: publicKeyString), publicKey.count == 32 else {
                return nil
            }
            xraySecurityLayer = .reality(RealityConfiguration(
                serverName: serverName,
                publicKey: publicKey,
                shortId: Data(hexString: shortIDString) ?? Data(),
                fingerprint: fingerprint
            ))
        } else if node.bool(forKey: "tls") == true {
            let ech = echSettings(node)
            xraySecurityLayer = .tls(TLSConfiguration(
                serverName: serverName,
                alpn: alpn,
                echEnabled: ech.enabled,
                echConfig: ech.config,
                fingerprint: fingerprint
            ))
        } else {
            xraySecurityLayer = .none
        }

        let xrayTransportLayer: XrayTransportLayer
        if network == "ws" {
            xrayTransportLayer = parseWSXrayTransportLayer(from: node, server: basics.server)
        } else {
            xrayTransportLayer = .raw
        }

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .vless(
                VLESSConfiguration(
                    uuid: uuid,
                    encryption: encryption,
                    flow: flow,
                    transport: xrayTransportLayer,
                    security: xraySecurityLayer
                )
            )
        )
    }

    // MARK: - Hysteria2

    private static func parseHysteria2Proxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }

        let obfuscation: HysteriaObfuscation?
        if let obfuscationType = node.string(forKey: "obfs"), !obfuscationType.isEmpty {
            let password = node.string(forKey: "obfs-password") ?? node.string(forKey: "obfs_password")
            let minimumPacketSize = node.int(forKey: "obfs-min-packet-size") ?? node.int(forKey: "obfs_min_packet_size")
            let maximumPacketSize = node.int(forKey: "obfs-max-packet-size") ?? node.int(forKey: "obfs_max_packet_size")
            guard let parsed = HysteriaObfuscation.make(
                type: obfuscationType, password: password,
                geckoMinPacketSize: minimumPacketSize,
                geckoMaxPacketSize: maximumPacketSize
            ) else {
                return nil
            }
            obfuscation = parsed
        } else {
            obfuscation = nil
        }

        let password = node.string(forKey: "password") ?? ""
        let serverName = (node.string(forKey: "sni") ?? node.string(forKey: "servername"))
            .flatMap { $0.isEmpty ? nil : $0 } ?? basics.server
        let upload = node.string(forKey: "up")
        let download = node.string(forKey: "down")
        let hasBandwidth = upload?.isEmpty == false || download?.isEmpty == false
        let congestionControl: HysteriaCongestionControl = hasBandwidth ? .brutal : .bbr

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .hysteria(
                HysteriaConfiguration(
                    password: password,
                    congestionControl: congestionControl,
                    uploadMbps: parseBandwidthMbps(upload, default: HysteriaCongestionControl.uploadMbpsDefault),
                    downloadMbps: parseBandwidthMbps(download, default: HysteriaCongestionControl.downloadMbpsDefault),
                    obfuscation: obfuscation,
                    serverName: serverName
                )
            )
        )
    }

    // MARK: - Sudoku

    private static func parseSudokuProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let key = node.string(forKey: "key")
        else { return nil }

        let aead = SudokuAEADMethod(
            rawValue: node.string(forKey: "aead-method")
                ?? node.string(forKey: "aead")
                ?? SudokuAEADMethod.chacha20Poly1305.rawValue
        ) ?? .chacha20Poly1305
        let asciiMode = SudokuASCIIMode(
            normalized: node.string(forKey: "table-type")
                ?? node.string(forKey: "ascii")
                ?? SudokuASCIIMode.preferEntropy.rawValue
        ) ?? .preferEntropy
        let legacyCustomTable = (
            node.string(forKey: "custom-table")
                ?? node.string(forKey: "custom_table")
                ?? node.string(forKey: "table")
                ?? ""
        )
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let rawCustomTables = node.stringArray(forKey: "custom-tables")
            ?? node.stringArray(forKey: "custom_tables")
            ?? node.stringArray(forKey: "customTables")
        let customTables = SudokuConfiguration.normalizeCustomTables(
            rawCustomTables ?? [],
            legacy: legacyCustomTable,
            legacyFallback: true
        )
        let paddingMin = node.int(forKey: "padding-min") ?? node.int(forKey: "padding_min") ?? 5
        let paddingMax = node.int(forKey: "padding-max") ?? node.int(forKey: "padding_max") ?? max(paddingMin, 15)
        let pureDownlink = node.bool(forKey: "enable-pure-downlink") ?? node.bool(forKey: "enable_pure_downlink") ?? true

        let httpMaskNode = node["httpmask"]
        let httpMask = parseSudokuHTTPMask(httpMaskNode)
        let legacyMultiplex = httpMaskNode?.string(forKey: "multiplex")?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let topLevelMultiplex = node.string(forKey: "multiplex") ?? ""
        let multiplexValue = legacyMultiplex.flatMap { $0.isEmpty ? nil : $0 } ?? topLevelMultiplex
        let multiplex = SudokuMultiplex(normalized: multiplexValue)

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .sudoku(
                SudokuConfiguration(
                    key: key,
                    aeadMethod: aead,
                    paddingMin: paddingMin,
                    paddingMax: paddingMax,
                    asciiMode: asciiMode,
                    customTables: customTables,
                    enablePureDownlink: pureDownlink,
                    multiplex: multiplex,
                    httpMask: httpMask
                )
            )
        )
    }

    // MARK: - Trojan

    private static func parseTrojanProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let password = node.string(forKey: "password")
        else { return nil }

        let network = node.string(forKey: "network") ?? "tcp"
        guard network == "tcp" else { return nil }

        if node["reality-opts"]?.mapping != nil { return nil }
        if node["grpc-opts"]?.mapping != nil { return nil }
        if node["ss-opts"]?.bool(forKey: "enabled") == true { return nil }

        let ech = echSettings(node)

        let tlsConfiguration = TLSConfiguration(
            serverName: parseSNI(node, server: basics.server),
            alpn: node.stringArray(forKey: "alpn"),
            echEnabled: ech.enabled,
            echConfig: ech.config,
            fingerprint: parseFingerprint(node)
        )

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .trojan(TrojanConfiguration(password: password, tls: tlsConfiguration))
        )
    }

    // MARK: - AnyTLS

    private static func parseAnyTLSProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }

        let password = node.string(forKey: "password") ?? ""

        let idleCheckInterval = node.int(forKey: "idle-session-check-interval") ?? AnyTLSConfiguration.defaultIdleCheckInterval
        let idleTimeout = node.int(forKey: "idle-session-timeout") ?? AnyTLSConfiguration.defaultIdleTimeout
        let minIdleSession = node.int(forKey: "min-idle-session") ?? AnyTLSConfiguration.defaultMinIdleSession

        let ech = echSettings(node)

        let tlsConfiguration = TLSConfiguration(
            serverName: parseSNI(node, server: basics.server),
            alpn: node.stringArray(forKey: "alpn"),
            echEnabled: ech.enabled,
            echConfig: ech.config,
            fingerprint: parseFingerprint(node)
        )

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .anytls(
                AnyTLSConfiguration(
                    password: password,
                    idleCheckInterval: idleCheckInterval,
                    idleTimeout: idleTimeout,
                    minIdleSession: minIdleSession,
                    securityLayer: .tls(tlsConfiguration)
                )
            )
        )
    }

    // MARK: - Shadowsocks

    private static func parseShadowsocksProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let password = node.string(forKey: "password"),
            let cipher = node.string(forKey: "cipher"),
            ShadowsocksCipher(method: cipher) != nil
        else { return nil }

        let network = node.string(forKey: "network") ?? node.string(forKey: "plugin-opts-network") ?? "tcp"
        guard network == "tcp" else { return nil }
        if node.bool(forKey: "tls") == true { return nil }
        if let plugin = node.string(forKey: "plugin"), !plugin.isEmpty { return nil }

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .shadowsocks(ShadowsocksConfiguration(password: password, method: cipher))
        )
    }

    // MARK: - SOCKS5

    private static func parseSOCKS5Proxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }
        if node.bool(forKey: "tls") == true { return nil }
        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .socks5(
                SOCKS5Configuration(
                    username: node.string(forKey: "username"),
                    password: node.string(forKey: "password")
                )
            )
        )
    }

    // MARK: - Direct

    private static func parseDirectProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard let name = node.string(forKey: "name") else { return nil }
        return ProxyConfiguration(
            name: name,
            serverAddress: "",
            serverPort: 0,
            outbound: .direct(DirectConfiguration())
        )
    }

    // MARK: - RFC

    private static func parseRFCProxy(_ node: YAML.Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }

        let securityLayer: GenericSecurityLayer
        if node.bool(forKey: "tls") == true {
            let ech = echSettings(node)
            securityLayer = .tls(TLSConfiguration(
                serverName: parseSNI(node, server: basics.server),
                alpn: node.stringArray(forKey: "alpn"),
                echEnabled: ech.enabled,
                echConfig: ech.config,
                fingerprint: parseFingerprint(node)
            ))
        } else {
            securityLayer = .none
        }

        let username = node.string(forKey: "username")
        if username?.contains(":") == true { return nil }

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .rfc(
                RFCConfiguration(
                    username: username,
                    password: node.string(forKey: "password"),
                    securityLayer: securityLayer
                )
            )
        )
    }

    // MARK: - Shared option parsing

    private static func parseSNI(_ node: YAML.Node, server: String) -> String {
        node.string(forKey: "servername")
            ?? node.string(forKey: "sni")
            ?? server
    }

    private static func parseFingerprint(_ node: YAML.Node) -> TLSFingerprint {
        guard let rawValue = node.string(forKey: "client-fingerprint") else { return .plain }
        switch rawValue.lowercased() {
        case "ios":    return .chrome120
        case "random": return .default
        default:       return TLSFingerprint(linkValue: rawValue)
        }
    }

    private static func parseBandwidthMbps(_ rawValue: String?, default defaultValue: Int) -> Int {
        guard let trimmed = rawValue?.trimmingCharacters(in: .whitespaces), !trimmed.isEmpty else {
            return defaultValue
        }
        let leading = trimmed.split(separator: " ", maxSplits: 1).first.map(String.init) ?? trimmed
        return Int(leading) ?? defaultValue
    }

    private static func parseWSXrayTransportLayer(from node: YAML.Node, server: String) -> XrayTransportLayer {
        var path = "/"
        var host = server
        var headers: [String: String] = [:]
        var isHTTPUpgrade = false
        var maxEarlyData = 0
        var earlyDataHeaderName = "Sec-WebSocket-Protocol"

        if let options = node["ws-opts"], case .mapping = options {
            path = options.string(forKey: "path") ?? "/"
            isHTTPUpgrade = options.bool(forKey: "v2ray-http-upgrade") ?? false
            maxEarlyData = options.int(forKey: "max-early-data") ?? 0
            earlyDataHeaderName = options.string(forKey: "early-data-header-name") ?? "Sec-WebSocket-Protocol"

            for pair in options["headers"]?.mapping ?? [] {
                let name = pair.key.string ?? ""
                let value = pair.value.string ?? ""
                headers[name] = value
                if name == "Host" { host = value }
            }
        }

        if isHTTPUpgrade {
            return .httpUpgrade(HTTPUpgradeConfiguration(
                host: host,
                path: path,
                headers: headers
            ))
        } else {
            return .ws(WebSocketConfiguration(
                host: host,
                path: path,
                headers: headers,
                maxEarlyData: maxEarlyData,
                earlyDataHeaderName: earlyDataHeaderName
            ))
        }
    }

    private static func parseSudokuHTTPMask(_ node: YAML.Node?) -> SudokuHTTPMaskConfiguration {
        guard let node, case .mapping = node else { return .init() }
        return SudokuHTTPMaskConfiguration(
            disable: node.bool(forKey: "disable") ?? false,
            mode: SudokuHTTPMaskMode(rawValue: node.string(forKey: "mode") ?? SudokuHTTPMaskMode.legacy.rawValue) ?? .legacy,
            tls: node.bool(forKey: "tls") ?? false,
            host: node.string(forKey: "host") ?? "",
            pathRoot: node.string(forKey: "path-root") ?? node.string(forKey: "path_root") ?? ""
        )
    }
}

// MARK: - Node access

nonisolated private extension YAML.Node {
    func string(forKey key: String) -> String? {
        self[key]?.string
    }

    func int(forKey key: String) -> Int? {
        string(forKey: key).flatMap { Int($0) }
    }

    func bool(forKey key: String) -> Bool? {
        switch string(forKey: key)?.lowercased() {
        case "true", "yes", "1": true
        case "false", "no", "0": false
        default: nil
        }
    }

    func stringArray(forKey key: String) -> [String]? {
        let strings = self[key]?.sequence?.compactMap(\.string) ?? []
        return strings.isEmpty ? nil : strings
    }
}
