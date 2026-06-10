//
//  ClashProxyParser.swift
//  Anywhere
//
//  Created by NodePassProject on 3/2/26.
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

    // MARK: - Dispatch

    /// Clash `type:` values without a matching outbound are silently skipped.
    private static func parseProxy(_ node: Node) -> ProxyConfiguration? {
        guard let type = getString(node, key: "type") else { return nil }
        switch type {
        case "vless":     return parseVLESSProxy(node)
        case "hysteria2": return parseHysteria2Proxy(node)
        case "trojan":    return parseTrojanProxy(node)
        case "anytls":    return parseAnyTLSProxy(node)
        case "ss":        return parseShadowsocksProxy(node)
        case "socks5":    return parseSOCKS5Proxy(node)
        case "sudoku":    return parseSudokuProxy(node)
        default:          return nil
        }
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

    private static func parseBasics(_ node: Node) -> (name: String, server: String, port: UInt16)? {
        guard
            let name = getString(node, key: "name"),
            let server = getString(node, key: "server"),
            let portInt = getInt(node, key: "port"),
            portInt > 0, portInt <= Int(UInt16.max)
        else { return nil }
        return (name, server, UInt16(portInt))
    }

    // MARK: - VLESS

    private static func parseVLESSProxy(_ node: Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let uuidString = getString(node, key: "uuid"),
            let uuid = UUID(xrayString: uuidString)
        else { return nil }

        // Transport: tcp (default) or ws; skip h2/grpc which we don't implement.
        let network = getString(node, key: "network") ?? "tcp"
        guard network != "h2" && network != "grpc" else { return nil }
        let transport = (network == "ws") ? "ws" : "tcp"

        let encryption = getString(node, key: "encryption") ?? "none"
        let rawFlow = getString(node, key: "flow")
        let flow: String? = (rawFlow?.isEmpty == false) ? rawFlow : nil

        let tlsEnabled = getBool(node, key: "tls") ?? false
        let realityOpts = node["reality-opts"]
        let hasReality = realityOpts.type == .map

        let serverName = parseSNI(node, server: basics.server)
        let alpn = getStringSequence(node, key: "alpn")
        let fingerprint = parseFingerprint(node)

        let securityLayer: SecurityLayer
        if hasReality {
            let pubKeyStr = getString(realityOpts, key: "public-key") ?? ""
            let shortIdStr = getString(realityOpts, key: "short-id") ?? ""
            guard let publicKey = Data(base64URLEncoded: pubKeyStr), publicKey.count == 32 else {
                return nil
            }
            securityLayer = .reality(RealityConfiguration(
                serverName: serverName,
                publicKey: publicKey,
                shortId: Data(hexString: shortIdStr) ?? Data(),
                fingerprint: fingerprint
            ))
        } else if tlsEnabled {
            securityLayer = .tls(TLSConfiguration(
                serverName: serverName,
                alpn: alpn,
                fingerprint: fingerprint
            ))
        } else {
            securityLayer = .none
        }

        let transportLayer: TransportLayer
        if transport == "ws" {
            transportLayer = parseWSTransportLayer(from: node, server: basics.server)
        } else {
            transportLayer = .tcp
        }

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .vless(
                uuid: uuid,
                encryption: encryption,
                flow: flow,
                transport: transportLayer,
                security: securityLayer,
                muxEnabled: true,
                xudpEnabled: true
            )
        )
    }
    
    // MARK: - Hysteria2

    /// Our Hysteria client lacks Salamander obfuscation, so obfuscated nodes are skipped. The
    /// `ports` (multi-port hop range) and `hop-interval` fields are imported as `portHopping`.
    private static func parseHysteria2Proxy(_ node: Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }

        if let obfs = getString(node, key: "obfs"), !obfs.isEmpty { return nil }

        let portHopping: HysteriaPortHopping?
        if let ports = getString(node, key: "ports"), !ports.isEmpty {
            // An unparseable range would silently collapse to one port and likely fail to
            // connect, so skip the node entirely — matching how this parser drops nodes
            // whose features it can't faithfully represent.
            guard HysteriaPortHopping.parseRanges(ports) != nil else { return nil }
            let interval = getInt(node, key: "hop-interval") ?? getInt(node, key: "hop_interval")
            portHopping = HysteriaPortHopping(
                portsSpec: ports,
                intervalSeconds: interval ?? HysteriaPortHopping.defaultIntervalSeconds
            )
        } else {
            portHopping = nil
        }

        let password = getString(node, key: "password") ?? ""
        let rawSNI = getString(node, key: "sni") ?? getString(node, key: "servername")
        let sni = (rawSNI?.isEmpty == false) ? rawSNI! : basics.server
        let upString = getString(node, key: "up")
        let downString = getString(node, key: "down")
        // `up`/`down` carry Brutal's bandwidth; a node without either runs BBR.
        let hasBandwidth = (upString?.isEmpty == false) || (downString?.isEmpty == false)
        let congestionControl: HysteriaCongestionControl = hasBandwidth ? .brutal : .bbr
        let uploadMbps = HysteriaCongestionControl.clampUploadMbps(parseBandwidthMbps(upString, default: HysteriaCongestionControl.uploadMbpsDefault))
        let downloadMbps = HysteriaCongestionControl.clampDownloadMbps(parseBandwidthMbps(downString, default: HysteriaCongestionControl.downloadMbpsDefault))

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .hysteria(
                password: password,
                congestionControl: congestionControl,
                uploadMbps: uploadMbps,
                downloadMbps: downloadMbps,
                portHopping: portHopping,
                sni: sni
            )
        )
    }

    // MARK: - Trojan

    /// Nodes using Reality, ECH, gRPC, the Trojan-Go SS layer, or any non-TCP transport are
    /// skipped — silently downgrading would speak a different wire format than the server expects.
    private static func parseTrojanProxy(_ node: Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let password = getString(node, key: "password")
        else { return nil }

        let network = getString(node, key: "network") ?? "tcp"
        guard network == "tcp" else { return nil }

        if node["reality-opts"].type == .map { return nil }
        if node["ech-opts"].type == .map { return nil }
        if node["grpc-opts"].type == .map { return nil }
        let ssOpts = node["ss-opts"]
        if ssOpts.type == .map, getBool(ssOpts, key: "enabled") == true { return nil }

        let tls = TLSConfiguration(
            serverName: parseSNI(node, server: basics.server),
            alpn: getStringSequence(node, key: "alpn"),
            fingerprint: parseFingerprint(node)
        )

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .trojan(password: password, tls: tls)
        )
    }

    // MARK: - AnyTLS

    /// Warm-pool knobs are stored raw; `AnyTLSClient` clamps them at use time.
    private static func parseAnyTLSProxy(_ node: Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }

        let password = getString(node, key: "password") ?? ""

        let idleCheckInterval = getInt(node, key: "idle-session-check-interval") ?? 30
        let idleTimeout = getInt(node, key: "idle-session-timeout") ?? 30
        let minIdleSession = getInt(node, key: "min-idle-session") ?? 0

        let tls = TLSConfiguration(
            serverName: parseSNI(node, server: basics.server),
            alpn: getStringSequence(node, key: "alpn"),
            fingerprint: parseFingerprint(node)
        )

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .anytls(
                password: password,
                idleCheckInterval: idleCheckInterval,
                idleTimeout: idleTimeout,
                minIdleSession: minIdleSession,
                tls: tls
            )
        )
    }

    // MARK: - Shadowsocks

    /// Only bare Shadowsocks is supported — nodes with a plugin, non-TCP transport,
    /// or TLS wrapper are skipped rather than silently downgraded.
    private static func parseShadowsocksProxy(_ node: Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let password = getString(node, key: "password"),
            let cipher = getString(node, key: "cipher"),
            ShadowsocksCipher(method: cipher) != nil
        else { return nil }

        let network = getString(node, key: "network") ?? getString(node, key: "plugin-opts-network") ?? "tcp"
        guard network == "tcp" else { return nil }
        if getBool(node, key: "tls") == true { return nil }
        if let plugin = getString(node, key: "plugin"), !plugin.isEmpty { return nil }

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .shadowsocks(password: password, method: cipher)
        )
    }

    // MARK: - SOCKS5

    private static func parseSOCKS5Proxy(_ node: Node) -> ProxyConfiguration? {
        guard let basics = parseBasics(node) else { return nil }
        // Reject SOCKS5-over-TLS rather than silently downgrading it.
        if getBool(node, key: "tls") == true { return nil }
        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .socks5(
                username: getString(node, key: "username"),
                password: getString(node, key: "password")
            )
        )
    }

    // MARK: - Sudoku

    private static func parseSudokuProxy(_ node: Node) -> ProxyConfiguration? {
        guard
            let basics = parseBasics(node),
            let key = getString(node, key: "key")
        else { return nil }

        let aead = SudokuAEADMethod(
            rawValue: getString(node, key: "aead-method")
                ?? getString(node, key: "aead")
                ?? SudokuAEADMethod.chacha20Poly1305.rawValue
        ) ?? .chacha20Poly1305
        let asciiMode = SudokuASCIIMode(
            normalized: getString(node, key: "table-type")
                ?? getString(node, key: "ascii")
                ?? SudokuASCIIMode.preferEntropy.rawValue
        ) ?? .preferEntropy
        let legacyCustomTable = (
            getString(node, key: "custom-table")
                ?? getString(node, key: "custom_table")
                ?? getString(node, key: "table")
                ?? ""
        )
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let rawCustomTables = getStringSequence(node, key: "custom-tables")
            ?? getStringSequence(node, key: "custom_tables")
            ?? getStringSequence(node, key: "customTables")
        let customTables = SudokuConfiguration.normalizeCustomTables(
            rawCustomTables ?? [],
            legacy: legacyCustomTable,
            legacyFallback: true
        )
        let paddingMin = getInt(node, key: "padding-min") ?? getInt(node, key: "padding_min") ?? 5
        let paddingMax = getInt(node, key: "padding-max") ?? getInt(node, key: "padding_max") ?? max(paddingMin, 15)
        let pureDownlink = getBool(node, key: "enable-pure-downlink") ?? getBool(node, key: "enable_pure_downlink") ?? true

        let httpMaskNode = node["httpmask"]
        let httpMask = parseSudokuHTTPMask(httpMaskNode)

        return ProxyConfiguration(
            name: basics.name,
            serverAddress: basics.server,
            serverPort: basics.port,
            outbound: .sudoku(SudokuConfiguration(
                key: key,
                aeadMethod: aead,
                paddingMin: paddingMin,
                paddingMax: paddingMax,
                asciiMode: asciiMode,
                customTables: customTables,
                enablePureDownlink: pureDownlink,
                httpMask: httpMask
            ))
        )
    }

    // MARK: - Shared option parsing

    /// Clash spells SNI `servername` for VLESS and `sni` for Trojan/Hysteria; accept either on any protocol.
    private static func parseSNI(_ node: Node, server: String) -> String {
        getString(node, key: "servername")
            ?? getString(node, key: "sni")
            ?? server
    }

    private static func parseFingerprint(_ node: Node) -> TLSFingerprint {
        let raw = getString(node, key: "client-fingerprint")
        return TLSFingerprint(rawValue: mapFingerprint(raw)) ?? .chrome133
    }

    /// Parses a Clash bandwidth string (e.g. `"30 Mbps"`, `"30"`) into Mbit/s, or `def` if unparseable.
    private static func parseBandwidthMbps(_ raw: String?, default def: Int) -> Int {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespaces), !trimmed.isEmpty else {
            return def
        }
        let leading = trimmed.split(separator: " ", maxSplits: 1).first.map(String.init) ?? trimmed
        return Int(leading) ?? def
    }

    private static func parseWSTransportLayer(from node: Node, server: String) -> TransportLayer {
        var wsPath = "/"
        var wsHost = server
        var wsHeaders: [String: String] = [:]
        var isHttpUpgrade = false
        var maxEarlyData = 0
        var earlyDataHeaderName = "Sec-WebSocket-Protocol"

        let wsOpts = node["ws-opts"]
        if wsOpts.type == .map {
            wsPath = getString(wsOpts, key: "path") ?? "/"
            isHttpUpgrade = getBool(wsOpts, key: "v2ray-http-upgrade") ?? false
            maxEarlyData = getInt(wsOpts, key: "max-early-data") ?? 0
            earlyDataHeaderName = getString(wsOpts, key: "early-data-header-name") ?? "Sec-WebSocket-Protocol"

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

        if isHttpUpgrade {
            return .httpUpgrade(HTTPUpgradeConfiguration(
                host: wsHost,
                path: wsPath,
                headers: wsHeaders
            ))
        } else {
            return .ws(WebSocketConfiguration(
                host: wsHost,
                path: wsPath,
                headers: wsHeaders,
                maxEarlyData: maxEarlyData,
                earlyDataHeaderName: earlyDataHeaderName
            ))
        }
    }

    private static func parseSudokuHTTPMask(_ node: Node) -> SudokuHTTPMaskConfiguration {
        guard node.type == .map else { return .init() }
        return SudokuHTTPMaskConfiguration(
            disable: getBool(node, key: "disable") ?? false,
            mode: SudokuHTTPMaskMode(rawValue: getString(node, key: "mode") ?? SudokuHTTPMaskMode.legacy.rawValue) ?? .legacy,
            tls: getBool(node, key: "tls") ?? false,
            host: getString(node, key: "host") ?? "",
            pathRoot: getString(node, key: "path-root") ?? getString(node, key: "path_root") ?? "",
            multiplex: SudokuHTTPMaskMultiplex(
                rawValue: getString(node, key: "multiplex") ?? SudokuHTTPMaskMultiplex.off.rawValue
            ) ?? .off
        )
    }

    private static func mapFingerprint(_ fp: String?) -> String {
        switch fp?.lowercased() {
        case "chrome":  return TLSFingerprint.chrome133.rawValue
        case "firefox": return TLSFingerprint.firefox148.rawValue
        case "safari":  return TLSFingerprint.safari26.rawValue
        case "ios":     return TLSFingerprint.ios14.rawValue
        case "edge":    return TLSFingerprint.edge85.rawValue
        case "random":  return TLSFingerprint.random.rawValue
        default:        return fp ?? TLSFingerprint.chrome133.rawValue
        }
    }
}
