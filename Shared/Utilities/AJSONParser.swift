//
//  AJSONParser.swift
//  Anywhere
//
//  Created by NodePassProject on 10/28/26.
//

import Foundation

nonisolated enum AJSONParser {
    static let version = 1
    static let formatHeaderValue = "ajson/\(version)"

    static let fileNamespace = UUID(uuidString: "F1C69133-42AF-4891-ACB0-ED5F5004817A")!

    static func stableIDs(for stableKeys: [UUID: String], in namespace: UUID) -> [UUID: UUID] {
        stableKeys.mapValues { UUID(namespace: namespace, name: $0) }
    }

    struct ParseResult {
        let configurations: [ProxyConfiguration]
        let stableKeys: [UUID: String]
        let name: String?
        let upload: Int64?
        let download: Int64?
        let total: Int64?
        let expire: Date?
        let iconLight: Data?
        let iconDark: Data?
    }

    static func looksLikeDocument(_ text: String) -> Bool {
        var rest = Substring(text)
        while true {
            rest = rest.drop { $0.isWhitespace || $0 == "\u{FEFF}" }
            if rest.hasPrefix("//") {
                rest = rest.drop { !$0.isNewline }
            } else if rest.hasPrefix("/*") {
                guard let end = rest.range(of: "*/") else { return false }
                rest = rest[end.upperBound...]
            } else {
                return rest.first == "{"
            }
        }
    }

    static func parse(_ text: String) throws -> ParseResult {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: Data(text.utf8), options: [.json5Allowed])
        } catch {
            let detail = (error as NSError).userInfo[NSDebugDescriptionErrorKey] as? String ?? error.localizedDescription
            throw AnywhereError.parse(.ajson(detail: detail))
        }
        guard let root = object as? [String: Any] else {
            throw AnywhereError.parse(.ajson(detail: "root is not an object"))
        }
        let document = Fields(root)
        guard let version = try? document.int("anywhere") else {
            throw AnywhereError.parse(.ajson(detail: "missing 'anywhere' version"))
        }
        guard (1...Self.version).contains(version) else {
            throw AnywhereError.parse(.ajson(detail: "version \(version) is not supported, update Anywhere"))
        }
        guard let entries = root["proxies"] as? [Any] else {
            throw AnywhereError.parse(.ajson(detail: "missing 'proxies' array"))
        }

        let templates = ((root["templates"] as? [String: Any]) ?? [:]).compactMapValues { value -> [String: Any]? in
            guard var template = value as? [String: Any] else { return nil }
            for key in ["id", "use", "link"] { template.removeValue(forKey: key) }
            return template
        }

        var configurations: [ProxyConfiguration] = []
        var stableKeys: [UUID: String] = [:]
        var seenKeys = Set<String>()
        for entry in entries {
            guard let parsed = try? parseEntry(entry, templates: templates) else { continue }
            if let key = parsed.key {
                guard seenKeys.insert(key).inserted else { continue }
                stableKeys[parsed.configuration.id] = key
            }
            configurations.append(parsed.configuration)
        }

        let usage = try? document.object("usage")
        let icon = try? document.object("icon")
        return ParseResult(
            configurations: configurations,
            stableKeys: stableKeys,
            name: (try? document.string("name"))?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .nonEmpty,
            upload: (try? usage?.int("upload")).map { Int64($0) },
            download: (try? usage?.int("download")).map { Int64($0) },
            total: (try? usage?.int("total")).map { Int64($0) },
            expire: (try? usage?.int("expire")).map { Date(timeIntervalSince1970: TimeInterval($0)) },
            iconLight: (try? icon?.string("light")).flatMap(Data.init(iconBase64:)),
            iconDark: (try? icon?.string("dark")).flatMap(Data.init(iconBase64:))
        )
    }

    // MARK: - Entries

    private static func parseEntry(
        _ entry: Any,
        templates: [String: [String: Any]]
    ) throws -> (configuration: ProxyConfiguration, key: String?) {
        if let link = entry as? String {
            return (try parseLink(link, name: nil), nil)
        }
        guard var object = entry as? [String: Any] else { throw Invalid() }
        let entryFields = Fields(object)
        let key = try entryFields.nonEmptyString("id")

        if let link = try entryFields.string("link") {
            return (try parseLink(link, name: try entryFields.nonEmptyString("name")), key)
        }
        if let templateName = try entryFields.string("use") {
            guard let template = templates[templateName] else { throw Invalid() }
            object = merged(template, with: object)
        }
        return (try parseProxy(Fields(object)), key)
    }

    private static func merged(_ base: [String: Any], with override: [String: Any]) -> [String: Any] {
        var result = base
        for (key, value) in override {
            if let overrideObject = value as? [String: Any], let baseObject = result[key] as? [String: Any] {
                result[key] = merged(baseObject, with: overrideObject)
            } else {
                result[key] = value
            }
        }
        return result
    }

    private static func parseLink(_ link: String, name: String?) throws -> ProxyConfiguration {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ProxyConfiguration.canParseSubscriptionEntry(trimmed) else { throw Invalid() }
        let configuration = try ProxyConfiguration.parseSubscriptionEntry(url: trimmed)
        guard var name else { return configuration }
        DeviceCensorship.deCensor(&name)
        return ProxyConfiguration(
            name: name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            outbound: configuration.outbound
        )
    }

    // MARK: - Proxy

    private static func parseProxy(_ proxy: Fields) throws -> ProxyConfiguration {
        var name = try proxy.requiredString("name")
        DeviceCensorship.deCensor(&name)

        guard let outboundProtocol = OutboundProtocol(rawValue: try proxy.requiredString("protocol")) else {
            throw Invalid()
        }

        let server: String
        let port: UInt16
        if outboundProtocol == .direct {
            server = ""
            port = 0
        } else {
            var trimmed = try proxy.requiredString("server").trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                trimmed = String(trimmed.dropFirst().dropLast())
            }
            guard !trimmed.isEmpty,
                  let rawPort = try proxy.int("port"),
                  let validPort = UInt16(exactly: rawPort), validPort > 0
            else { throw Invalid() }
            server = trimmed
            port = validPort
        }

        let outbound: Outbound
        switch outboundProtocol {
        case .nowhere:      outbound = .nowhere(try parseNowhere(proxy))
        case .vless:        outbound = .vless(try parseVLESS(proxy, server: server))
        case .hysteria:     outbound = .hysteria(try parseHysteria(proxy, server: server))
        case .sudoku:       outbound = .sudoku(try parseSudoku(proxy))
        case .trojan:       outbound = .trojan(try parseTrojan(proxy, server: server))
        case .anytls:       outbound = .anytls(try parseAnyTLS(proxy, server: server))
        case .shadowsocks:  outbound = .shadowsocks(try parseShadowsocks(proxy))
        case .socks5:       outbound = .socks5(try parseSOCKS5(proxy))
        case .rfc:          outbound = .rfc(try parseRFC(proxy, server: server))
        case .direct:       outbound = .direct(DirectConfiguration())
        }

        return ProxyConfiguration(name: name, serverAddress: server, serverPort: port, outbound: outbound)
    }

    // MARK: - Protocols

    private static func parseNowhere(_ proxy: Fields) throws -> NowhereConfiguration {
        NowhereConfiguration(
            key: try proxy.requiredString("key"),
            network: try proxy.enumeration("network") ?? .tcp,
            morph: try proxy.bool("morph") ?? true,
            morphPrelude: try proxy.enumeration("morphPrelude") ?? .fade
        )
    }

    private static func parseVLESS(_ proxy: Fields, server: String) throws -> VLESSConfiguration {
        guard let uuid = UUID(vlessString: try proxy.requiredString("uuid")) else { throw Invalid() }
        let security = try parseXraySecurity(proxy, server: server)
        return VLESSConfiguration(
            uuid: uuid,
            encryption: try proxy.nonEmptyString("encryption") ?? "none",
            flow: try proxy.nonEmptyString("flow"),
            transport: try parseXrayTransport(proxy, server: server, security: security),
            security: security
        )
    }

    private static func parseHysteria(_ proxy: Fields, server: String) throws -> HysteriaConfiguration {
        let uploadMbps = try proxy.int("upMbps")
        let downloadMbps = try proxy.int("downMbps")
        let congestionControl: HysteriaCongestionControl = try proxy.enumeration("congestion")
            ?? ((uploadMbps != nil || downloadMbps != nil) ? .brutal : .bbr)

        var obfuscation: HysteriaObfuscation?
        if let obfs = try proxy.object("obfs") {
            guard let made = HysteriaObfuscation.make(
                type: try obfs.requiredString("type"),
                password: try obfs.string("password"),
                geckoMinPacketSize: try obfs.int("minPacketSize"),
                geckoMaxPacketSize: try obfs.int("maxPacketSize")
            ) else { throw Invalid() }
            obfuscation = made
        }

        return HysteriaConfiguration(
            password: try proxy.requiredString("password"),
            congestionControl: congestionControl,
            uploadMbps: uploadMbps ?? HysteriaCongestionControl.uploadMbpsDefault,
            downloadMbps: downloadMbps ?? HysteriaCongestionControl.downloadMbpsDefault,
            obfuscation: obfuscation,
            serverName: try proxy.nonEmptyString("sni") ?? server
        )
    }

    private static func parseSudoku(_ proxy: Fields) throws -> SudokuConfiguration {
        var asciiMode = SudokuASCIIMode.preferEntropy
        if let rawASCIIMode = try proxy.string("asciiMode") {
            guard let parsed = SudokuASCIIMode(normalized: rawASCIIMode) else { throw Invalid() }
            asciiMode = parsed
        }

        var httpMask = SudokuHTTPMaskConfiguration()
        if let mask = try proxy.object("httpMask") {
            httpMask = SudokuHTTPMaskConfiguration(
                disable: try mask.bool("disable") ?? false,
                mode: try mask.enumeration("mode") ?? .legacy,
                tls: try mask.bool("tls") ?? false,
                host: try mask.string("host") ?? "",
                pathRoot: try mask.string("pathRoot") ?? ""
            )
        }

        return SudokuConfiguration(
            key: try proxy.requiredString("key"),
            aeadMethod: try proxy.enumeration("aeadMethod") ?? .chacha20Poly1305,
            paddingMin: try proxy.int("paddingMin") ?? 5,
            paddingMax: try proxy.int("paddingMax") ?? 15,
            asciiMode: asciiMode,
            customTables: try proxy.strings("customTables") ?? [],
            enablePureDownlink: try proxy.bool("enablePureDownlink") ?? true,
            multiplex: try proxy.enumeration("multiplex") ?? .off,
            httpMask: httpMask
        )
    }

    private static func parseTrojan(_ proxy: Fields, server: String) throws -> TrojanConfiguration {
        TrojanConfiguration(
            password: try proxy.requiredString("password"),
            securityLayer: try parseGenericSecurity(proxy, server: server)
        )
    }

    private static func parseAnyTLS(_ proxy: Fields, server: String) throws -> AnyTLSConfiguration {
        AnyTLSConfiguration(
            password: try proxy.requiredString("password"),
            idleCheckInterval: try proxy.int("idleCheckInterval") ?? AnyTLSConfiguration.defaultIdleCheckInterval,
            idleTimeout: try proxy.int("idleTimeout") ?? AnyTLSConfiguration.defaultIdleTimeout,
            minIdleSession: try proxy.int("minIdleSession") ?? AnyTLSConfiguration.defaultMinIdleSession,
            securityLayer: try parseGenericSecurity(proxy, server: server)
        )
    }

    private static func parseShadowsocks(_ proxy: Fields) throws -> ShadowsocksConfiguration {
        let method = try proxy.requiredString("method")
        guard ShadowsocksCipher(method: method) != nil else { throw Invalid() }
        return ShadowsocksConfiguration(password: try proxy.string("password") ?? "", method: method)
    }

    private static func parseSOCKS5(_ proxy: Fields) throws -> SOCKS5Configuration {
        SOCKS5Configuration(
            username: try proxy.nonEmptyString("username"),
            password: try proxy.string("password")
        )
    }

    private static func parseRFC(_ proxy: Fields, server: String) throws -> RFCConfiguration {
        let username = try proxy.nonEmptyString("username")
        guard username?.contains(":") != true else { throw Invalid() }
        return RFCConfiguration(
            username: username,
            password: try proxy.string("password"),
            securityLayer: try parseGenericSecurity(proxy, server: server)
        )
    }

    // MARK: - Security Layers

    private static func parseXraySecurity(_ proxy: Fields, server: String) throws -> XraySecurityLayer {
        guard let layer = try proxy.layer("security") else { return .none }
        switch layer.type {
        case "none":    return .none
        case "tls":     return .tls(try parseTLS(layer.fields, server: server))
        case "reality": return .reality(try parseReality(layer.fields))
        default:        throw Invalid()
        }
    }

    private static func parseGenericSecurity(_ proxy: Fields, server: String) throws -> GenericSecurityLayer {
        let layer = try proxy.layer("security") ?? (type: "tls", fields: Fields([:]))
        switch layer.type {
        case "none":    return .none
        case "tls":     return .tls(try parseTLS(layer.fields, server: server))
        default:        throw Invalid()
        }
    }

    private static func parseTLS(_ tls: Fields, server: String) throws -> TLSConfiguration {
        let ech = try parseECH(tls.lookup("ech"))
        let alpn = try tls.strings("alpn")
        return TLSConfiguration(
            serverName: try tls.nonEmptyString("sni") ?? server,
            alpn: alpn?.isEmpty == false ? alpn : nil,
            minVersion: try tls.string("minVersion").map(parseTLSVersion),
            maxVersion: try tls.string("maxVersion").map(parseTLSVersion),
            echEnabled: ech.enabled,
            echConfig: ech.config,
            fingerprint: try parseFingerprint(tls),
            insecureSkipVerify: try tls.bool("insecure") ?? false
        )
    }

    private static func parseReality(_ reality: Fields) throws -> RealityConfiguration {
        guard let publicKey = Data(base64URLEncoded: try reality.requiredString("publicKey")),
              publicKey.count == 32
        else { throw Invalid() }

        let shortIdString = try reality.string("shortId") ?? ""
        let shortId: Data
        if shortIdString.isEmpty {
            shortId = Data()
        } else {
            guard let parsed = Data(hexString: shortIdString), parsed.count <= 8 else { throw Invalid() }
            shortId = parsed
        }

        return RealityConfiguration(
            serverName: try reality.requiredString("sni"),
            publicKey: publicKey,
            shortId: shortId,
            fingerprint: try parseFingerprint(reality)
        )
    }

    private static func parseECH(_ value: Any?) throws -> (config: String?, enabled: Bool) {
        guard let value else { return (nil, false) }
        if let number = value as? NSNumber, number.isBoolean {
            return (nil, number.boolValue)
        }
        guard let config = value as? String, ECHConfigResolver.resolveImmediate(config) != nil else { throw Invalid() }
        return (config, true)
    }

    private static func parseTLSVersion(_ value: String) throws -> TLSVersion {
        switch value {
        case "1.0": return .tls10
        case "1.1": return .tls11
        case "1.2": return .tls12
        case "1.3": return .tls13
        default:    throw Invalid()
        }
    }

    private static func parseFingerprint(_ fields: Fields) throws -> TLSFingerprint {
        guard let value = try fields.string("fingerprint") else { return .default }
        guard let fingerprint = TLSFingerprint(importValue: value) else { throw Invalid() }
        return fingerprint
    }

    // MARK: - Transport Layers

    private static func parseXrayTransport(
        _ proxy: Fields,
        server: String,
        security: XraySecurityLayer
    ) throws -> XrayTransportLayer {
        guard let layer = try proxy.layer("transport") else { return .raw }
        let transport = layer.fields
        switch layer.type {
        case "raw":
            return .raw

        case "ws":
            let heartbeatPeriod = try transport.int("heartbeatPeriod") ?? 0
            guard let heartbeat = UInt32(exactly: heartbeatPeriod) else { throw Invalid() }
            return .ws(
                WebSocketConfiguration(
                    host: try transport.nonEmptyString("host") ?? server,
                    path: try transport.nonEmptyString("path") ?? "/",
                    headers: try transport.stringMap("headers") ?? [:],
                    maxEarlyData: try transport.int("maxEarlyData") ?? 0,
                    earlyDataHeaderName: try transport.nonEmptyString("earlyDataHeaderName") ?? "Sec-WebSocket-Protocol",
                    heartbeatPeriod: heartbeat
                )
            )

        case "httpupgrade":
            return .httpUpgrade(
                HTTPUpgradeConfiguration(
                    host: try transport.nonEmptyString("host") ?? server,
                    path: try transport.nonEmptyString("path") ?? "/",
                    headers: try transport.stringMap("headers") ?? [:]
                )
            )

        case "grpc":
            return .grpc(
                GRPCConfiguration(
                    serviceName: try transport.string("serviceName") ?? "",
                    authority: try transport.string("authority") ?? "",
                    multiMode: try transport.bool("multiMode") ?? false,
                    userAgent: try transport.string("userAgent") ?? "",
                    initialWindowsSize: try transport.int("initialWindowsSize") ?? 0,
                    idleTimeout: try transport.int("idleTimeout") ?? 0,
                    healthCheckTimeout: try transport.int("healthCheckTimeout") ?? 0,
                    permitWithoutStream: try transport.bool("permitWithoutStream") ?? false
                )
            )

        case "xhttp":
            let _: XHTTPMode? = try transport.enumeration("mode")
            var json = transport.raw
            json.removeValue(forKey: "type")
            var parentExtra = json
            for key in ["host", "path", "mode"] { parentExtra.removeValue(forKey: key) }
            let tlsServerName: String?
            if case .tls(let tls) = security { tlsServerName = tls.serverName } else { tlsServerName = nil }
            let realityServerName: String?
            if case .reality(let reality) = security { realityServerName = reality.serverName } else { realityServerName = nil }
            return .xhttp(
                XHTTPConfiguration.parse(
                    fromJSON: json,
                    serverAddress: server,
                    tlsServerName: tlsServerName,
                    realityServerName: realityServerName,
                    downloadSettings: XHTTPConfiguration.parseDownloadSettings(
                        from: json["downloadSettings"] as? [String: Any],
                        parentExtra: parentExtra
                    )
                )
            )

        default:
            throw Invalid()
        }
    }
}

// MARK: - Field access

nonisolated private struct Invalid: Error {}

nonisolated private struct Fields {
    let raw: [String: Any]

    init(_ raw: [String: Any]) {
        self.raw = raw
    }

    func lookup(_ key: String) -> Any? {
        guard let value = raw[key], !(value is NSNull) else { return nil }
        return value
    }

    func string(_ key: String) throws -> String? {
        guard let value = lookup(key) else { return nil }
        guard let string = value as? String else { throw Invalid() }
        return string
    }

    func nonEmptyString(_ key: String) throws -> String? {
        try string(key)?.nonEmpty
    }

    func requiredString(_ key: String) throws -> String {
        guard let string = try nonEmptyString(key) else { throw Invalid() }
        return string
    }

    func int(_ key: String) throws -> Int? {
        guard let value = lookup(key) else { return nil }
        guard let number = value as? NSNumber, !number.isBoolean, let int = Int(exactly: number) else { throw Invalid() }
        return int
    }

    func bool(_ key: String) throws -> Bool? {
        guard let value = lookup(key) else { return nil }
        guard let number = value as? NSNumber, number.isBoolean else { throw Invalid() }
        return number.boolValue
    }

    func strings(_ key: String) throws -> [String]? {
        guard let value = lookup(key) else { return nil }
        guard let strings = value as? [String] else { throw Invalid() }
        return strings
    }

    func stringMap(_ key: String) throws -> [String: String]? {
        guard let value = lookup(key) else { return nil }
        guard let map = value as? [String: String] else { throw Invalid() }
        return map
    }

    func object(_ key: String) throws -> Fields? {
        guard let value = lookup(key) else { return nil }
        guard let object = value as? [String: Any] else { throw Invalid() }
        return Fields(object)
    }

    func enumeration<T: RawRepresentable>(_ key: String) throws -> T? where T.RawValue == String {
        guard let raw = try string(key) else { return nil }
        guard let value = T(rawValue: raw) else { throw Invalid() }
        return value
    }

    func layer(_ key: String) throws -> (type: String, fields: Fields)? {
        guard let value = lookup(key) else { return nil }
        if let type = value as? String { return (type, Fields([:])) }
        guard let object = value as? [String: Any] else { throw Invalid() }
        let fields = Fields(object)
        return (try fields.requiredString("type"), fields)
    }
}

nonisolated private extension NSNumber {
    var isBoolean: Bool { CFGetTypeID(self) == CFBooleanGetTypeID() }
}

nonisolated private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
