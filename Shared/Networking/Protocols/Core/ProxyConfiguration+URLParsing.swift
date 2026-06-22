//
//  ProxyConfiguration+URLParsing.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

// MARK: - URL Parsing

extension ProxyConfiguration {

    static let parsableURLPrefixes = ["vless://", "hysteria2://", "hy2://", "nowhere://", "trojan://", "anytls://", "ss://", "socks5://", "socks://", "sudoku://"]

    static func canParseURL(_ string: String) -> Bool {
        parsableURLPrefixes.contains { string.hasPrefix($0) }
    }

    /// Parses a proxy share link; per-scheme formats are documented on the private parsers.
    static func parse(url: String) throws -> ProxyConfiguration {
        if url.hasPrefix("hysteria2://") || url.hasPrefix("hy2://") {
            return try parseHysteria(url: url)
        }
        if url.hasPrefix("nowhere://") {
            return try parseNowhere(url: url)
        }
        if url.hasPrefix("trojan://") {
            return try parseTrojan(url: url)
        }
        if url.hasPrefix("anytls://") {
            return try parseAnyTLS(url: url)
        }
        if url.hasPrefix("ss://") {
            return try parseShadowsocks(url: url)
        }
        if url.hasPrefix("socks5://") || url.hasPrefix("socks://") {
            return try parseSOCKS5(url: url)
        }
        if url.hasPrefix("sudoku://") {
            return try parseSudoku(url: url)
        }
        guard url.hasPrefix("vless://") else {
            throw ProxyError.invalidURL("URL must start with vless://, hysteria2://, nowhere://, trojan://, anytls://, ss://, socks5://, or sudoku://")
        }

        var urlWithoutScheme = String(url.dropFirst("vless://".count))

        var fragmentName: String?
        if let hashIndex = urlWithoutScheme.lastIndex(of: "#") {
            fragmentName = String(urlWithoutScheme[urlWithoutScheme.index(after: hashIndex)...])
                .removingPercentEncoding
            urlWithoutScheme = String(urlWithoutScheme[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        guard let atIndex = urlWithoutScheme.firstIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator")
        }

        let uuidString = String(urlWithoutScheme[..<atIndex])
        let serverPart = String(urlWithoutScheme[urlWithoutScheme.index(after: atIndex)...])

        guard let uuid = UUID(uuidString: uuidString) else {
            throw ProxyError.invalidURL("Invalid UUID: \(uuidString)")
        }

        let hostPort: String
        var queryString: String?
        if let questionIndex = serverPart.firstIndex(of: "?") {
            let before = String(serverPart[..<questionIndex])
            hostPort = before.hasSuffix("/") ? String(before.dropLast()) : before
            queryString = String(serverPart[serverPart.index(after: questionIndex)...])
        } else {
            let parts = serverPart.split(separator: "/", maxSplits: 1)
            hostPort = String(parts[0])
        }

        let (host, port) = try parseHostPort(hostPort)

        let parameters = parseQueryParams(queryString)

        let encryption = parameters["encryption"] ?? "none"
        let flow = parameters["flow"]
        let security = parameters["security"] ?? "none"
        let transportStr = parameters["type"] ?? "tcp"

        let xraySecurityLayer: XraySecurityLayer
        if security == "reality" {
            do {
                if let realityConfig = try RealityConfiguration.parse(from: parameters) {
                    xraySecurityLayer = .reality(realityConfig)
                } else {
                    xraySecurityLayer = .none
                }
            } catch {
                throw ProxyError.invalidURL("Reality configuration error: \(error.localizedDescription)")
            }
        } else if security == "tls" {
            do {
                if let tlsConfig = try TLSConfiguration.parse(from: parameters, serverAddress: host) {
                    xraySecurityLayer = .tls(tlsConfig)
                } else {
                    xraySecurityLayer = .none
                }
            } catch {
                throw ProxyError.invalidURL("TLS configuration error: \(error.localizedDescription)")
            }
        } else {
            xraySecurityLayer = .none
        }

        let xrayTransportLayer = parseXrayTransportLayer(from: parameters, transport: transportStr, serverAddress: host, xraySecurityLayer: xraySecurityLayer)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .vless(
                uuid: uuid,
                encryption: encryption,
                flow: flow,
                transport: xrayTransportLayer,
                security: xraySecurityLayer
            )
        )
    }
    
    /// Parses `hysteria2://password@host:port/?sni=...&insecure=0#name` (`hy2://` alias accepted).
    private static func parseHysteria(url: String) throws -> ProxyConfiguration {
        let rawPrefix: String = url.hasPrefix("hysteria2://") ? "hysteria2://" : "hy2://"
        var remaining = String(url.dropFirst(rawPrefix.count))

        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...]).removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        var queryString: String?
        if let questionIndex = remaining.firstIndex(of: "?") {
            queryString = String(remaining[remaining.index(after: questionIndex)...])
            remaining = String(remaining[..<questionIndex])
        }

        guard let atIndex = remaining.lastIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator in hysteria URL")
        }
        let userInfo = String(remaining[..<atIndex])
        var serverPart = String(remaining[remaining.index(after: atIndex)...])

        if serverPart.hasSuffix("/") { serverPart.removeLast() }
        if let slashIndex = serverPart.firstIndex(of: "/") {
            serverPart = String(serverPart[..<slashIndex])
        }

        let password = userInfo.removingPercentEncoding ?? userInfo

        let (host, port) = try parseHostPort(serverPart)
        let parameters = parseQueryParams(queryString)

        let sni = (parameters["sni"]?.isEmpty == false) ? parameters["sni"]! : host

        // Presence of upmbps/downmbps selects Brutal; a link without either runs BBR.
        let rawUp = parameters["upmbps"].flatMap { Int($0) }
        let rawDown = parameters["downmbps"].flatMap { Int($0) }
        let congestionControl: HysteriaCongestionControl = (rawUp != nil || rawDown != nil) ? .brutal : .bbr
        let uploadMbps = HysteriaCongestionControl.clampUploadMbps(rawUp ?? HysteriaCongestionControl.uploadMbpsDefault)
        let downloadMbps = HysteriaCongestionControl.clampDownloadMbps(rawDown ?? HysteriaCongestionControl.downloadMbpsDefault)

        // Both `mport` (Hysteria links) and `ports` (Clash) name the hop range, by source.
        let portsSpec = (parameters["mport"]?.isEmpty == false) ? parameters["mport"]
            : ((parameters["ports"]?.isEmpty == false) ? parameters["ports"] : nil)
        let hopInterval = (parameters["hop-interval"] ?? parameters["hopInterval"]).flatMap { Int($0) }
        let portHopping = HysteriaPortHopping.make(spec: portsSpec, intervalSeconds: hopInterval)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
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

    /// Parses `nowhere://<key>@host:port?net=udp|tcp&spec=...&sni=...&alpn=...#name`.
    private static func parseNowhere(url: String) throws -> ProxyConfiguration {
        let rawPrefix = "nowhere://"
        var remaining = String(url.dropFirst(rawPrefix.count))

        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...]).removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        var queryString: String?
        if let questionIndex = remaining.firstIndex(of: "?") {
            queryString = String(remaining[remaining.index(after: questionIndex)...])
            remaining = String(remaining[..<questionIndex])
        }

        guard let atIndex = remaining.lastIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator in Nowhere URL")
        }
        let userInfo = String(remaining[..<atIndex])
        var serverPart = String(remaining[remaining.index(after: atIndex)...])
        if serverPart.hasSuffix("/") { serverPart.removeLast() }
        if let slashIndex = serverPart.firstIndex(of: "/") {
            serverPart = String(serverPart[..<slashIndex])
        }

        let key = userInfo.removingPercentEncoding ?? userInfo
        guard !key.isEmpty else {
            throw ProxyError.invalidURL("Missing Nowhere key")
        }

        let (host, port) = try parseHostPort(serverPart)
        let parameters = parseQueryParams(queryString)
        let spec = parameters["spec"].flatMap { $0.isEmpty ? nil : $0 }
        let rawNetwork = parameters["net"] ?? ""
        let network: NowhereNetwork
        if rawNetwork.isEmpty {
            network = .udp
        } else if let parsed = NowhereNetwork(rawValue: rawNetwork) {
            network = parsed
        } else {
            throw ProxyError.invalidURL("Invalid Nowhere net value")
        }
        let rawPool = parameters["pool"] ?? ""
        let pool: Int
        if rawPool.isEmpty {
            pool = 0
        } else if let parsed = Int(rawPool), NowherePool.validRange.contains(parsed) {
            pool = parsed
        } else {
            throw ProxyError.invalidURL("Invalid Nowhere pool value")
        }
        let sni = (parameters["sni"]?.isEmpty == false ? parameters["sni"] : nil)
            ?? (parameters["peer"]?.isEmpty == false ? parameters["peer"] : nil)
            ?? host
        let alpn = parameters["alpn"].flatMap { $0.isEmpty ? nil : [$0] }
        let ech = (parameters["ech"]?.isEmpty == false) ? parameters["ech"] : nil
        let tls = TLSConfiguration(serverName: sni, alpn: alpn, echConfig: ech)

        return ProxyConfiguration(
            name: fragmentName ?? "Nowhere",
            serverAddress: host,
            serverPort: port,
            outbound: .nowhere(
                key: key,
                spec: spec,
                net: network,
                pool: pool,
                tls: tls
            )
        )
    }
    
    /// Parses `trojan://password@host:port?sni=...&alpn=...&fp=...#name`; TLS is mandatory.
    private static func parseTrojan(url: String) throws -> ProxyConfiguration {
        var remaining = String(url.dropFirst("trojan://".count))

        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...]).removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        var queryString: String?
        if let questionIndex = remaining.firstIndex(of: "?") {
            queryString = String(remaining[remaining.index(after: questionIndex)...])
            remaining = String(remaining[..<questionIndex])
        }

        guard let atIndex = remaining.lastIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator in trojan URL")
        }
        let userInfo = String(remaining[..<atIndex])
        var serverPart = String(remaining[remaining.index(after: atIndex)...])

        if serverPart.hasSuffix("/") { serverPart.removeLast() }
        if let slashIndex = serverPart.firstIndex(of: "/") {
            serverPart = String(serverPart[..<slashIndex])
        }

        // Whole userinfo is the password (no user:pass split per trojan-gfw spec).
        let password = userInfo.removingPercentEncoding ?? userInfo

        let (host, port) = try parseHostPort(serverPart)
        let parameters = parseQueryParams(queryString)

        let sni = (parameters["sni"]?.isEmpty == false ? parameters["sni"] : nil)
            ?? (parameters["peer"]?.isEmpty == false ? parameters["peer"] : nil)
            ?? host

        var alpn: [String]? = nil
        if let alpnString = parameters["alpn"], !alpnString.isEmpty {
            alpn = alpnString.split(separator: ",").map { String($0) }
        }

        let fpString = parameters["fp"] ?? "chrome_120"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

        let ech = (parameters["ech"]?.isEmpty == false) ? parameters["ech"] : nil
        let tls = TLSConfiguration(serverName: sni, alpn: alpn, echConfig: ech, fingerprint: fingerprint)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .trojan(password: password, tls: tls)
        )
    }

    /// Parses `anytls://password@host:port?sni=…[&ici=30&it=30&mis=0]#name`; TLS is mandatory
    /// and the pool knobs default to sing-anytls's recommended values.
    private static func parseAnyTLS(url: String) throws -> ProxyConfiguration {
        var remaining = String(url.dropFirst("anytls://".count))

        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...]).removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        var queryString: String?
        if let questionIndex = remaining.firstIndex(of: "?") {
            queryString = String(remaining[remaining.index(after: questionIndex)...])
            remaining = String(remaining[..<questionIndex])
        }

        guard let atIndex = remaining.lastIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator in anytls URL")
        }
        let userInfo = String(remaining[..<atIndex])
        var serverPart = String(remaining[remaining.index(after: atIndex)...])

        if serverPart.hasSuffix("/") { serverPart.removeLast() }
        if let slashIndex = serverPart.firstIndex(of: "/") {
            serverPart = String(serverPart[..<slashIndex])
        }

        let password = userInfo.removingPercentEncoding ?? userInfo

        let (host, port) = try parseHostPort(serverPart)
        let parameters = parseQueryParams(queryString)

        let sni = (parameters["sni"]?.isEmpty == false ? parameters["sni"] : nil)
            ?? (parameters["peer"]?.isEmpty == false ? parameters["peer"] : nil)
            ?? host

        var alpn: [String]? = nil
        if let alpnString = parameters["alpn"], !alpnString.isEmpty {
            alpn = alpnString.split(separator: ",").map { String($0) }
        }

        let fpString = parameters["fp"] ?? "chrome_120"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome120

        let idleCheckInterval = parameters["ici"].flatMap { Int($0) } ?? 30
        let idleTimeout = parameters["it"].flatMap  { Int($0) } ?? 30
        let minIdleSession = parameters["mis"].flatMap { Int($0) } ?? 0

        let ech = (parameters["ech"]?.isEmpty == false) ? parameters["ech"] : nil
        let tls = TLSConfiguration(serverName: sni, alpn: alpn, echConfig: ech, fingerprint: fingerprint)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .anytls(
                password: password,
                idleCheckInterval: idleCheckInterval,
                idleTimeout: idleTimeout,
                minIdleSession: minIdleSession,
                tls: tls
            )
        )
    }

    /// Parses SIP002 `ss://` links (plain or websafe-base64 userinfo) plus the legacy
    /// pre-SIP002 `ss://base64(method:password@host:port)#name` shape.
    private static func parseShadowsocks(url: String) throws -> ProxyConfiguration {
        var urlWithoutScheme = String(url.dropFirst("ss://".count))

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

        if let atIndex = urlWithoutScheme.lastIndex(of: "@") {
            // SIP002 form: userinfo@host:port/?params
            let userInfo = String(urlWithoutScheme[..<atIndex])
            var serverPart = String(urlWithoutScheme[urlWithoutScheme.index(after: atIndex)...])

            // We don't carry SS plugin params.
            if let questionIndex = serverPart.firstIndex(of: "?") {
                serverPart = String(serverPart[..<questionIndex])
            }
            if let slashIndex = serverPart.firstIndex(of: "/") {
                serverPart = String(serverPart[..<slashIndex])
            }

            (method, password) = try decodeShadowsocksUserInfo(userInfo)
            (host, port) = try parseHostPort(serverPart)
        } else {
            // Legacy pre-SIP002 form: base64(method:password@host:port)
            guard let decoded = Data(base64URLEncoded: urlWithoutScheme),
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

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .shadowsocks(password: password, method: method)
        )
    }

    /// A literal `:` means the plain form (password percent-encoded, used by SS2022 links);
    /// otherwise the whole string is websafe-base64(method:password).
    private static func decodeShadowsocksUserInfo(_ userInfo: String) throws -> (method: String, password: String) {
        if let colonIndex = userInfo.firstIndex(of: ":") {
            let method = String(userInfo[..<colonIndex])
            let rawPassword = String(userInfo[userInfo.index(after: colonIndex)...])
            return (method, rawPassword.removingPercentEncoding ?? rawPassword)
        }
        guard let decoded = Data(base64URLEncoded: userInfo),
              let decodedString = String(data: decoded, encoding: .utf8),
              let colonIndex = decodedString.firstIndex(of: ":") else {
            throw ProxyError.invalidURL("Invalid SS user info encoding")
        }
        let method = String(decodedString[..<colonIndex])
        let password = String(decodedString[decodedString.index(after: colonIndex)...])
        return (method, password)
    }
    
    /// Parses `socks5://user:pass@host:port#name` or `socks5://host:port#name`.
    private static func parseSOCKS5(url: String) throws -> ProxyConfiguration {
        let urlWithoutScheme: String
        if url.hasPrefix("socks5://") {
            urlWithoutScheme = String(url.dropFirst("socks5://".count))
        } else if url.hasPrefix("socks://") {
            urlWithoutScheme = String(url.dropFirst("socks://".count))
        } else {
            throw ProxyError.invalidURL("SOCKS5 URL must start with socks5:// or socks://")
        }

        var remaining = urlWithoutScheme

        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...])
                .removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }

        let username: String?
        let password: String?
        let serverPart: String

        if let atIndex = remaining.lastIndex(of: "@") {
            let userInfo = String(remaining[..<atIndex])
            serverPart = String(remaining[remaining.index(after: atIndex)...])

            if let colonIndex = userInfo.firstIndex(of: ":") {
                username = String(userInfo[..<colonIndex]).removingPercentEncoding ?? String(userInfo[..<colonIndex])
                password = String(userInfo[userInfo.index(after: colonIndex)...]).removingPercentEncoding ?? String(userInfo[userInfo.index(after: colonIndex)...])
            } else {
                username = userInfo.removingPercentEncoding ?? userInfo
                password = nil
            }
        } else {
            username = nil
            password = nil
            if let slashIndex = remaining.firstIndex(of: "/") {
                serverPart = String(remaining[..<slashIndex])
            } else {
                serverPart = remaining
            }
        }

        let (host, port) = try parseHostPort(serverPart)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .socks5(username: username, password: password)
        )
    }

    /// Parses a `sudoku://` short link (base64URL JSON payload).
    private static func parseSudoku(url: String) throws -> ProxyConfiguration {
        let encoded = String(url.dropFirst("sudoku://".count))
        guard let payload = Data(base64URLEncoded: encoded),
              let json = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            throw ProxyError.invalidURL("Invalid Sudoku short link payload")
        }

        guard let host = json["h"] as? String,
              let portValue = json["p"],
              let key = json["k"] as? String,
              !host.isEmpty,
              !key.isEmpty else {
            throw ProxyError.invalidURL("Sudoku short link is missing required fields")
        }

        let portInt: Int
        if let number = portValue as? NSNumber {
            portInt = number.intValue
        } else {
            portInt = Int("\(portValue)") ?? 0
        }
        guard let port = UInt16(exactly: portInt), port > 0 else {
            throw ProxyError.invalidURL("Invalid Sudoku short link port")
        }

        let aead = SudokuAEADMethod(rawValue: (json["e"] as? String) ?? SudokuAEADMethod.none.rawValue) ?? .none
        let asciiMode = SudokuASCIIMode(normalized: (json["a"] as? String) ?? SudokuASCIIMode.preferEntropy.shortLinkToken) ?? .preferEntropy
        let mixPortValue = json["m"] as? NSNumber
        let name = (json["n"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let legacyCustomTable = (
            (json["t"] as? String)
                ?? (json["table"] as? String)
                ?? (json["custom_table"] as? String)
                ?? ""
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        let rawCustomTables = json["ts"] as? [String]
        let customTables = SudokuConfiguration.normalizeCustomTables(
            rawCustomTables ?? [],
            legacy: legacyCustomTable,
            legacyFallback: true
        )
        let enablePureDownlink = !((json["x"] as? Bool) ?? false)
        let httpMask = SudokuHTTPMaskConfiguration(
            disable: (json["hd"] as? Bool) ?? false,
            mode: SudokuHTTPMaskMode(rawValue: (json["hm"] as? String) ?? SudokuHTTPMaskMode.legacy.rawValue) ?? .legacy,
            tls: (json["ht"] as? Bool) ?? false,
            host: (json["hh"] as? String) ?? "",
            pathRoot: (json["hy"] as? String) ?? "",
            multiplex: SudokuHTTPMaskMultiplex(rawValue: (json["hx"] as? String) ?? SudokuHTTPMaskMultiplex.off.rawValue) ?? .off
        )

        let config = SudokuConfiguration(
            key: key,
            aeadMethod: aead,
            paddingMin: 5,
            paddingMax: 15,
            asciiMode: asciiMode,
            customTables: customTables,
            enablePureDownlink: enablePureDownlink,
            httpMask: httpMask
        )

        let defaultName = mixPortValue == nil ? "Sudoku" : "Sudoku \(mixPortValue!.intValue)"
        return ProxyConfiguration(
            name: (name?.isEmpty == false) ? name! : defaultName,
            serverAddress: host,
            serverPort: port,
            outbound: .sudoku(config)
        )
    }

    // MARK: - Parsing Helpers

    static func parseQueryParams(_ queryString: String?) -> [String: String] {
        guard let queryString else { return [:] }
        var parameters: [String: String] = [:]
        for parameter in queryString.split(separator: "&") {
            let keyValue = parameter.split(separator: "=", maxSplits: 1)
            if keyValue.count == 2 {
                let key = String(keyValue[0])
                let value = String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])
                parameters[key] = value
            }
        }
        return parameters
    }

    private static func parseXrayTransportLayer(
        from params: [String: String],
        transport: String,
        serverAddress: String,
        xraySecurityLayer: XraySecurityLayer
    ) -> XrayTransportLayer {
        switch transport {
        case "ws":
            if let configuration = WebSocketConfiguration.parse(from: params, serverAddress: serverAddress) {
                return .ws(configuration)
            }
            return .tcp
        case "httpupgrade":
            if let configuration = HTTPUpgradeConfiguration.parse(from: params, serverAddress: serverAddress) {
                return .httpUpgrade(configuration)
            }
            return .tcp
        case "grpc":
            if let configuration = GRPCConfiguration.parse(from: params) {
                return .grpc(configuration)
            }
            return .tcp
        case "xhttp":
            let tlsServerName: String?
            if case .tls(let tls) = xraySecurityLayer { tlsServerName = tls.serverName }
            else { tlsServerName = nil }
            let realityServerName: String?
            if case .reality(let reality) = xraySecurityLayer { realityServerName = reality.serverName }
            else { realityServerName = nil }
            if let configuration = XHTTPConfiguration.parse(from: params, serverAddress: serverAddress, tlsServerName: tlsServerName, realityServerName: realityServerName) {
                return .xhttp(configuration)
            }
            return .tcp
        default:
            return .tcp
        }
    }

    static func padBase64(_ string: String) -> String {
        let remainder = string.count % 4
        if remainder == 0 { return string }
        return string + String(repeating: "=", count: 4 - remainder)
    }

    /// Parses a host:port string, handling IPv6 brackets.
    static func parseHostPort(_ string: String) throws -> (String, UInt16) {
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
}
