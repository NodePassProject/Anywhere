//
//  ProxyConfiguration+URLParsing.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - URL Parsing

extension ProxyConfiguration {

    /// URL scheme prefixes that ``parse(url:)`` can handle.
    static let parsableURLPrefixes = ["vless://", "hysteria2://", "hy2://", "trojan://", "ss://", "socks5://", "socks://", "sudoku://", "https://", "quic://"]

    /// Whether the given string starts with a URL scheme that ``parse(url:)`` can handle.
    static func canParseURL(_ string: String) -> Bool {
        parsableURLPrefixes.contains { string.hasPrefix($0) }
    }

    /// Parse a VLESS, Shadowsocks, SOCKS5, or NaiveProxy URL into configuration.
    /// Format: vless://uuid@host:port/?type=tcp&encryption=none&security=none
    /// SS format: ss://base64(method:password)@host:port#name
    /// SOCKS5 format: socks5://user:pass@host:port#name  or  socks5://host:port#name
    /// Naive format: https://user:pass@host:port#name  or  quic://user:pass@host:port#name
    /// Trojan format: trojan://password@host:port?sni=...&alpn=h2%2Chttp%2F1.1#name
    static func parse(url: String, naiveProtocol: OutboundProtocol? = nil) throws -> ProxyConfiguration {
        if url.hasPrefix("hysteria2://") || url.hasPrefix("hy2://") {
            return try parseHysteria(url: url)
        }
        if url.hasPrefix("trojan://") {
            return try parseTrojan(url: url)
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
        if url.hasPrefix("https://") || url.hasPrefix("quic://") {
            return try parseNaive(url: url, protocolOverride: naiveProtocol)
        }
        guard url.hasPrefix("vless://") else {
            throw ProxyError.invalidURL("URL must start with vless://, trojan://, ss://, socks5://, sudoku://, https://, or quic://")
        }

        var urlWithoutScheme = String(url.dropFirst("vless://".count))

        // Extract fragment (#name) — standard VLESS share link format
        var fragmentName: String?
        if let hashIndex = urlWithoutScheme.lastIndex(of: "#") {
            fragmentName = String(urlWithoutScheme[urlWithoutScheme.index(after: hashIndex)...])
                .removingPercentEncoding
            urlWithoutScheme = String(urlWithoutScheme[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

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
        let (host, port) = try parseHostPort(hostPort)

        // Parse query parameters into dictionary
        let params = parseQueryParams(queryString)

        let encryption = params["encryption"] ?? "none"
        let flow = params["flow"]
        let security = params["security"] ?? "none"
        let transportStr = params["type"] ?? "tcp"

        // Parse security layer
        let securityLayer: SecurityLayer
        if security == "reality" {
            do {
                if let realityConfig = try RealityConfiguration.parse(from: params) {
                    securityLayer = .reality(realityConfig)
                } else {
                    securityLayer = .none
                }
            } catch {
                throw ProxyError.invalidURL("Reality configuration error: \(error.localizedDescription)")
            }
        } else if security == "tls" {
            do {
                if let tlsConfig = try TLSConfiguration.parse(from: params, serverAddress: host) {
                    securityLayer = .tls(tlsConfig)
                } else {
                    securityLayer = .none
                }
            } catch {
                throw ProxyError.invalidURL("TLS configuration error: \(error.localizedDescription)")
            }
        } else {
            securityLayer = .none
        }

        // Parse transport layer
        let transportLayer = parseTransportLayer(from: params, transport: transportStr, serverAddress: host, securityLayer: securityLayer)

        // Parse mux and xudp flags (default true, matching Xray-core behavior)
        let muxEnabled = params["mux"].map { $0 != "false" && $0 != "0" } ?? true
        let xudpEnabled = params["xudp"].map { $0 != "false" && $0 != "0" } ?? true

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .vless(
                uuid: uuid,
                encryption: encryption,
                flow: flow,
                transport: transportLayer,
                security: securityLayer,
                muxEnabled: muxEnabled,
                xudpEnabled: xudpEnabled
            )
        )
    }
    
    /// Parse a Hysteria v2 URL.
    /// Format: `hysteria2://password@host:port/?sni=...&insecure=0#name`
    /// (`hy2://` is accepted as an alias.)
    private static func parseHysteria(url: String) throws -> ProxyConfiguration {
        let rawPrefix: String = url.hasPrefix("hysteria2://") ? "hysteria2://" : "hy2://"
        var remaining = String(url.dropFirst(rawPrefix.count))

        // 1) Strip fragment
        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...]).removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        // 2) Strip query
        var queryString: String?
        if let questionIndex = remaining.firstIndex(of: "?") {
            queryString = String(remaining[remaining.index(after: questionIndex)...])
            remaining = String(remaining[..<questionIndex])
        }

        // 3) Require @
        guard let atIndex = remaining.lastIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator in hysteria URL")
        }
        let userInfo = String(remaining[..<atIndex])
        var serverPart = String(remaining[remaining.index(after: atIndex)...])

        // Strip trailing `/`
        if serverPart.hasSuffix("/") { serverPart.removeLast() }
        if let slashIndex = serverPart.firstIndex(of: "/") {
            serverPart = String(serverPart[..<slashIndex])
        }

        // Whole userinfo is the password (no user:pass split)
        let password = userInfo.removingPercentEncoding ?? userInfo

        let (host, port) = try parseHostPort(serverPart)
        let params = parseQueryParams(queryString)
        
        let sni = (params["sni"]?.isEmpty == false) ? params["sni"]! : host

        // `upmbps` matches the Hysteria v2 share-link convention for the
        // client's declared upload bandwidth (Mbit/s). Clamped to 1...100.
        let rawMbps = params["upmbps"].flatMap { Int($0) } ?? HysteriaUploadMbpsDefault
        let uploadMbps = clampHysteriaUploadMbps(rawMbps)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .hysteria(password: password, uploadMbps: uploadMbps, sni: sni)
        )
    }
    
    /// Parse a Trojan URL.
    /// Format: `trojan://password@host:port?sni=...&alpn=h2%2Chttp%2F1.1&fp=chrome_133#name`
    /// TLS is mandatory — there is no plaintext Trojan variant on the wire.
    private static func parseTrojan(url: String) throws -> ProxyConfiguration {
        var remaining = String(url.dropFirst("trojan://".count))

        // 1) Strip fragment
        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...]).removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }
        DeviceCensorship.deCensor(&fragmentName)

        // 2) Strip query
        var queryString: String?
        if let questionIndex = remaining.firstIndex(of: "?") {
            queryString = String(remaining[remaining.index(after: questionIndex)...])
            remaining = String(remaining[..<questionIndex])
        }

        // 3) Require @
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
        let params = parseQueryParams(queryString)

        let sni = (params["sni"]?.isEmpty == false ? params["sni"] : nil)
            ?? (params["peer"]?.isEmpty == false ? params["peer"] : nil)
            ?? host

        var alpn: [String]? = nil
        if let alpnString = params["alpn"], !alpnString.isEmpty {
            alpn = alpnString.split(separator: ",").map { String($0) }
        }

        let fpString = params["fp"] ?? "chrome_133"
        let fingerprint = TLSFingerprint(rawValue: fpString) ?? .chrome133

        let tls = TLSConfiguration(serverName: sni, alpn: alpn, fingerprint: fingerprint)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: .trojan(password: password, tls: tls)
        )
    }

    /// Parse a Shadowsocks URL into configuration.
    /// SIP002 allows two userinfo encodings:
    ///   `ss://method:password@host:port#name`            (plain, password percent-encoded)
    ///   `ss://websafe-base64(method:password)@host:port#name`
    /// and we also accept the legacy pre-SIP002 shape
    ///   `ss://base64(method:password@host:port)#name`.
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

        if let atIndex = urlWithoutScheme.lastIndex(of: "@") {
            // SIP002 form: userinfo@host:port/?params
            let userInfo = String(urlWithoutScheme[..<atIndex])
            var serverPart = String(urlWithoutScheme[urlWithoutScheme.index(after: atIndex)...])

            // Strip trailing path/query (we don't carry SS plugin params)
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

    /// Decodes a SIP002 userinfo chunk into `(method, password)`.
    /// A literal `:` in the userinfo means the plain form (method:password
    /// with the password percent-encoded — used by SS2022 share links);
    /// otherwise we treat the whole string as websafe-base64(method:password).
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
    
    /// Parse a SOCKS5 URL into configuration.
    /// Format: socks5://user:pass@host:port#name  or  socks5://host:port#name
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

        // Extract fragment (#name)
        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...])
                .removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }

        // Check for user:pass@host:port or just host:port
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
            // Strip trailing path/query
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

    /// Parse a `sudoku://` short link into configuration.
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
            legacyFallback: rawCustomTables == nil
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

    /// Parse a NaiveProxy URL into configuration.
    /// Format(HTTPS): https://user:pass@host:port#name
    /// Format(QUIC): quic://user:pass@host:port#name
    private static func parseNaive(url: String, protocolOverride: OutboundProtocol? = nil) throws -> ProxyConfiguration {
        // Determine scheme (https or quic)
        let scheme: String
        let urlWithoutScheme: String
        if url.hasPrefix("https://") {
            scheme = "https"
            urlWithoutScheme = String(url.dropFirst("https://".count))
        } else if url.hasPrefix("quic://") {
            scheme = "quic"
            urlWithoutScheme = String(url.dropFirst("quic://".count))
        } else {
            throw ProxyError.invalidURL("Naive URL must start with https:// or quic://")
        }

        var remaining = urlWithoutScheme

        // Extract fragment (#name)
        var fragmentName: String?
        if let hashIndex = remaining.lastIndex(of: "#") {
            fragmentName = String(remaining[remaining.index(after: hashIndex)...])
                .removingPercentEncoding
            remaining = String(remaining[..<hashIndex])
        }

        // Split user:pass@host:port
        guard let atIndex = remaining.lastIndex(of: "@") else {
            throw ProxyError.invalidURL("Missing @ separator in naive URL")
        }

        let userInfo = String(remaining[..<atIndex])
        var serverPart = String(remaining[remaining.index(after: atIndex)...])

        // Strip trailing path/query
        if let slashIndex = serverPart.firstIndex(of: "/") {
            serverPart = String(serverPart[..<slashIndex])
        }

        // Parse user:pass
        guard let colonIndex = userInfo.firstIndex(of: ":") else {
            throw ProxyError.invalidURL("Missing password in naive URL (expected user:pass)")
        }
        let username = String(userInfo[..<colonIndex]).removingPercentEncoding ?? String(userInfo[..<colonIndex])
        let password = String(userInfo[userInfo.index(after: colonIndex)...]).removingPercentEncoding ?? String(userInfo[userInfo.index(after: colonIndex)...])

        // Parse host:port
        let (host, port) = try parseHostPort(serverPart)

        let outbound: Outbound
        switch scheme {
        case "https":
            let proto = protocolOverride ?? .http2
            switch proto {
            case .http11: outbound = .http11(username: username, password: password)
            case .http2:  outbound = .http2(username: username, password: password)
            default:      outbound = .http2(username: username, password: password)
            }
        case "quic":
            outbound = .http3(username: username, password: password)
        default:
            throw ProxyError.invalidURL("Naive URL must start with https:// or quic://")
        }

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            outbound: outbound
        )
    }

    // MARK: - Parsing Helpers

    /// Parses a query string into a dictionary.
    static func parseQueryParams(_ queryString: String?) -> [String: String] {
        guard let queryString else { return [:] }
        var params: [String: String] = [:]
        for param in queryString.split(separator: "&") {
            let keyValue = param.split(separator: "=", maxSplits: 1)
            if keyValue.count == 2 {
                let key = String(keyValue[0])
                let value = String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])
                params[key] = value
            }
        }
        return params
    }

    /// Parses transport layer from URL parameters.
    private static func parseTransportLayer(
        from params: [String: String],
        transport: String,
        serverAddress: String,
        securityLayer: SecurityLayer
    ) -> TransportLayer {
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
            if case .tls(let tls) = securityLayer { tlsServerName = tls.serverName }
            else { tlsServerName = nil }
            let realityServerName: String?
            if case .reality(let reality) = securityLayer { realityServerName = reality.serverName }
            else { realityServerName = nil }
            if let configuration = XHTTPConfiguration.parse(from: params, serverAddress: serverAddress, tlsServerName: tlsServerName, realityServerName: realityServerName) {
                return .xhttp(configuration)
            }
            return .tcp
        default:
            return .tcp
        }
    }

    /// Pads a base64 string to a multiple of 4 characters.
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
