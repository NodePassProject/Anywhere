//
//  ProxyConfiguration+URLParsing.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - URL Parsing

extension ProxyConfiguration {

    /// Parse a VLESS, Shadowsocks, or NaiveProxy URL into configuration.
    /// Format: vless://uuid@host:port/?type=tcp&encryption=none&security=none
    /// SS format: ss://base64(method:password)@host:port#name
    /// Naive format: https://user:pass@host:port#name  or  quic://user:pass@host:port#name
    static func parse(url: String) throws -> ProxyConfiguration {
        if url.hasPrefix("ss://") {
            return try parseShadowsocks(url: url)
        }
        if url.hasPrefix("https://") || url.hasPrefix("quic://") {
            return try parseNaive(url: url)
        }
        guard url.hasPrefix("vless://") else {
            throw ProxyError.invalidURL("URL must start with vless://, ss://, https://, or quic://")
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
        let (host, port) = try parseHostPort(hostPort)

        // Parse query parameters into dictionary
        let params = parseQueryParams(queryString)

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

        // Parse security configurations
        var realityConfiguration: RealityConfiguration? = nil
        if security == "reality" {
            do {
                realityConfiguration = try RealityConfiguration.parse(from: params)
            } catch {
                throw ProxyError.invalidURL("Reality configuration error: \(error.localizedDescription)")
            }
        }

        var tlsConfiguration: TLSConfiguration? = nil
        if security == "tls" {
            do {
                tlsConfiguration = try TLSConfiguration.parse(from: params, serverAddress: host)
            } catch {
                throw ProxyError.invalidURL("TLS configuration error: \(error.localizedDescription)")
            }
        }

        // Parse transport configurations
        let (wsConfig, huConfig, xhttpConfig) = parseTransportConfigs(from: params, transport: transport, serverAddress: host)

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
            websocket: wsConfig,
            httpUpgrade: huConfig,
            xhttp: xhttpConfig,
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

        let params = parseQueryParams(queryString)
        let transport = params["type"] ?? "tcp"
        let security = params["security"] ?? "none"

        var tlsConfiguration: TLSConfiguration? = nil
        if security == "tls" {
            tlsConfiguration = try TLSConfiguration.parse(from: params, serverAddress: host)
        }

        let (wsConfig, huConfig, xhttpConfig) = parseTransportConfigs(from: params, transport: transport, serverAddress: host)

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for SS
            encryption: "none",
            transport: transport,
            security: security,
            tls: tlsConfiguration,
            websocket: wsConfig,
            httpUpgrade: huConfig,
            xhttp: xhttpConfig,
            outboundProtocol: .shadowsocks,
            ssPassword: password,
            ssMethod: method
        )
    }

    /// Parse a NaiveProxy URL into configuration.
    /// Format: https://user:pass@host:port#name
    ///         quic://user:pass@host:port#name
    private static func parseNaive(url: String) throws -> ProxyConfiguration {
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

        return ProxyConfiguration(
            name: fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for naive
            encryption: "none",
            outboundProtocol: scheme == "https" ? .https : .http2,
            naiveUsername: username,
            naivePassword: password,
            naiveScheme: scheme
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

    /// Parses transport-specific configurations from URL parameters.
    private static func parseTransportConfigs(
        from params: [String: String],
        transport: String,
        serverAddress: String
    ) -> (WebSocketConfiguration?, HTTPUpgradeConfiguration?, XHTTPConfiguration?) {
        var wsConfig: WebSocketConfiguration? = nil
        if transport == "ws" {
            wsConfig = WebSocketConfiguration.parse(from: params, serverAddress: serverAddress)
        }

        var huConfig: HTTPUpgradeConfiguration? = nil
        if transport == "httpupgrade" {
            huConfig = HTTPUpgradeConfiguration.parse(from: params, serverAddress: serverAddress)
        }

        var xhttpConfig: XHTTPConfiguration? = nil
        if transport == "xhttp" {
            xhttpConfig = XHTTPConfiguration.parse(from: params, serverAddress: serverAddress)
        }

        return (wsConfig, huConfig, xhttpConfig)
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
