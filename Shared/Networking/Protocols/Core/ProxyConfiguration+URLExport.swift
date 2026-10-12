//
//  ProxyConfiguration+URLExport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

extension ProxyConfiguration {
    private var bracketedServerAddress: String {
        serverAddress.contains(":") ? "[\(serverAddress)]" : serverAddress
    }

    private func encodedQueryValue(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&#=")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    func toURL() -> String {
        switch outboundProtocol {
        case .nowhere:
            return toNowhereURL()
        case .vless:
            return toVLESSURL()
        case .hysteria:
            return toHysteriaURL()
        case .sudoku:
            return toSudokuURL()
        case .trojan:
            return toTrojanURL()
        case .anytls:
            return toAnyTLSURL()
        case .shadowsocks:
            return toShadowsocksURL()
        case .socks5:
            return toSOCKS5URL()
        case .rfc:
            return toRFCURL()
        }
    }

    private func toNowhereURL() -> String {
        guard case .nowhere(let configuration) = outbound else {
            return ""
        }
        let usernameCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let encodedKey = configuration.key.addingPercentEncoding(withAllowedCharacters: usernameCharacters) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        let parameters = ["net=\(configuration.network.rawValue)", "morph=\(configuration.morph ? 1 : 0)"]
        return "nowhere://\(encodedKey)@\(bracketedServerAddress):\(serverPort)?\(parameters.joined(separator: "&"))#\(fragment)"
    }

    private func toVLESSURL() -> String {
        guard case .vless(let vless) = outbound else { return "" }
        var parameters: [String] = []

        if vless.encryption != "none" {
            parameters.append("encryption=\(vless.encryption)")
        }
        if let flow = vless.flow, !flow.isEmpty {
            parameters.append("flow=\(flow)")
        }
        parameters.append("security=\(vless.security.tag)")
        if vless.transport.tag != "tcp" {
            parameters.append("type=\(vless.transport.tag)")
        }
        
        if case .tls(let tls) = vless.security {
            if tls.serverName != serverAddress {
                parameters.append("sni=\(tls.serverName)")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                parameters.append("alpn=\(alpn.joined(separator: ",").addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? alpn.joined(separator: ","))")
            }
            if tls.fingerprint != .default {
                parameters.append("fp=\(tls.fingerprint.rawValue)")
            }
            if let ech = tls.echQueryValue {
                parameters.append("ech=\(ech)")
            }
        }

        if case .reality(let reality) = vless.security {
            parameters.append("sni=\(reality.serverName)")
            parameters.append("pbk=\(reality.publicKey.base64URLEncodedString())")
            if !reality.shortId.isEmpty {
                parameters.append("sid=\(reality.shortId.hexEncodedString())")
            }
            if reality.fingerprint != .default {
                parameters.append("fp=\(reality.fingerprint.rawValue)")
            }
        }
        
        appendTransportParams(to: &parameters)

        let query = parameters.isEmpty ? "" : "?\(parameters.joined(separator: "&"))"
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "vless://\(vless.uuid.uuidString.lowercased())@\(bracketedServerAddress):\(serverPort)/\(query)#\(fragment)"
    }
    
    private func appendTransportParams(to params: inout [String]) {
        switch xrayTransportLayer {
        case .ws(let ws):
            if ws.host != serverAddress {
                params.append("host=\(ws.host)")
            }
            if ws.path != "/" {
                params.append("path=\(ws.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ws.path)")
            }
            if ws.maxEarlyData > 0 {
                params.append("ed=\(ws.maxEarlyData)")
            }
        case .httpUpgrade(let hu):
            if hu.host != serverAddress {
                params.append("host=\(hu.host)")
            }
            if hu.path != "/" {
                params.append("path=\(hu.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? hu.path)")
            }
        case .grpc(let grpc):
            if !grpc.serviceName.isEmpty {
                let encoded = grpc.serviceName.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? grpc.serviceName
                params.append("serviceName=\(encoded)")
            }
            if !grpc.authority.isEmpty {
                let encoded = grpc.authority.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? grpc.authority
                params.append("authority=\(encoded)")
            }
            if grpc.multiMode {
                params.append("mode=multi")
            }
        case .xhttp(let xhttp):
            if xhttp.host != serverAddress {
                params.append("host=\(xhttp.host)")
            }
            if xhttp.path != "/" {
                params.append("path=\(xhttp.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? xhttp.path)")
            }
            if xhttp.mode != .auto {
                params.append("mode=\(xhttp.mode.rawValue)")
            }
            if let extra = xhttp.urlExtraParam {
                params.append("extra=\(extra)")
            }
        case .raw:
            break
        }
    }
    
    private func toHysteriaURL() -> String {
        guard case .hysteria(let configuration) = outbound else {
            return ""
        }
        let encodedPassword = configuration.password.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var parameters: [String] = []
        if configuration.congestionControl == .brutal {
            parameters.append("upmbps=\(configuration.uploadMbps)")
            parameters.append("downmbps=\(configuration.downloadMbps)")
        }
        if let obfuscation = configuration.obfuscation {
            parameters.append("obfs=\(obfuscation.typeTag)")
            parameters.append("obfs-password=\(encodedQueryValue(obfuscation.password))")
            if case .gecko(_, let minPacketSize, let maxPacketSize) = obfuscation {
                parameters.append("obfs-min-packet-size=\(minPacketSize)")
                parameters.append("obfs-max-packet-size=\(maxPacketSize)")
            }
        }
        if configuration.serverName != serverAddress {
            parameters.append("sni=\(configuration.serverName)")
        }
        let query = parameters.isEmpty ? "" : "?\(parameters.joined(separator: "&"))"
        return "hysteria2://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)/\(query)#\(fragment)"
    }
    
    private func toSudokuURL() -> String {
        guard case .sudoku(let configuration) = outbound else { return "sudoku://" }
        var payload: [String: Any] = [
            "h": serverAddress,
            "p": Int(serverPort),
            "k": configuration.key,
            "a": configuration.asciiMode.shortLinkToken,
            "e": configuration.aeadMethod.rawValue,
            "x": !configuration.enablePureDownlink
        ]
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedName.isEmpty { payload["n"] = trimmedName }
        if !configuration.customTables.isEmpty { payload["ts"] = configuration.customTables }
        if configuration.httpMask.disable { payload["hd"] = true }
        if configuration.httpMask.mode != .legacy { payload["hm"] = configuration.httpMask.mode.rawValue }
        if configuration.httpMask.tls { payload["ht"] = true }
        if !configuration.httpMask.host.isEmpty { payload["hh"] = configuration.httpMask.host }
        if configuration.multiplex != .off { payload["hx"] = configuration.multiplex.rawValue }
        if !configuration.httpMask.pathRoot.isEmpty { payload["hy"] = configuration.httpMask.pathRoot }

        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            return "sudoku://"
        }
        return "sudoku://\(data.base64URLEncodedString())"
    }

    private func toTrojanURL() -> String {
        guard case .trojan(let configuration) = outbound,
              let tls = configuration.tlsConfiguration else { return "" }
        let encodedPassword = configuration.password.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var parameters: [String] = []
        if tls.serverName != serverAddress {
            parameters.append("sni=\(tls.serverName)")
        }
        if let alpn = tls.alpn, !alpn.isEmpty {
            let joined = alpn.joined(separator: ",")
            parameters.append("alpn=\(joined.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? joined)")
        }
        if tls.fingerprint != .default {
            parameters.append("fp=\(tls.fingerprint.rawValue)")
        }
        if let ech = tls.echQueryValue {
            parameters.append("ech=\(ech)")
        }
        let query = parameters.isEmpty ? "" : "?\(parameters.joined(separator: "&"))"
        return "trojan://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }

    private func toAnyTLSURL() -> String {
        guard case .anytls(let configuration) = outbound,
              let tls = configuration.tlsConfiguration else { return "" }
        let encodedPassword = configuration.password.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var parameters: [String] = []
        if tls.serverName != serverAddress {
            parameters.append("sni=\(tls.serverName)")
        }
        if let alpn = tls.alpn, !alpn.isEmpty {
            let joined = alpn.joined(separator: ",")
            parameters.append("alpn=\(joined.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? joined)")
        }
        if tls.fingerprint != .default {
            parameters.append("fp=\(tls.fingerprint.rawValue)")
        }
        if let ech = tls.echQueryValue {
            parameters.append("ech=\(ech)")
        }
        if configuration.idleCheckInterval != AnyTLSConfiguration.defaultIdleCheckInterval {
            parameters.append("ici=\(configuration.idleCheckInterval)")
        }
        if configuration.idleTimeout != AnyTLSConfiguration.defaultIdleTimeout {
            parameters.append("it=\(configuration.idleTimeout)")
        }
        if configuration.minIdleSession != AnyTLSConfiguration.defaultMinIdleSession {
            parameters.append("mis=\(configuration.minIdleSession)")
        }
        let query = parameters.isEmpty ? "" : "?\(parameters.joined(separator: "&"))"
        return "anytls://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }

    private func toShadowsocksURL() -> String {
        guard case .shadowsocks(let configuration) = outbound else {
            return "ss://invalid"
        }
        let userInfo = "\(configuration.method):\(configuration.password)"
        let encoded = Data(userInfo.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "ss://\(encoded)@\(bracketedServerAddress):\(serverPort)/#\(fragment)"
    }

    private func toSOCKS5URL() -> String {
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        if case .socks5(let configuration) = outbound, let user = configuration.username, !user.isEmpty {
            let encodedUser = user.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? user
            let encodedPass = (configuration.password ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
            return "socks5://\(encodedUser):\(encodedPass)@\(bracketedServerAddress):\(serverPort)#\(fragment)"
        }
        return "socks5://\(bracketedServerAddress):\(serverPort)#\(fragment)"
    }
    
    private func toRFCURL() -> String {
        guard case .rfc(let configuration) = outbound else { return "" }
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        
        var userInfo = ""
        let user = configuration.username ?? ""
        let secret = configuration.password ?? ""
        if !user.isEmpty || !secret.isEmpty {
            let encodedUser = user.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? user
            let encodedPassword = secret.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? secret
            userInfo = "\(encodedUser):\(encodedPassword)@"
        }

        var parameters: [String] = []
        switch configuration.securityLayer {
        case .none:
            parameters.append("security=none")
        case .tls(let tls):
            if tls.serverName != serverAddress {
                parameters.append("sni=\(encodedQueryValue(tls.serverName))")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                let joined = alpn.joined(separator: ",")
                parameters.append("alpn=\(encodedQueryValue(joined))")
            }
            if tls.fingerprint != .default {
                parameters.append("fp=\(tls.fingerprint.rawValue)")
            }
            if let ech = tls.echQueryValue {
                parameters.append("ech=\(ech)")
            }
        }
        let query = parameters.isEmpty ? "" : "?\(parameters.joined(separator: "&"))"
        return "rfc://\(userInfo)\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }
}
