//
//  ProxyConfiguration+URLExport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

// MARK: - URL Export

extension ProxyConfiguration {

    /// RFC 3986 §3.2.2: IPv6 literals must be bracketed in URL authority components.
    private var bracketedServerAddress: String {
        serverAddress.contains(":") ? "[\(serverAddress)]" : serverAddress
    }

    private func encodedQueryValue(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&#=")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    /// Export configuration as a shareable URL string.
    func toURL() -> String {
        switch outboundProtocol {
        case .vless:
            return toVLESSURL()
        case .hysteria:
            return toHysteriaURL()
        case .nowhere:
            return toNowhereURL()
        case .trojan:
            return toTrojanURL()
        case .anytls:
            return toAnyTLSURL()
        case .shadowsocks:
            return toShadowsocksURL()
        case .socks5:
            return toSOCKS5URL()
        case .sudoku:
            return toSudokuURL()
        case .http11, .http2, .http3:
            return toNaiveURL()
        }
    }

    private func toVLESSURL() -> String {
        guard case .vless(let uuid, let encryption, let flow, let transport, let security, _, _) = outbound else {
            return ""
        }
        var params: [String] = []

        if encryption != "none" {
            params.append("encryption=\(encryption)")
        }
        if let flow, !flow.isEmpty {
            params.append("flow=\(flow)")
        }
        params.append("security=\(security.tag)")
        if transport.tag != "tcp" {
            params.append("type=\(transport.tag)")
        }
        
        if case .tls(let tls) = security {
            if tls.serverName != serverAddress {
                params.append("sni=\(tls.serverName)")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                params.append("alpn=\(alpn.joined(separator: ",").addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? alpn.joined(separator: ","))")
            }
            if tls.fingerprint != .chrome120 {
                params.append("fp=\(tls.fingerprint.rawValue)")
            }
            if let ech = tls.echQueryValue {
                params.append("ech=\(ech)")
            }
        }

        if case .reality(let reality) = security {
            params.append("sni=\(reality.serverName)")
            params.append("pbk=\(reality.publicKey.base64URLEncodedString())")
            if !reality.shortId.isEmpty {
                params.append("sid=\(reality.shortId.hexEncodedString())")
            }
            if reality.fingerprint != .chrome120 {
                params.append("fp=\(reality.fingerprint.rawValue)")
            }
        }
        
        appendTransportParams(to: &params)
        
        if !muxEnabled {
            params.append("mux=false")
        }
        
        if !xudpEnabled {
            params.append("xudp=false")
        }
        
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "vless://\(uuid.uuidString.lowercased())@\(bracketedServerAddress):\(serverPort)/\(query)#\(fragment)"
    }
    
    private func toHysteriaURL() -> String {
        guard case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let portHopping, let sni) = outbound else {
            return ""
        }
        let encodedPassword = password.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var params: [String] = []
        if congestionControl == .brutal {
            params.append("upmbps=\(uploadMbps)")
            params.append("downmbps=\(downloadMbps)")
        }
        if let portHopping {
            params.append("mport=\(portHopping.portsSpec)")
            if portHopping.intervalSeconds != HysteriaPortHopping.defaultIntervalSeconds {
                params.append("hop-interval=\(portHopping.intervalSeconds)")
            }
        }
        if sni != serverAddress {
            params.append("sni=\(sni)")
        }
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "hysteria2://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)/\(query)#\(fragment)"
    }

    private func toNowhereURL() -> String {
        guard case .nowhere(let key, let spec, let tls) = outbound else {
            return ""
        }
        let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var params: [String] = []
        if let spec, !spec.isEmpty {
            params.append("spec=\(encodedQueryValue(spec))")
        }
        if tls.serverName != serverAddress {
            params.append("sni=\(encodedQueryValue(tls.serverName))")
        }
        if let alpn = tls.alpn?.first, !alpn.isEmpty {
            params.append("alpn=\(encodedQueryValue(alpn))")
        }
        if let ech = tls.echQueryValue {
            params.append("ech=\(ech)")
        }
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "nowhere://\(encodedKey)@\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }

    private func toTrojanURL() -> String {
        guard case .trojan(let password, let tls) = outbound else { return "" }
        let encodedPassword = password.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var params: [String] = []
        if tls.serverName != serverAddress {
            params.append("sni=\(tls.serverName)")
        }
        if let alpn = tls.alpn, !alpn.isEmpty {
            let joined = alpn.joined(separator: ",")
            params.append("alpn=\(joined.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? joined)")
        }
        if tls.fingerprint != .chrome120 {
            params.append("fp=\(tls.fingerprint.rawValue)")
        }
        if let ech = tls.echQueryValue {
            params.append("ech=\(ech)")
        }
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "trojan://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }

    private func toAnyTLSURL() -> String {
        guard case .anytls(let password, let ici, let it, let mis, let tls) = outbound else { return "" }
        let encodedPassword = password.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var params: [String] = []
        if tls.serverName != serverAddress {
            params.append("sni=\(tls.serverName)")
        }
        if let alpn = tls.alpn, !alpn.isEmpty {
            let joined = alpn.joined(separator: ",")
            params.append("alpn=\(joined.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? joined)")
        }
        if tls.fingerprint != .chrome120 {
            params.append("fp=\(tls.fingerprint.rawValue)")
        }
        if let ech = tls.echQueryValue {
            params.append("ech=\(ech)")
        }
        // Emit pool tuners only when they differ from the sing-anytls defaults.
        if ici != 30 { params.append("ici=\(ici)") }
        if it != 30 { params.append("it=\(it)") }
        if mis != 0 { params.append("mis=\(mis)") }
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "anytls://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }

    private func toShadowsocksURL() -> String {
        guard case .shadowsocks(let password, let method) = outbound else {
            return "ss://invalid"
        }
        let userInfo = "\(method):\(password)"
        let encoded = Data(userInfo.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "ss://\(encoded)@\(bracketedServerAddress):\(serverPort)/#\(fragment)"
    }

    private func toSOCKS5URL() -> String {
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        if case .socks5(let username, let password) = outbound, let user = username, !user.isEmpty {
            let encodedUser = user.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? user
            let encodedPass = (password ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
            return "socks5://\(encodedUser):\(encodedPass)@\(bracketedServerAddress):\(serverPort)#\(fragment)"
        }
        return "socks5://\(bracketedServerAddress):\(serverPort)#\(fragment)"
    }

    private func toSudokuURL() -> String {
        guard case .sudoku(let sudoku) = outbound else { return "sudoku://" }
        var payload: [String: Any] = [
            "h": serverAddress,
            "p": Int(serverPort),
            "k": sudoku.key,
            "a": sudoku.asciiMode.shortLinkToken,
            "e": sudoku.aeadMethod.rawValue,
            "x": !sudoku.enablePureDownlink
        ]
        if !sudoku.customTables.isEmpty { payload["ts"] = sudoku.customTables }
        if sudoku.httpMask.disable { payload["hd"] = true }
        if sudoku.httpMask.mode != .legacy { payload["hm"] = sudoku.httpMask.mode.rawValue }
        if sudoku.httpMask.tls { payload["ht"] = true }
        if !sudoku.httpMask.host.isEmpty { payload["hh"] = sudoku.httpMask.host }
        if sudoku.httpMask.multiplex != .off { payload["hx"] = sudoku.httpMask.multiplex.rawValue }
        if !sudoku.httpMask.pathRoot.isEmpty { payload["hy"] = sudoku.httpMask.pathRoot }

        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            return "sudoku://"
        }
        return "sudoku://\(data.base64URLEncodedString())"
    }

    private func toNaiveURL() -> String {
        let scheme = outboundProtocol == .http3 ? "quic" : "https"
        let username: String?
        let password: String?
        switch outbound {
        case .http11(let u, let p), .http2(let u, let p), .http3(let u, let p):
            username = u; password = p
        default:
            username = nil; password = nil
        }
        let user = (username ?? "").addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? ""
        let pass = (password ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "\(scheme)://\(user):\(pass)@\(bracketedServerAddress):\(serverPort)#\(fragment)"
    }

    private func appendTransportParams(to params: inout [String]) {
        switch transportLayer {
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
            // Up/download detach round-trips via the `extra` blob; other advanced
            // XHTTP fields are intentionally not exported.
            if let ds = xhttp.downloadSettings, let extra = ds.urlExtraParam {
                params.append("extra=\(extra)")
            }
        case .tcp:
            break
        }
    }
}
