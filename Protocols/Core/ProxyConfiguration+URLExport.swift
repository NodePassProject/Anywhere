//
//  ProxyConfiguration+URLExport.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - URL Export

extension ProxyConfiguration {

    /// RFC 3986 §3.2.2: IPv6 literals must be bracketed in URL authority components.
    private var bracketedServerAddress: String {
        serverAddress.contains(":") ? "[\(serverAddress)]" : serverAddress
    }

    /// Export configuration as a shareable URL string.
    /// Produces `vless://...` for VLESS or `ss://...` for Shadowsocks.
    func toURL() -> String {
        switch outboundProtocol {
        case .vless:
            return toVLESSURL()
        case .hysteria:
            return toHysteriaURL()
        case .trojan:
            return toTrojanURL()
        case .shadowsocks:
            return toShadowsocksURL()
        case .socks5:
            return toSOCKS5URL()
        case .http11, .http2, .http3:
            return toNaiveURL()
        }
    }

    private func toVLESSURL() -> String {
        var params: [String] = []

        if encryption != "none" {
            params.append("encryption=\(encryption)")
        }
        if let flow, !flow.isEmpty {
            params.append("flow=\(flow)")
        }
        params.append("security=\(security)")
        if transport != "tcp" {
            params.append("type=\(transport)")
        }
        
        if security == "tls", let tls {
            if tls.serverName != serverAddress {
                params.append("sni=\(tls.serverName)")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                params.append("alpn=\(alpn.joined(separator: ",").addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? alpn.joined(separator: ","))")
            }
            if tls.fingerprint != .chrome120 {
                params.append("fp=\(tls.fingerprint.rawValue)")
            }
        }
        
        if security == "reality", let reality {
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
        let password = (hysteriaPassword ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var params: [String] = []
        // SNI is always populated; only emit when it differs from the server
        // address to keep share links short.
        if let sni = hysteriaSNI, sni != serverAddress {
            params.append("sni=\(sni)")
        }
        if let mbps = hysteriaUploadMbps, mbps != HysteriaUploadMbpsDefault {
            params.append("upmbps=\(mbps)")
        }
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "hysteria2://\(password)@\(bracketedServerAddress):\(serverPort)/\(query)#\(fragment)"
    }

    private func toTrojanURL() -> String {
        let password = (trojanPassword ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        var params: [String] = []
        if let tls = trojanTLS {
            if tls.serverName != serverAddress {
                params.append("sni=\(tls.serverName)")
            }
            if let alpn = tls.alpn, !alpn.isEmpty {
                let joined = alpn.joined(separator: ",")
                params.append("alpn=\(joined.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? joined)")
            }
            if tls.fingerprint != .chrome133 {
                params.append("fp=\(tls.fingerprint.rawValue)")
            }
        }
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "trojan://\(password)@\(bracketedServerAddress):\(serverPort)\(query)#\(fragment)"
    }

    private func toShadowsocksURL() -> String {
        guard let method = ssMethod, let password = ssPassword else {
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
        if let user = socks5Username, !user.isEmpty {
            let encodedUser = user.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? user
            let encodedPass = (socks5Password ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
            return "socks5://\(encodedUser):\(encodedPass)@\(bracketedServerAddress):\(serverPort)#\(fragment)"
        }
        return "socks5://\(bracketedServerAddress):\(serverPort)#\(fragment)"
    }

    private func toNaiveURL() -> String {
        let scheme = outboundProtocol == .http3 ? "quic" : "https"
        let user = (activeUsername ?? "").addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? ""
        let pass = (activePassword ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "\(scheme)://\(user):\(pass)@\(bracketedServerAddress):\(serverPort)#\(fragment)"
    }

    private func appendTransportParams(to params: inout [String]) {
        if let ws = websocket, transport == "ws" {
            if ws.host != serverAddress {
                params.append("host=\(ws.host)")
            }
            if ws.path != "/" {
                params.append("path=\(ws.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ws.path)")
            }
            if ws.maxEarlyData > 0 {
                params.append("ed=\(ws.maxEarlyData)")
            }
        }
        if let hu = httpUpgrade, transport == "httpupgrade" {
            if hu.host != serverAddress {
                params.append("host=\(hu.host)")
            }
            if hu.path != "/" {
                params.append("path=\(hu.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? hu.path)")
            }
        }
        if let grpc, transport == "grpc" {
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
        }
        if let xhttp, transport == "xhttp" {
            if xhttp.host != serverAddress {
                params.append("host=\(xhttp.host)")
            }
            if xhttp.path != "/" {
                params.append("path=\(xhttp.path.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? xhttp.path)")
            }
            if xhttp.mode != .auto {
                params.append("mode=\(xhttp.mode.rawValue)")
            }
        }
    }
}
