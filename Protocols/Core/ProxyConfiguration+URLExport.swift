//
//  ProxyConfiguration+URLExport.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - URL Export

extension ProxyConfiguration {

    /// Export configuration as a shareable URL string.
    /// Produces `vless://...` for VLESS or `ss://...` for Shadowsocks.
    func toURL() -> String {
        switch outboundProtocol {
        case .shadowsocks:
            return toShadowsocksURL()
        case .vless:
            return toVLESSURL()
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

        // TLS parameters
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

        // Reality parameters
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

        // Transport parameters
        appendTransportParams(to: &params)

        // Mux/XUDP
        if !muxEnabled {
            params.append("mux=false")
        }
        if !xudpEnabled {
            params.append("xudp=false")
        }

        // Testseed (only if non-default)
        if testseed != [900, 500, 900, 256] {
            params.append("testseed=\(testseed.map { String($0) }.joined(separator: ","))")
        }

        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "vless://\(uuid.uuidString.lowercased())@\(serverAddress):\(serverPort)/\(query)#\(fragment)"
    }

    private func toShadowsocksURL() -> String {
        guard let method = ssMethod, let password = ssPassword else {
            return "ss://invalid"
        }
        let userInfo = "\(method):\(password)"
        let encoded = Data(userInfo.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        var params: [String] = []
        if transport != "tcp" {
            params.append("type=\(transport)")
        }
        if security != "none" {
            params.append("security=\(security)")
        }

        // TLS parameters
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

        // Transport parameters
        appendTransportParams(to: &params)

        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "ss://\(encoded)@\(serverAddress):\(serverPort)/\(query)#\(fragment)"
    }

    private func toNaiveURL() -> String {
        let scheme = outboundProtocol == .http3 ? "quic" : "https"
        let user = (activeUsername ?? "").addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? ""
        let pass = (activePassword ?? "").addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? ""
        let fragment = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        return "\(scheme)://\(user):\(pass)@\(serverAddress):\(serverPort)#\(fragment)"
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
