//
//  ProxyConfiguration+DictExport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

// MARK: - Dictionary Export

extension ProxyConfiguration {

    /// Serializes the configuration into the `[String: Any]` shape the Network Extension's
    /// routing layer expects, with nested `chain` hops serialized recursively.
    ///
    /// Inverse of `ProxyConfiguration.parse(from:)`.
    var serializedConfiguration: [String: Any] {
        let vlessUUID: UUID
        let vlessEncryption: String
        let vlessFlow: String?
        if case .vless(let u, let enc, let fl, _, _, _, _) = outbound {
            vlessUUID = u; vlessEncryption = enc; vlessFlow = fl
        } else {
            vlessUUID = id; vlessEncryption = "none"; vlessFlow = nil
        }
        var configurationDict: [String: Any] = [
            "name": name,
            "serverAddress": serverAddress,
            "serverPort": serverPort,
            "uuid": vlessUUID.uuidString,
            "encryption": vlessEncryption,
            "flow": vlessFlow ?? "",
            "security": securityLayer.tag,
            "muxEnabled": muxEnabled,
            "xudpEnabled": xudpEnabled,
            "outboundProtocol": outboundProtocol.rawValue,
        ]

        switch outbound {
        case .vless: break
        case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let portHopping, let sni):
            configurationDict["hysteriaPassword"] = password
            configurationDict["hysteriaCongestionControl"] = congestionControl.rawValue
            configurationDict["hysteriaUploadMbps"] = uploadMbps
            configurationDict["hysteriaDownloadMbps"] = downloadMbps
            if let portHopping {
                configurationDict["hysteriaPorts"] = portHopping.portsSpec
                configurationDict["hysteriaHopInterval"] = portHopping.intervalSeconds
            }
            configurationDict["hysteriaSNI"] = sni
        case .nowhere(let key, let spec, let tls):
            configurationDict["nowhereKey"] = key
            if let spec, !spec.isEmpty {
                configurationDict["nowhereSpec"] = spec
            }
            configurationDict["nowhereSNI"] = tls.serverName
            if let alpn = tls.alpn?.first, !alpn.isEmpty {
                configurationDict["nowhereALPN"] = alpn
            }
            if let ech = tls.echConfig { configurationDict["nowhereEch"] = ech }
        case .trojan(let password, let tls):
            configurationDict["trojanPassword"] = password
            configurationDict["trojanSNI"] = tls.serverName
            if let alpn = tls.alpn, !alpn.isEmpty {
                configurationDict["trojanALPN"] = alpn.joined(separator: ",")
            }
            configurationDict["trojanFingerprint"] = tls.fingerprint.rawValue
            if let ech = tls.echConfig { configurationDict["trojanEch"] = ech }
        case .anytls(let password, let ici, let it, let mis, let tls):
            configurationDict["anytlsPassword"] = password
            configurationDict["anytlsIdleCheckInterval"] = ici
            configurationDict["anytlsIdleTimeout"] = it
            configurationDict["anytlsMinIdleSession"] = mis
            configurationDict["anytlsSNI"] = tls.serverName
            if let alpn = tls.alpn, !alpn.isEmpty {
                configurationDict["anytlsALPN"] = alpn.joined(separator: ",")
            }
            configurationDict["anytlsFingerprint"] = tls.fingerprint.rawValue
            if let ech = tls.echConfig { configurationDict["anytlsEch"] = ech }
        case .shadowsocks(let password, let method):
            configurationDict["ssPassword"] = password
            configurationDict["ssMethod"] = method
        case .socks5(let username, let password):
            if let username { configurationDict["socks5Username"] = username }
            if let password { configurationDict["socks5Password"] = password }
        case .sudoku(let sudoku):
            configurationDict["sudokuKey"] = sudoku.key
            configurationDict["sudokuAEADMethod"] = sudoku.aeadMethod.rawValue
            configurationDict["sudokuPaddingMin"] = sudoku.paddingMin
            configurationDict["sudokuPaddingMax"] = sudoku.paddingMax
            configurationDict["sudokuASCIIMode"] = sudoku.asciiMode.rawValue
            configurationDict["sudokuCustomTables"] = sudoku.customTables
            configurationDict["sudokuEnablePureDownlink"] = sudoku.enablePureDownlink
            configurationDict["sudokuHTTPMaskDisable"] = sudoku.httpMask.disable
            configurationDict["sudokuHTTPMaskMode"] = sudoku.httpMask.mode.rawValue
            configurationDict["sudokuHTTPMaskTLS"] = sudoku.httpMask.tls
            configurationDict["sudokuHTTPMaskHost"] = sudoku.httpMask.host
            configurationDict["sudokuHTTPMaskPathRoot"] = sudoku.httpMask.pathRoot
            configurationDict["sudokuHTTPMaskMultiplex"] = sudoku.httpMask.multiplex.rawValue
        case .http11(let username, let password):
            configurationDict["http11Username"] = username
            configurationDict["http11Password"] = password
        case .http2(let username, let password):
            configurationDict["http2Username"] = username
            configurationDict["http2Password"] = password
        case .http3(let username, let password):
            configurationDict["http3Username"] = username
            configurationDict["http3Password"] = password
        }

        if case .reality(let reality) = securityLayer {
            configurationDict["realityServerName"] = reality.serverName
            configurationDict["realityPublicKey"] = reality.publicKey.base64EncodedString()
            configurationDict["realityShortId"] = reality.shortId.map { String(format: "%02x", $0) }.joined()
            configurationDict["realityFingerprint"] = reality.fingerprint.rawValue
        }

        if case .tls(let tls) = securityLayer {
            configurationDict["tlsServerName"] = tls.serverName
            if let alpn = tls.alpn {
                configurationDict["tlsAlpn"] = alpn.joined(separator: ",")
            }
            configurationDict["tlsFingerprint"] = tls.fingerprint.rawValue
            if let ech = tls.echConfig { configurationDict["tlsEch"] = ech }
        }

        if outboundProtocol == .vless {
            configurationDict["transport"] = transportLayer.tag
            if case .ws(let ws) = transportLayer {
                configurationDict["wsHost"] = ws.host
                configurationDict["wsPath"] = ws.path
                if !ws.headers.isEmpty {
                    configurationDict["wsHeaders"] = ws.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
                configurationDict["wsMaxEarlyData"] = ws.maxEarlyData
                configurationDict["wsEarlyDataHeaderName"] = ws.earlyDataHeaderName
            }

            if case .httpUpgrade(let hu) = transportLayer {
                configurationDict["huHost"] = hu.host
                configurationDict["huPath"] = hu.path
                if !hu.headers.isEmpty {
                    configurationDict["huHeaders"] = hu.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
            }

            if case .grpc(let grpc) = transportLayer {
                configurationDict["grpcServiceName"] = grpc.serviceName
                configurationDict["grpcAuthority"] = grpc.authority
                configurationDict["grpcMultiMode"] = grpc.multiMode
                configurationDict["grpcUserAgent"] = grpc.userAgent
                configurationDict["grpcInitialWindowsSize"] = grpc.initialWindowsSize
                configurationDict["grpcIdleTimeout"] = grpc.idleTimeout
                configurationDict["grpcHealthCheckTimeout"] = grpc.healthCheckTimeout
                configurationDict["grpcPermitWithoutStream"] = grpc.permitWithoutStream
            }

            if case .xhttp(let xhttp) = transportLayer {
                configurationDict["xhttpHost"] = xhttp.host
                configurationDict["xhttpPath"] = xhttp.path
                configurationDict["xhttpMode"] = xhttp.mode.rawValue
                if !xhttp.headers.isEmpty {
                    configurationDict["xhttpHeaders"] = xhttp.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
                configurationDict["xhttpNoGRPCHeader"] = xhttp.noGRPCHeader
                // Carry downloadSettings as one JSON value (lossless) rather than flattening each field.
                if let ds = xhttp.downloadSettings,
                   let data = try? JSONEncoder().encode(ds),
                   let json = String(data: data, encoding: .utf8) {
                    configurationDict["xhttpDownloadSettings"] = json
                }
            }
        }

        if let chain, !chain.isEmpty {
            configurationDict["chain"] = chain.map { $0.serializedConfiguration }
        }

        return configurationDict
    }
}
