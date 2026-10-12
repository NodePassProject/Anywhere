//
//  ProxyConfiguration+LegacyDecoding.swift
//  Anywhere
//
//  Created by NodePassProject on 9/13/26.
//

import Foundation

// MARK: Remove in future build

nonisolated extension Outbound {
    private enum LegacyCodingKeys: String, CodingKey {
        case serverPort
        case outboundProtocol
        case hysteriaPassword, hysteriaCongestionControl, hysteriaUploadMbps, hysteriaDownloadMbps
        case hysteriaObfs, hysteriaObfsPassword, hysteriaObfsMinPacketSize, hysteriaObfsMaxPacketSize
        case hysteriaSNI
        case sudoku
        case trojanPassword, trojanTLS
        case anytlsPassword, anytlsIdleCheckInterval, anytlsIdleTimeout, anytlsMinIdleSession, anytlsTLS
        case ssPassword, ssMethod
        case socks5Username, socks5Password
        case rfcUsername, rfcPassword, rfcSecurity, rfcTLS
    }

    init(legacyFrom decoder: Decoder, serverAddress: String, serverPort: UInt16) throws {
        let container = try decoder.container(keyedBy: LegacyCodingKeys.self)
        
        let `protocol` = try container.decodeIfPresent(OutboundProtocol.self, forKey: .outboundProtocol) ?? .vless

        switch `protocol` {
        case .nowhere:
            throw DecodingError.dataCorruptedError(
                forKey: .outboundProtocol,
                in: container,
                debugDescription: "Unsupported Nowhere configuration"
            )

        case .vless:
            self = .vless(try VLESSConfiguration(from: decoder))

        case .hysteria:
            let explicitSNI = try container.decodeIfPresent(String.self, forKey: .hysteriaSNI)
            self = .hysteria(HysteriaConfiguration(
                password: try container.decodeIfPresent(String.self, forKey: .hysteriaPassword) ?? "",
                congestionControl: try container.decodeIfPresent(HysteriaCongestionControl.self, forKey: .hysteriaCongestionControl) ?? .brutal,
                uploadMbps: try container.decodeIfPresent(Int.self, forKey: .hysteriaUploadMbps)
                    ?? HysteriaCongestionControl.uploadMbpsDefault,
                downloadMbps: try container.decodeIfPresent(Int.self, forKey: .hysteriaDownloadMbps)
                    ?? HysteriaCongestionControl.downloadMbpsDefault,
                obfuscation: HysteriaObfuscation.make(
                    type: try container.decodeIfPresent(String.self, forKey: .hysteriaObfs),
                    password: try container.decodeIfPresent(String.self, forKey: .hysteriaObfsPassword),
                    geckoMinPacketSize: try container.decodeIfPresent(Int.self, forKey: .hysteriaObfsMinPacketSize),
                    geckoMaxPacketSize: try container.decodeIfPresent(Int.self, forKey: .hysteriaObfsMaxPacketSize)
                ),
                serverName: (explicitSNI?.isEmpty == false ? explicitSNI! : serverAddress)
            ))

        case .sudoku:
            self = .sudoku(try container.decode(SudokuConfiguration.self, forKey: .sudoku))

        case .trojan:
            self = .trojan(TrojanConfiguration(
                password: try container.decodeIfPresent(String.self, forKey: .trojanPassword) ?? "",
                tls: try container.decodeIfPresent(TLSConfiguration.self, forKey: .trojanTLS)
                    ?? TLSConfiguration(serverName: serverAddress)
            ))

        case .anytls:
            let tlsConfiguration = try container.decodeIfPresent(TLSConfiguration.self, forKey: .anytlsTLS)
                ?? TLSConfiguration(serverName: serverAddress)
            self = .anytls(AnyTLSConfiguration(
                password: try container.decodeIfPresent(String.self, forKey: .anytlsPassword) ?? "",
                idleCheckInterval: try container.decodeIfPresent(Int.self, forKey: .anytlsIdleCheckInterval)
                    ?? AnyTLSConfiguration.defaultIdleCheckInterval,
                idleTimeout: try container.decodeIfPresent(Int.self, forKey: .anytlsIdleTimeout)
                    ?? AnyTLSConfiguration.defaultIdleTimeout,
                minIdleSession: try container.decodeIfPresent(Int.self, forKey: .anytlsMinIdleSession)
                    ?? AnyTLSConfiguration.defaultMinIdleSession,
                securityLayer: .tls(tlsConfiguration)
            ))

        case .shadowsocks:
            self = .shadowsocks(ShadowsocksConfiguration(
                password: try container.decodeIfPresent(String.self, forKey: .ssPassword) ?? "",
                method: try container.decodeIfPresent(String.self, forKey: .ssMethod) ?? ""
            ))

        case .socks5:
            self = .socks5(SOCKS5Configuration(
                username: try container.decodeIfPresent(String.self, forKey: .socks5Username),
                password: try container.decodeIfPresent(String.self, forKey: .socks5Password)
            ))

        case .rfc:
            let securityTag = try container.decodeIfPresent(String.self, forKey: .rfcSecurity) ?? "tls"
            let securityLayer: GenericSecurityLayer
            if securityTag == "none" {
                securityLayer = .none
            } else {
                securityLayer = .tls(
                    try container.decodeIfPresent(TLSConfiguration.self, forKey: .rfcTLS)
                        ?? TLSConfiguration(serverName: serverAddress, alpn: RFCProtocol.defaultALPN)
                )
            }
            self = .rfc(RFCConfiguration(
                username: try container.decodeIfPresent(String.self, forKey: .rfcUsername),
                password: try container.decodeIfPresent(String.self, forKey: .rfcPassword),
                securityLayer: securityLayer
            ))
        }
    }
    
}

nonisolated extension ProxyConfiguration {
    static func legacyPayloadIDs(in payloads: [Data]) -> Set<UUID> {
        var ids: Set<UUID> = []
        for payload in payloads {
            guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
                  object["outbound"] == nil,
                  let id = (object["id"] as? String).flatMap(UUID.init(uuidString:))
            else { continue }
            ids.insert(id)
        }
        return ids
    }
}
