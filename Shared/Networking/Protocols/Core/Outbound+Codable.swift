//
//  Outbound+Codable.swift
//  Anywhere
//
//  Created by NodePassProject on 9/13/26.
//

import Foundation

nonisolated extension Outbound: Codable {
    private enum CodingKeys: String, CodingKey {
        case `protocol`
        case nowhere, vless, hysteria, sudoku, trojan, anytls, shadowsocks, socks5, rfc, direct
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        switch try container.decode(OutboundProtocol.self, forKey: .protocol) {
        case .nowhere:
            self = .nowhere(try container.decode(NowhereConfiguration.self, forKey: .nowhere))
        case .vless:
            self = .vless(try container.decode(VLESSConfiguration.self, forKey: .vless))
        case .hysteria:
            self = .hysteria(try container.decode(HysteriaConfiguration.self, forKey: .hysteria))
        case .sudoku:
            self = .sudoku(try container.decode(SudokuConfiguration.self, forKey: .sudoku))
        case .trojan:
            self = .trojan(try container.decode(TrojanConfiguration.self, forKey: .trojan))
        case .anytls:
            self = .anytls(try container.decode(AnyTLSConfiguration.self, forKey: .anytls))
        case .shadowsocks:
            self = .shadowsocks(try container.decode(ShadowsocksConfiguration.self, forKey: .shadowsocks))
        case .socks5:
            self = .socks5(try container.decode(SOCKS5Configuration.self, forKey: .socks5))
        case .rfc:
            self = .rfc(try container.decode(RFCConfiguration.self, forKey: .rfc))
        case .direct:
            self = .direct(try container.decodeIfPresent(DirectConfiguration.self, forKey: .direct) ?? DirectConfiguration())
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(outboundProtocol, forKey: .protocol)

        switch self {
        case .nowhere(let configuration):
            try container.encode(configuration, forKey: .nowhere)
        case .vless(let configuration):
            try container.encode(configuration, forKey: .vless)
        case .hysteria(let configuration):
            try container.encode(configuration, forKey: .hysteria)
        case .sudoku(let configuration):
            try container.encode(configuration, forKey: .sudoku)
        case .trojan(let configuration):
            try container.encode(configuration, forKey: .trojan)
        case .anytls(let configuration):
            try container.encode(configuration, forKey: .anytls)
        case .shadowsocks(let configuration):
            try container.encode(configuration, forKey: .shadowsocks)
        case .socks5(let configuration):
            try container.encode(configuration, forKey: .socks5)
        case .rfc(let configuration):
            try container.encode(configuration, forKey: .rfc)
        case .direct(let configuration):
            try container.encode(configuration, forKey: .direct)
        }
    }
}
