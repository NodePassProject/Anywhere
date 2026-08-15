//
//  TransportReclaim.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

nonisolated enum TransportReclaim {
    static func reclaimAll() {
        for proto in OutboundProtocol.allCases {
            switch proto {
            case .nowhere:  NowhereClient.pool.reclaim()
            case .vless:
                VLESSEncryption0RTTCache.shared.clear()
                XHTTPXMUXMultiplexerRegistry.shared.reclaim()
            case .hysteria: HysteriaClient.pool.reclaim()
            case .anytls:   AnyTLSMultiplexerRegistry.shared.reclaim()
            case .sudoku:   SudokuMultiplexerRegistry.shared.reclaim()
            case .http2:    NaiveHTTP2MultiplexerPool.shared.reclaim()
            case .http3:    NaiveHTTP3MultiplexerPool.shared.reclaim()
            case .trojan, .shadowsocks, .socks5, .http11:
                break
            }
        }
    }
    
    static func sealAll() {
        AnyTLSMultiplexerRegistry.shared.seal()
        SudokuMultiplexerRegistry.shared.seal()
    }

    static func unsealAll() {
        AnyTLSMultiplexerRegistry.shared.unseal()
        SudokuMultiplexerRegistry.shared.unseal()
    }
}
