//
//  TransportReclaim.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

nonisolated enum TransportReclaim {

    /// Called from `lwipQueue` on device wake, network-path change, and tunnel stop.
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
            // Per-connection or instance-tier only — no process-wide warm state.
            case .trojan, .shadowsocks, .socks5, .http11:
                break
            }
        }
    }
}
