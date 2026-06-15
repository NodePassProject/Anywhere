//
//  TransportReclaim.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

// MARK: - TransportPool

/// Process-wide cache of warm upstream transports; the kernel tears down their
/// sockets across sleep/path changes, and reusing a dead session stalls the dial.
/// `reclaim()` must be internally synchronized and idempotent; close sessions outside the lock.
protocol TransportPool: AnyObject {
    func reclaim()
}

// MARK: - TransportReclaim

/// Single audit point for tearing down every protocol's process-wide warm transports.
/// The switch is exhaustive with no `default` so a new protocol cannot be silently omitted.
enum TransportReclaim {

    /// Called from `lwipQueue` on device wake, network-path change, and tunnel stop.
    static func reclaimAll() {
        for proto in OutboundProtocol.allCases {
            switch proto {
            case .vless:    VLESSEncryption0RTTCache.shared.clear()
            case .hysteria: HysteriaClient.pool.reclaim()
            case .nowhere:  NowhereClient.pool.reclaim()
            case .anytls:   AnyTLSMultiplexerRegistry.shared.reclaim()
            case .sudoku:   SudokuTransportPool.pool.reclaim()
            case .http2:    NaiveHTTP2MultiplexerPool.shared.reclaim()
            case .http3:    NaiveHTTP3MultiplexerPool.shared.reclaim()
            // Per-connection or instance-tier only — no process-wide warm state.
            case .trojan, .shadowsocks, .socks5, .http11:
                break
            }
        }
    }
}
