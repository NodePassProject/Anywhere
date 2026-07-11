//
//  TransportReclaim.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

// MARK: - TransportPool

/// Kernel tears down warm sockets across sleep/path changes; reusing a dead session stalls the dial.
/// `reclaim()` must be internally synchronized and idempotent; close sessions outside the lock.
protocol TransportPool: AnyObject {
    func reclaim()
}

// MARK: - TransportPrewarm

/// Prepares process-wide state for the default outbound before app traffic arrives.
/// The exhaustive switch keeps protocol-specific lifecycle hooks out of TunnelStack.
enum TransportPrewarm {
    static func warm(
        configuration: ProxyConfiguration,
        directDialHost: String,
        timeout: TimeInterval = 2
    ) {
        switch configuration.outboundProtocol {
        case .sudoku:
            SudokuTransportPool.warm(
                configuration: configuration,
                directDialHost: directDialHost,
                timeout: timeout
            )
        case .vless, .hysteria, .nowhere, .anytls, .http2, .http3,
             .trojan, .shadowsocks, .socks5, .http11:
            break
        }
    }
}

// MARK: - TransportReclaim

/// Switch is exhaustive with no `default` so a new protocol cannot be silently omitted.
enum TransportReclaim {

    /// Called from `lwipQueue` on device wake, network-path change, and tunnel stop.
    static func reclaimAll() {
        for proto in OutboundProtocol.allCases {
            switch proto {
            case .vless:
                VLESSEncryption0RTTCache.shared.clear()
                XHTTPXMUXMultiplexerRegistry.shared.reclaim()
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
