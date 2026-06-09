//
//  TransportReclaim.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

// MARK: - TransportPool

/// A process-wide cache of warm upstream transports — QUIC / TLS / HTTP-2 /
/// HTTP-3 / mux sessions that outlive individual connections and survive tunnel
/// restarts. The kernel tears down their sockets across sleep and network-path
/// changes, so the tunnel lifecycle must reclaim them on wake, path change, and
/// stop; otherwise the first post-event dial reuses a dead session and stalls
/// until an internal idle timeout fires.
///
/// Conformance is the standardized teardown contract every such cache adopts.
/// ``reclaim()`` is invoked from `lwipQueue` (see ``TransportReclaim/reclaimAll()``),
/// so implementations must be:
///
/// - **internally synchronized** — callable from any queue, taking their own
///   lock — and
/// - **idempotent** — safe when already empty, and safe to call repeatedly
///   (wake, then an immediate path change, then stop).
///
/// Reclaim should snapshot its cache under the lock and close the drained
/// sessions *outside* it, so teardown never blocks while holding the lock.
protocol TransportPool: AnyObject {
    /// Closes every cached session and empties the cache.
    func reclaim()
}

// MARK: - TransportReclaim

/// The single audit point for tearing down every protocol's process-wide warm
/// transports.
///
/// The `switch` is exhaustive over ``OutboundProtocol`` with no `default`: a new
/// protocol will not compile until its author names the warm cache here — or
/// adds the case to the no-cache group to *assert* it keeps none. This is the
/// same forcing function the other per-protocol switches already use (`name`,
/// `handshakeCarriesInitialData`, `upstreamCommand`), and it keeps the teardown
/// set auditable in one place: a reviewer can confirm that everything holding a
/// socket is released on a network change by reading this one function. We
/// accept that the protocol list is restated here (it also appears in those
/// switches) — exhaustiveness makes the compiler keep the copies in sync, so the
/// duplication carries no drift risk, only the clarity of an explicit list.
///
/// Per-tunnel transports owned by the running ``TunnelStack`` (the Vision mux,
/// Shadowsocks UDP sessions, and per-flow UDP state) are *not* process-wide and
/// are reclaimed separately by `TunnelStack.reclaimInstanceTransports(rebuildMux:)`.
enum TransportReclaim {

    /// Reclaims every protocol's process-wide warm transports. Called from
    /// `lwipQueue` on device wake, network-path change, and tunnel stop. Each
    /// pool self-synchronizes and is idempotent (see ``TransportPool``), so the
    /// order below is irrelevant and a pool with nothing cached is a no-op.
    static func reclaimAll() {
        for proto in OutboundProtocol.allCases {
            switch proto {
            case .hysteria: HysteriaClient.pool.reclaim()
            case .nowhere:  NowhereClient.pool.reclaim()
            case .anytls:   AnyTLSManager.shared.reclaim()
            case .http2:    HTTP2SessionPool.shared.reclaim()
            case .http3:    HTTP3SessionPool.shared.reclaim()
            case .sudoku:   SudokuTransportPool.pool.reclaim()
            // Per-connection or instance-tier only — no process-wide warm cache.
            case .vless, .trojan, .shadowsocks, .socks5, .http11:
                break
            }
        }
    }
}
