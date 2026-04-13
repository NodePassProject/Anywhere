//
//  QUICTuning.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

/// Per-protocol tuning knobs for `QUICConnection`. Covers congestion
/// control, flow-control windows, stream limits, and timeouts — everything
/// that a higher-layer protocol may want to adjust without touching
/// `QUICConnection` internals.
///
/// Use one of the static presets (e.g. `.naive`) unless you have a reason
/// to diverge.
struct QUICTuning {

    // MARK: Congestion control

    var ccAlgo: ngtcp2_cc_algo

    // MARK: Flow-control windows (receive side)

    /// Per-stream receive window ceiling (auto-tuning upper bound).
    var maxStreamWindow: UInt64
    /// Connection-level receive window ceiling (auto-tuning upper bound).
    var maxWindow: UInt64

    // MARK: Initial transport parameters (what we advertise)

    var initialMaxData: UInt64
    var initialMaxStreamDataBidiLocal: UInt64
    var initialMaxStreamDataBidiRemote: UInt64
    var initialMaxStreamDataUni: UInt64
    var initialMaxStreamsBidi: UInt64
    var initialMaxStreamsUni: UInt64

    // MARK: Timeouts (nanoseconds)

    var maxIdleTimeout: UInt64
    var handshakeTimeout: UInt64

    // MARK: Misc

    var disableActiveMigration: Bool
}

extension QUICTuning {

    /// Matches naiveproxy/Chromium defaults. CUBIC is what the upstream
    /// server stack is tuned against; BBR is a reasonable proxy-side
    /// choice but deviates from the reference implementation.
    ///
    /// Handshake timeout matches naive's `kMaxTimeForCryptoHandshakeSecs = 10`
    /// (quic_constants.h). Covers ~three PTO retransmissions (1/2/4 s)
    /// before the pool's one-shot retry kicks in — tight enough to
    /// recover from a stale PSK quickly, loose enough not to trip on
    /// high-RTT / lossy mobile paths.
    static let naive = QUICTuning(
        ccAlgo: NGTCP2_CC_ALGO_CUBIC,
        maxStreamWindow: 32 * 1024 * 1024,
        maxWindow: 96 * 1024 * 1024,
        initialMaxData: 15 * 1024 * 1024,
        initialMaxStreamDataBidiLocal: 6 * 1024 * 1024,
        initialMaxStreamDataBidiRemote: 6 * 1024 * 1024,
        initialMaxStreamDataUni: 6 * 1024 * 1024,
        initialMaxStreamsBidi: 100,
        initialMaxStreamsUni: 100,
        maxIdleTimeout: 30 * 1_000_000_000,
        handshakeTimeout: 10 * 1_000_000_000,
        disableActiveMigration: true
    )

    /// Hysteria v2. Same flow-control envelope as `.naive` — both stacks
    /// tunnel bulk TCP traffic over one QUIC connection and benefit from
    /// large windows. The reference Hysteria client advertises Brutal
    /// congestion control; we stay on CUBIC for now (Brutal is a
    /// client-side CC swap and isn't wire-signalled).
    static let hysteria = QUICTuning(
        ccAlgo: NGTCP2_CC_ALGO_CUBIC,
        maxStreamWindow: 32 * 1024 * 1024,
        maxWindow: 96 * 1024 * 1024,
        initialMaxData: 15 * 1024 * 1024,
        initialMaxStreamDataBidiLocal: 6 * 1024 * 1024,
        initialMaxStreamDataBidiRemote: 6 * 1024 * 1024,
        initialMaxStreamDataUni: 6 * 1024 * 1024,
        initialMaxStreamsBidi: 1024,
        initialMaxStreamsUni: 16,
        maxIdleTimeout: 30 * 1_000_000_000,
        handshakeTimeout: 10 * 1_000_000_000,
        disableActiveMigration: true
    )
}
