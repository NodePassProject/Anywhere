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

    /// Which congestion controller `QUICConnection` should run.
    ///
    /// The three ngtcp2-native algorithms are passed through unchanged.
    /// `.brutal` keeps ngtcp2 initialized with CUBIC (for a valid fallback
    /// state) and then replaces `conn->cc`'s callbacks with our Swift
    /// Brutal implementation — no ngtcp2 source changes.
    enum CongestionControl {
        case reno
        case cubic
        case bbr
        /// Hysteria Brutal CC with an initial target send rate (bytes/sec).
        /// The rate is typically updated post-auth once the server's
        /// Hysteria-CC-RX is known.
        case brutal(initialBps: UInt64)
    }

    var cc: CongestionControl

    /// Underlying ngtcp2 algo enum used to initialize `ngtcp2_conn`. For
    /// `.brutal` we init with CUBIC and overlay Brutal callbacks after.
    var ngtcp2CCAlgo: ngtcp2_cc_algo {
        switch cc {
        case .reno:    return NGTCP2_CC_ALGO_RENO
        case .cubic:   return NGTCP2_CC_ALGO_CUBIC
        case .bbr:     return NGTCP2_CC_ALGO_BBR
        case .brutal:  return NGTCP2_CC_ALGO_CUBIC
        }
    }

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
    /// Idle period after which ngtcp2 emits a PING to keep the path alive.
    var keepAliveTimeout: UInt64

    // MARK: Misc

    var disableActiveMigration: Bool
}

extension QUICTuning {

    /// Matches naiveproxy/Chromium defaults. CUBIC is what the upstream
    /// server stack is tuned against; BBR is a reasonable proxy-side
    /// choice but deviates from the reference implementation.
    ///
    /// Flow-control windows are sized after upstream naiveproxy
    /// (`naive_proxy_bin.cc`): 64 MB stream / 128 MB connection, the
    /// 2× BDP target for 125 Mbps × 256 ms links. Initial per-stream
    /// window is bumped to 16 MB so the first RTT after CONNECT can
    /// fill a high-BDP pipe before the ngtcp2 auto-scaler ramps.
    ///
    /// Handshake timeout matches naive's `kMaxTimeForCryptoHandshakeSecs = 10`
    /// (quic_constants.h). Covers ~three PTO retransmissions (1/2/4 s)
    /// before the pool's one-shot retry kicks in — tight enough to
    /// recover from a stale PSK quickly, loose enough not to trip on
    /// high-RTT / lossy mobile paths.
    static let naive = QUICTuning(
        cc: .cubic,
        maxStreamWindow: 64 * 1024 * 1024,
        maxWindow: 128 * 1024 * 1024,
        initialMaxData: 64 * 1024 * 1024,
        initialMaxStreamDataBidiLocal: 16 * 1024 * 1024,
        initialMaxStreamDataBidiRemote: 16 * 1024 * 1024,
        initialMaxStreamDataUni: 16 * 1024 * 1024,
        initialMaxStreamsBidi: 1024,
        initialMaxStreamsUni: 100,
        maxIdleTimeout: 30 * 1_000_000_000,
        handshakeTimeout: 10 * 1_000_000_000,
        keepAliveTimeout: 15 * 1_000_000_000,
        disableActiveMigration: true
    )

    /// Hysteria v2 runs Brutal congestion control with a user-configured
    /// upload rate (Mbit/s). The rate applies from the moment the QUIC
    /// connection opens; `HysteriaSession` replaces it with
    /// `min(server_rx, client_max_tx)` once the auth response lands.
    ///
    /// Flow-control windows are smaller than the reference Hysteria client
    /// (`core/client/config.go` uses 8 MB/20 MB). Each QUIC stream proxies
    /// a TCP connection with `TCP_SND_BUF ≈ 696 KB`. When the server's
    /// stream credit dwarfs `TCP_SND_BUF`, Brutal dumps 8 MB into our side
    /// in milliseconds and then sits stalled behind `snd_buf=0` waiting for
    /// iOS client ACKs. Matching the stream window to roughly 2× `TCP_SND_BUF`
    /// keeps the server paced to what the downstream TCP can actually absorb,
    /// eliminating the "burst-then-stall" pattern without capping throughput
    /// (Brutal sends at a fixed rate with no window-driven backoff, so a
    /// smaller window doesn't reduce steady-state goodput).
    ///
    /// `max == initial` disables ngtcp2's receive-window auto-tuner, so the
    /// values here are also the effective ceiling.
    static func hysteria(uploadMbps: Int) -> QUICTuning {
        let bps = UInt64(uploadMbps) * 1_000_000 / 8
        return QUICTuning(
            cc: .brutal(initialBps: bps),
            maxStreamWindow: 2 * 1024 * 1024,
            maxWindow: 4 * 1024 * 1024,
            initialMaxData: 4 * 1024 * 1024,
            initialMaxStreamDataBidiLocal: 2 * 1024 * 1024,
            initialMaxStreamDataBidiRemote: 2 * 1024 * 1024,
            initialMaxStreamDataUni: 2 * 1024 * 1024,
            initialMaxStreamsBidi: 1024,
            initialMaxStreamsUni: 16,
            maxIdleTimeout: 30 * 1_000_000_000,
            handshakeTimeout: 10 * 1_000_000_000,
            keepAliveTimeout: 10 * 1_000_000_000,
            disableActiveMigration: true
        )
    }
}
