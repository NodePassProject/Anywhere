//
//  QUICTuning.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
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

    /// Tuning preset for the Naive (HTTP/3 CONNECT) transport. CUBIC is the
    /// congestion controller the Naive server stack is tuned against; BBR is
    /// a reasonable proxy-side alternative but is left off by default.
    ///
    /// Flow-control windows target 2× BDP for 125 Mbps × 256 ms links:
    /// 64 MB stream / 128 MB connection. The initial per-stream window is
    /// bumped to 16 MB so the first RTT after CONNECT can fill a high-BDP
    /// pipe before the ngtcp2 auto-scaler ramps.
    ///
    /// The 10 s handshake timeout covers ~three PTO retransmissions
    /// (1/2/4 s) before the pool's one-shot retry kicks in — tight enough to
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

    /// Hysteria v2 runs over QUIC with a user-selectable congestion controller.
    ///
    /// `.brutal` paces uploads at a user-configured rate (replaced post-auth
    /// with `min(server_rx, client_max_tx)`). Its flow-control windows are
    /// deliberately small: each QUIC stream proxies a TCP connection with
    /// `TCP_SND_BUF ≈ 696 KB`, so when the server's stream credit dwarfs that,
    /// Brutal dumps several MB into our side in milliseconds and then sits
    /// stalled behind `snd_buf=0` waiting for iOS client ACKs. Sizing the
    /// stream window to roughly 2× `TCP_SND_BUF` keeps the server paced to what
    /// the downstream TCP can actually absorb, eliminating the "burst-then-stall"
    /// pattern without capping throughput (Brutal sends at a fixed rate with no
    /// window-driven backoff). `max == initial` disables ngtcp2's receive-window
    /// auto-tuner, so those values are also the effective ceiling.
    ///
    /// `.bbr` paces from ngtcp2's own bandwidth estimate, so it needs room to
    /// grow: the windows start small but let the auto-tuner scale up to a
    /// high-BDP ceiling (`max > initial`).
    static func hysteria(congestionControl: HysteriaCongestionControl, uploadMbps: Int) -> QUICTuning {
        switch congestionControl {
        case .brutal:
            let bps = UInt64(max(0, uploadMbps)) * 1_000_000 / 8
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
        case .bbr:
            return QUICTuning(
                cc: .bbr,
                maxStreamWindow: 16 * 1024 * 1024,
                maxWindow: 32 * 1024 * 1024,
                initialMaxData: 8 * 1024 * 1024,
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
}
