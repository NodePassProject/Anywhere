//
//  QUICTuning.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation

/// Per-protocol tuning knobs for `QUICConnection`.
struct QUICTuning {

    // MARK: Congestion control

    /// ngtcp2-native algorithms pass through unchanged; `.brutal` initializes ngtcp2
    /// with CUBIC and then swaps `conn->cc`'s callbacks for the Swift Brutal implementation.
    enum CongestionControl {
        case reno
        case cubic
        case bbr
        /// Hysteria Brutal CC with an initial target send rate (bytes/sec),
        /// typically updated post-auth from the server's Hysteria-CC-RX.
        case brutal(initialBps: UInt64)
    }

    var cc: CongestionControl

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

    /// Naive (HTTP/3 CONNECT) preset: CUBIC matches the Naive server stack; windows target
    /// 2× BDP for 125 Mbps × 256 ms links, with a 16 MB initial stream window so the first RTT
    /// can fill a high-BDP pipe; 10 s handshake ≈ three PTOs before the pool's one-shot retry.
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

    /// Brutal windows are deliberately small — ~2× the proxied stream's `TCP_SND_BUF` (≈696 KB)
    /// prevents burst-then-stall without capping throughput — and `max == initial` disables
    /// ngtcp2's window auto-tuner. BBR paces from its own estimate, so its windows may auto-scale
    /// (`max > initial`).
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

    static let nowhere = QUICTuning(
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
