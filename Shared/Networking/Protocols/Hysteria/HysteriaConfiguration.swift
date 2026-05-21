//
//  HysteriaConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation

/// Configuration for a Hysteria v2 session.
struct HysteriaConfiguration {
    let proxyHost: String
    let proxyPort: UInt16
    /// Authentication password (sent in the `Hysteria-Auth` header).
    let password: String
    /// TLS SNI sent on the wire. Always populated — callers default to
    /// `proxyHost` when there is no explicit override.
    let sni: String
    /// Selected congestion controller. `.brutal` paces each direction at the
    /// configured rate; `.bbr` adapts and asks the server to detect bandwidth.
    let congestionControl: HysteriaCongestionControl

    /// Client-declared upload bandwidth in Mbit/s. Drives the initial Brutal
    /// target rate (before the server's CC-RX is known) and the post-auth
    /// `min(server_rx, client_max_tx)` cap. Ignored under `.bbr`.
    let uploadMbps: Int

    /// Client-declared download bandwidth in Mbit/s. Advertised to the server
    /// so it can pace our downlink under Brutal. Ignored under `.bbr`.
    let downloadMbps: Int

    /// Upload bandwidth in bytes/sec — the unit Brutal uses internally.
    var uploadBytesPerSec: UInt64 {
        UInt64(max(0, uploadMbps)) * 1_000_000 / 8
    }

    /// Download bandwidth in bytes/sec.
    var downloadBytesPerSec: UInt64 {
        UInt64(max(0, downloadMbps)) * 1_000_000 / 8
    }

    /// Value advertised in the `Hysteria-CC-RX` request header (bytes/sec).
    /// Under Brutal this is the configured download rate, so the server paces
    /// our downlink; `0` (BBR, or a download of 0) asks the server to run its
    /// own bandwidth detection.
    var clientRxBytesPerSec: UInt64 {
        congestionControl == .brutal ? downloadBytesPerSec : 0
    }
}
