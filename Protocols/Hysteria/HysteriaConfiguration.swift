//
//  HysteriaConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

/// Configuration for a Hysteria v2 session.
struct HysteriaConfiguration {
    let proxyHost: String
    let proxyPort: UInt16
    /// Authentication password (sent in the `Hysteria-Auth` header).
    let password: String
    /// TLS SNI override. Defaults to `proxyHost` when `nil`.
    let sni: String?
    /// Client's receive bandwidth estimate in bytes/sec. Advertised to the
    /// server in the `Hysteria-CC-RX` request header so the server can cap
    /// its send rate. 0 means "please probe" / "I don't know".
    let clientRxBytesPerSec: UInt64

    /// Client-declared upload bandwidth in Mbit/s (1…100). Drives both the
    /// initial Brutal target rate (before the server's CC-RX is known) and
    /// the post-auth `min(server_rx, client_max_tx)` cap.
    let uploadMbps: Int

    /// Upload bandwidth expressed in bytes/sec — the unit Brutal uses
    /// internally.
    var uploadBytesPerSec: UInt64 {
        UInt64(uploadMbps) * 1_000_000 / 8
    }

    var effectiveSNI: String { sni ?? proxyHost }
}
