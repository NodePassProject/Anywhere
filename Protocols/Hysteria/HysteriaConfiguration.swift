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
    /// Client's receive bandwidth in bytes/sec. 0 = "please probe".
    /// Currently unused by our CC (we're on CUBIC), but sent to the
    /// server for compatibility.
    let clientRxBytesPerSec: UInt64

    var effectiveSNI: String { sni ?? proxyHost }
}
