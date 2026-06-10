//
//  HysteriaConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation

struct HysteriaConfiguration {
    let proxyHost: String
    let proxyPort: UInt16
    /// Authentication password (sent in the `Hysteria-Auth` header).
    let password: String
    
    let congestionControl: HysteriaCongestionControl

    /// Client-declared upload bandwidth in Mbit/s; drives Brutal's tx rate. Ignored under `.bbr`.
    let uploadMbps: Int

    /// Client-declared download bandwidth in Mbit/s; advertised so the server
    /// paces our downlink under Brutal. Ignored under `.bbr`.
    let downloadMbps: Int

    /// Bytes/sec conversion; Brutal uses this unit internally.
    var uploadBytesPerSec: UInt64 {
        UInt64(max(0, uploadMbps)) * 1_000_000 / 8
    }

    var downloadBytesPerSec: UInt64 {
        UInt64(max(0, downloadMbps)) * 1_000_000 / 8
    }
    
    /// `Hysteria-CC-RX` header value (bytes/sec); 0 tells the server to run
    /// its own bandwidth detection (BBR mode).
    var clientRxBytesPerSec: UInt64 {
        congestionControl == .brutal ? downloadBytesPerSec : 0
    }
    
    /// Port-hopping settings, or `nil` for a fixed single port. Honored only on the direct
    /// kernel-socket path; ignored when Hysteria is a chain link riding a relay transport.
    let portHopping: HysteriaPortHopping?
    
    /// TLS SNI; callers default to `proxyHost` when there is no explicit override.
    let sni: String
}
