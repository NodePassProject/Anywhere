//
//  NowhereConfiguration.swift
//  Anywhere
//
// Created by NodePassProject on 5/29/26.
//

import Foundation

/// Configuration for a Nowhere QUIC session.
struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let uploadMbps: Int

    var uploadBytesPerSec: UInt64 {
        UInt64(max(0, uploadMbps)) * 1_000_000 / 8
    }
}
